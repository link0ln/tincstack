/*
 * tincstack for Android
 * Copyright (C) 2026 tincstack contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.pacien.tincapp.activities.config

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.databinding.ActivityConfigEditorBinding
import org.pacien.tincapp.databinding.ConfigKeyItemBinding
import org.pacien.tincapp.databinding.DialogAddKeyBinding
import org.pacien.tincapp.extensions.Java.defaultMessage
import org.pacien.tincapp.service.TincVpnService
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Interactive configuration editor for a network's `tinc.yaml`:
 *
 *  - **Per-section / Per-node Scope Tabs**:
 *    - `⚙ Options`: global network options (`Mode`, `Port`, `ConnectTo`, `Transports`, etc.)
 *    - `📱 <own> (this device)`: this phone's host record (`Subnet`, `Port`, public keys, etc.)
 *    - `🖥 <peer>`: individual editor for each peer node (`Address`, `Port`, `HttpsPort`,
 *      `QuicPort`, `ObfsPort`, `PreferredTransport`, `Subnet`, etc.)
 *    - `📋 All sections`: unified view with headers
 *    - `📄 Raw YAML`: direct `tinc.yaml` text editor with syntax validation
 *    - `+ Add node`: create a new peer node section (`hosts.<node>`)
 *  - **Quick-Add Strip & Smart Parameter Dialog**:
 *    - Shows one-tap chips for common missing parameters in the current scope
 *    - Provides parameter presets, descriptions, and quick-value chips (`quic`, `https`, `obfs`, `yes`/`no`, peer names)
 */
class ConfigEditorActivity : BaseActivity() {
  private lateinit var binding: ActivityConfigEditorBinding
  override val snackbarRoot: View get() = binding.configRoot
  private val netName by lazy { intent.getStringExtra(EXTRA_NET_NAME)!! }
  private val focusNode by lazy { intent.getStringExtra(EXTRA_FOCUS_NODE) }
  private val yaml by lazy { TincYaml(AppPaths.tincYamlFile(netName)) }
  private lateinit var stanza: String
  private var ownNode: String? = null

  private val adapter = Adapter()
  private val allRows = mutableListOf<Row>()
  private val visibleRows = mutableListOf<Row>()
  private val removedRows = mutableListOf<Row>()
  private val knownNodes = mutableListOf<String>()
  private val initialNodes = mutableSetOf<String>()
  private val deletedNodes = mutableSetOf<String>()

  private var rawOriginalText: String = ""
  private var rawPendingText: String? = null
  private var suppressRawWatcher = false

  private var currentScope: Scope = Scope.Options
  private val dirty = AtomicBoolean(false)

  sealed class Scope {
    object Options : Scope()
    data class Node(val name: String) : Scope()
    object All : Scope()
    object RawYaml : Scope()
  }

  data class KeySpec(
    val name: String,
    val description: String,
    val defaultSuggestion: String = "",
    val valuePresets: (peers: List<String>) -> List<String> = { emptyList() },
  )

  data class Row(
    val kind: Kind,
    val sectionTitle: Int,
    val sectionSort: Int,
    val net: String,
    val node: String?,
    val k: String,
    val original: String,
    val header: Boolean = false,
    val headerText: String = "",
    val newlyAdded: Boolean = false,
  ) {
    var pending: String? = null
    fun key() = k
    fun value() = pending ?: original
    fun set(v: String) {
      pending = v
    }

    fun changed(): Boolean = !header && (
      (pending != null && pending != original) ||
        (newlyAdded && value().isNotBlank())
      )

    enum class Kind { OPTION, HOST, HEADER }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = ActivityConfigEditorBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = true)
    supportActionBar?.subtitle = netName

    binding.configList.layoutManager = LinearLayoutManager(this)
    binding.configList.adapter = adapter

    binding.configAdd.setOnClickListener {
      val targetNode = (currentScope as? Scope.Node)?.name
      addKeyDialog(preselectedNode = targetNode)
    }
    binding.configSave.setOnClickListener { save() }

    binding.configRawEdit.addTextChangedListener(SimpleWatcher { s ->
      if (suppressRawWatcher) return@SimpleWatcher
      val text = s?.toString().orEmpty()
      rawPendingText = text
      binding.configRawLayout.error = null
      if (text != rawOriginalText) markDirty()
    })

    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        if (dirty.get()) confirmDiscardAndFinish() else finish()
      }
    })

    stanza = yaml.resolveNetwork(netName)
    loadFromDisk()

    val targetFocus = focusNode?.takeIf { it.isNotBlank() }
    currentScope = if (targetFocus != null) {
      if (targetFocus !in knownNodes) {
        knownNodes.add(targetFocus)
      }
      Scope.Node(targetFocus)
    } else {
      Scope.Options
    }

    renderScopeChips()
    applyScope()
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    if (item.itemId == android.R.id.home && dirty.get()) {
      confirmDiscardAndFinish()
      return true
    }
    if (item.itemId == MENU_DELETE_NODE) {
      val targetNode = (currentScope as? Scope.Node)?.name ?: return true
      confirmDeleteNode(targetNode)
      return true
    }
    return super.onOptionsItemSelected(item)
  }

  /** "Delete node" lives in the toolbar, scoped to a non-own node tab: a third
      button in the bottom bar squeezed Save on narrow screens. */
  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menu.add(Menu.NONE, MENU_DELETE_NODE, Menu.NONE, R.string.config_delete_node_action)
    return true
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    val scope = currentScope
    menu.findItem(MENU_DELETE_NODE)?.isVisible =
      scope is Scope.Node && scope.name != ownNode
    return true
  }

  private fun confirmDiscardAndFinish() {
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.config_unsaved_title)
      .setMessage(R.string.config_unsaved_msg)
      .setNegativeButton(R.string.action_cancel, null)
      .setPositiveButton(R.string.config_action_discard) { _, _ -> finish() }
      .show()
  }

  private fun loadFromDisk() {
    allRows.clear()
    visibleRows.clear()
    removedRows.clear()
    knownNodes.clear()
    initialNodes.clear()
    deletedNodes.clear()

    rawOriginalText = yaml.readRawText()
    rawPendingText = null
    suppressRawWatcher = true
    binding.configRawEdit.setText(rawOriginalText)
    suppressRawWatcher = false

    ownNode = yaml.optionValue(stanza, "Name")
    for ((k, v) in yaml.options(stanza)) {
      allRows.add(
        Row(
          kind = Row.Kind.OPTION,
          sectionTitle = R.string.config_section_options,
          sectionSort = 0,
          net = stanza,
          node = null,
          k = k,
          original = TincYaml.valuesOf(v).joinToString(", "),
        )
      )
    }

    val nodes = yaml.hostNames(stanza)
    knownNodes.addAll(nodes)
    initialNodes.addAll(nodes)

    for (node in nodes) {
      val text = yaml.hostText(stanza, node) ?: continue
      for ((k, vals) in TincYaml.parseHostMultiKeyValues(text)) {
        allRows.add(
          Row(
            kind = Row.Kind.HOST,
            sectionTitle = R.string.config_section_hosts,
            sectionSort = 1,
            net = stanza,
            node = node,
            k = k,
            original = vals.joinToString(", "),
          )
        )
      }
    }
  }

  private fun peerNodeNames(): List<String> =
    knownNodes.filter { it != ownNode }

  private fun renderScopeChips() {
    val group = binding.configScopeChips
    group.removeAllViews()

    fun addScopeChip(label: String, scope: Scope, selected: Boolean) {
      val chip = Chip(this).apply {
        text = label
        isCheckable = true
        isChecked = selected
        setOnClickListener {
          if (currentScope != scope) {
            currentScope = scope
            applyScope()
            renderScopeChips()
          }
        }
      }
      group.addView(chip)
      if (selected) {
        chip.post {
          binding.configScopeScroll.smoothScrollTo((chip.left - 48).coerceAtLeast(0), 0)
        }
      }
    }

    addScopeChip(
      getString(R.string.config_scope_options),
      Scope.Options,
      currentScope == Scope.Options,
    )

    for (node in knownNodes) {
      val isOwn = node == ownNode
      val label = if (isOwn) {
        getString(R.string.config_scope_own_format, node)
      } else {
        getString(R.string.config_scope_node_format, node)
      }
      val scope = Scope.Node(node)
      addScopeChip(label, scope, currentScope == scope)
    }

    addScopeChip(
      getString(R.string.config_scope_all),
      Scope.All,
      currentScope == Scope.All,
    )

    addScopeChip(
      getString(R.string.config_scope_raw),
      Scope.RawYaml,
      currentScope == Scope.RawYaml,
    )

    // Action chip: + Add node
    val addNodeChip = Chip(this).apply {
      text = getString(R.string.config_scope_add_node)
      isCheckable = false
      setOnClickListener { showAddNodeDialog() }
    }
    group.addView(addNodeChip)
  }

  private fun applyScope() {
    invalidateOptionsMenu()
    when (val s = currentScope) {
      Scope.Options -> {
        supportActionBar?.title = getString(R.string.config_section_options)
        binding.configList.isVisible = true
        binding.configRawContainer.isVisible = false
        binding.configAdd.isVisible = true
      }
      is Scope.Node -> {
        val isOwn = s.name == ownNode
        supportActionBar?.title = getString(
          if (isOwn) R.string.config_section_own_node else R.string.config_section_node,
          s.name
        )
        binding.configList.isVisible = true
        binding.configRawContainer.isVisible = false
        binding.configAdd.isVisible = true
      }
      Scope.All -> {
        supportActionBar?.title = getString(R.string.config_editor_title)
        binding.configList.isVisible = true
        binding.configRawContainer.isVisible = false
        binding.configAdd.isVisible = true
      }
      Scope.RawYaml -> {
        supportActionBar?.title = getString(R.string.config_scope_raw)
        binding.configList.isVisible = false
        binding.configRawContainer.isVisible = true
        binding.configAdd.isVisible = false
        binding.configQuickBar.isVisible = false
        return
      }
    }

    rebuildVisibleRows()
    renderQuickAddBar()
  }

  private fun rebuildVisibleRows() {
    visibleRows.clear()
    when (val s = currentScope) {
      Scope.Options -> {
        visibleRows.addAll(allRows.filter { it.kind == Row.Kind.OPTION })
      }
      is Scope.Node -> {
        visibleRows.addAll(allRows.filter { it.kind == Row.Kind.HOST && it.node == s.name })
      }
      Scope.All -> {
        visibleRows.add(
          Row(
            kind = Row.Kind.HEADER,
            sectionTitle = R.string.config_section_options,
            sectionSort = 0,
            net = stanza,
            node = null,
            k = "",
            original = "",
            header = true,
            headerText = getString(R.string.config_section_options),
          )
        )
        visibleRows.addAll(allRows.filter { it.kind == Row.Kind.OPTION })
        for (node in knownNodes) {
          val isOwn = node == ownNode
          visibleRows.add(
            Row(
              kind = Row.Kind.HEADER,
              sectionTitle = R.string.config_section_hosts,
              sectionSort = 1,
              net = stanza,
              node = node,
              k = "",
              original = "",
              header = true,
              headerText = getString(
                if (isOwn) R.string.config_section_own_node else R.string.config_section_node,
                node
              ),
            )
          )
          visibleRows.addAll(allRows.filter { it.kind == Row.Kind.HOST && it.node == node })
        }
      }
      Scope.RawYaml -> {}
    }
    adapter.notifyDataSetChanged()
  }

  private fun renderQuickAddBar() {
    val quickGroup = binding.configQuickChips
    quickGroup.removeAllViews()

    val (targetNode, specs, existingKeys) = when (val s = currentScope) {
      Scope.Options -> Triple(
        null,
        OPTION_SPECS,
        allRows.filter { it.kind == Row.Kind.OPTION }.map { it.key().lowercase() }.toSet()
      )
      is Scope.Node -> Triple(
        s.name,
        HOST_SPECS,
        allRows.filter { it.kind == Row.Kind.HOST && it.node == s.name }.map { it.key().lowercase() }.toSet()
      )
      else -> {
        binding.configQuickBar.isVisible = false
        return
      }
    }

    val missing = specs.filter { it.name.lowercase() !in existingKeys }
    if (missing.isEmpty()) {
      binding.configQuickBar.isVisible = false
      return
    }

    binding.configQuickBar.isVisible = true
    for (spec in missing) {
      val chip = Chip(this).apply {
        text = "+ ${spec.name}"
        isCheckable = false
        setOnClickListener {
          addKeyDialog(
            preselectedNode = targetNode,
            prefillKey = spec.name,
            prefillValue = spec.defaultSuggestion,
          )
        }
      }
      quickGroup.addView(chip)
    }
  }

  private fun showAddNodeDialog() {
    val pad = (20 * resources.displayMetrics.density).toInt()
    val container = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(pad, pad / 2, pad, 0)
    }

    val nameLayout = TextInputLayout(this).apply {
      hint = getString(R.string.config_add_node_name_hint)
    }
    val nameInput = TextInputEditText(nameLayout.context).apply {
      inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
      isSingleLine = true
    }
    nameLayout.addView(nameInput)

    val addrLayout = TextInputLayout(this).apply {
      hint = getString(R.string.config_add_node_address_hint)
      val lp = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
      )
      lp.topMargin = pad / 2
      layoutParams = lp
    }
    val addrInput = TextInputEditText(addrLayout.context).apply {
      inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
      isSingleLine = true
    }
    addrLayout.addView(addrInput)

    container.addView(nameLayout)
    container.addView(addrLayout)

    val dialog = MaterialAlertDialogBuilder(this)
      .setTitle(R.string.config_add_node_title)
      .setView(container)
      .setPositiveButton(R.string.action_add, null)
      .setNegativeButton(R.string.action_cancel, null)
      .create()

    dialog.setOnShowListener {
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
        val rawName = nameInput.text?.toString()?.trim().orEmpty()
        if (!rawName.matches(NODE_NAME_RE)) {
          nameLayout.error = getString(R.string.config_add_node_bad_name)
          return@setOnClickListener
        }
        if (knownNodes.any { it.equals(rawName, ignoreCase = true) }) {
          nameLayout.error = getString(R.string.config_add_node_exists)
          return@setOnClickListener
        }
        deletedNodes.remove(rawName)
        knownNodes.add(rawName)
        val addr = addrInput.text?.toString()?.trim().orEmpty()
        if (addr.isNotEmpty()) {
          allRows.add(
            Row(
              kind = Row.Kind.HOST,
              sectionTitle = R.string.config_section_hosts,
              sectionSort = 1,
              net = stanza,
              node = rawName,
              k = "Address",
              original = "",
              newlyAdded = true,
            ).apply { set(addr) }
          )
        }
        allRows.add(
          Row(
            kind = Row.Kind.HOST,
            sectionTitle = R.string.config_section_hosts,
            sectionSort = 1,
            net = stanza,
            node = rawName,
            k = "Port",
            original = "",
            newlyAdded = true,
          ).apply { set("655") }
        )
        markDirty()
        currentScope = Scope.Node(rawName)
        renderScopeChips()
        applyScope()
        dialog.dismiss()
      }
    }
    dialog.show()
  }

  private fun confirmDeleteNode(nodeName: String) {
    if (nodeName == ownNode) return
    MaterialAlertDialogBuilder(this)
      .setTitle(getString(R.string.config_delete_node_title, nodeName))
      .setMessage(getString(R.string.config_delete_node_msg, nodeName))
      .setNegativeButton(R.string.action_cancel, null)
      .setPositiveButton(R.string.action_remove) { _, _ ->
        knownNodes.remove(nodeName)
        allRows.removeAll { it.kind == Row.Kind.HOST && it.node == nodeName }
        removedRows.removeAll { it.kind == Row.Kind.HOST && it.node == nodeName }
        if (nodeName in initialNodes) {
          deletedNodes.add(nodeName)
        }
        markDirty()
        currentScope = Scope.Options
        renderScopeChips()
        applyScope()
      }
      .show()
  }

  /**
   * Open the Add Parameter dialog:
   *  - Lists `Network Options` AND every node in `knownNodes`
   *  - Pre-selects the active node or `preselectedNode`
   *  - Provides clickable parameter preset chips and value preset chips
   *  - Validates without closing the dialog on error
   */
  private fun addKeyDialog(
    preselectedNode: String? = null,
    prefillKey: String? = null,
    prefillValue: String? = null,
  ) {
    // Targets: null = Network Options, non-null = Node name
    val targets: List<String?> = listOf(null) + knownNodes
    val targetLabels: Array<String> = targets.map { node ->
      if (node == null) {
        getString(R.string.config_section_options)
      } else if (node == ownNode) {
        getString(R.string.config_section_own_node, node)
      } else {
        getString(R.string.config_section_node, node)
      }
    }.toTypedArray()

    var selectedTargetIdx = if (preselectedNode != null) {
      targets.indexOf(preselectedNode).takeIf { it >= 0 } ?: 0
    } else {
      0
    }

    val dialogView = layoutInflater.inflate(R.layout.dialog_add_key, null)
    val addBinding = DialogAddKeyBinding.bind(dialogView)

    fun currentTargetNode(): String? = targets.getOrNull(selectedTargetIdx)

    fun updateValueSuggestionsForKey(keyName: String) {
      val targetNode = currentTargetNode()
      val spec = findKeySpec(isOption = targetNode == null, key = keyName)
      if (spec != null && spec.description.isNotEmpty()) {
        addBinding.addKeyDesc.text = spec.description
        addBinding.addKeyDesc.isVisible = true
      } else {
        addBinding.addKeyDesc.isVisible = false
      }

      val presets = spec?.valuePresets?.invoke(peerNodeNames()).orEmpty()
      addBinding.addKeyValueChips.removeAllViews()
      if (presets.isEmpty()) {
        addBinding.addKeyValueChipsScroll.isVisible = false
      } else {
        addBinding.addKeyValueChipsScroll.isVisible = true
        for (presetVal in presets) {
          val chip = Chip(this).apply {
            text = presetVal
            isCheckable = false
            setOnClickListener {
              addBinding.addKeyValue.setText(presetVal)
              addBinding.addKeyValue.setSelection(presetVal.length)
              addBinding.addKeyValueLayout.error = null
            }
          }
          addBinding.addKeyValueChips.addView(chip)
        }
      }
    }

    fun refreshPresetKeyChips() {
      val targetNode = currentTargetNode()
      val specs = if (targetNode == null) OPTION_SPECS else HOST_SPECS
      val existingKeys = allRows
        .filter { if (targetNode == null) it.kind == Row.Kind.OPTION else (it.kind == Row.Kind.HOST && it.node == targetNode) }
        .map { it.key().lowercase() }
        .toSet()

      addBinding.addKeyPresets.removeAllViews()
      // Show missing keys first, then existing ones
      val orderedSpecs = specs.filter { it.name.lowercase() !in existingKeys } +
        specs.filter { it.name.lowercase() in existingKeys }

      for (spec in orderedSpecs) {
        val chip = Chip(this).apply {
          text = spec.name
          isCheckable = false
          setOnClickListener {
            addBinding.addKeyName.setText(spec.name)
            addBinding.addKeyName.setSelection(spec.name.length)
            addBinding.addKeyNameLayout.error = null
            val existingRow = allRows.firstOrNull {
              it.key().equals(spec.name, ignoreCase = true) &&
                if (targetNode == null) it.kind == Row.Kind.OPTION else (it.kind == Row.Kind.HOST && it.node == targetNode)
            }
            val suggested = existingRow?.value()?.takeIf { it.isNotEmpty() } ?: spec.defaultSuggestion
            if (addBinding.addKeyValue.text.isNullOrBlank() && suggested.isNotEmpty()) {
              addBinding.addKeyValue.setText(suggested)
              addBinding.addKeyValue.setSelection(suggested.length)
            }
            updateValueSuggestionsForKey(spec.name)
          }
        }
        addBinding.addKeyPresets.addView(chip)
      }
    }

    // Opened from a node tab or a quick-add chip: the target is already
    // decided, so the section picker (another dialog on tap) is not shown.
    addBinding.addKeySectionLayout.isVisible = preselectedNode == null
    addBinding.addKeySection.setText(targetLabels[selectedTargetIdx])
    addBinding.addKeySection.setOnClickListener {
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.config_pick_section)
        .setItems(targetLabels) { _, which ->
          selectedTargetIdx = which
          addBinding.addKeySection.setText(targetLabels[which])
          refreshPresetKeyChips()
          updateValueSuggestionsForKey(addBinding.addKeyName.text?.toString()?.trim().orEmpty())
        }
        .show()
    }

    addBinding.addKeyName.addTextChangedListener(SimpleWatcher { s ->
      addBinding.addKeyNameLayout.error = null
      updateValueSuggestionsForKey(s?.toString()?.trim().orEmpty())
    })
    addBinding.addKeyValue.addTextChangedListener(SimpleWatcher {
      addBinding.addKeyValueLayout.error = null
    })

    refreshPresetKeyChips()

    if (!prefillKey.isNullOrBlank()) {
      addBinding.addKeyName.setText(prefillKey)
      addBinding.addKeyName.setSelection(prefillKey.length)
      updateValueSuggestionsForKey(prefillKey)
    }
    if (!prefillValue.isNullOrBlank()) {
      addBinding.addKeyValue.setText(prefillValue)
      addBinding.addKeyValue.setSelection(prefillValue.length)
    }

    val dialog = MaterialAlertDialogBuilder(this)
      .setTitle(R.string.config_add_key)
      .setView(dialogView)
      .setPositiveButton(R.string.action_add, null)
      .setNegativeButton(R.string.action_cancel, null)
      .create()

    dialog.setOnShowListener {
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
        val k = addBinding.addKeyName.text?.toString()?.trim().orEmpty()
        val v = addBinding.addKeyValue.text?.toString()?.trim().orEmpty()
        if (!k.matches(KEY_NAME_RE)) {
          addBinding.addKeyNameLayout.error = getString(R.string.config_bad_key)
          return@setOnClickListener
        }
        val targetNode = currentTargetNode()
        val isOption = targetNode == null
        val existing = allRows.firstOrNull {
          !it.header && it.key().equals(k, ignoreCase = true) &&
            if (isOption) it.kind == Row.Kind.OPTION else (it.kind == Row.Kind.HOST && it.node == targetNode)
        }
        if (existing != null) {
          if (v.isEmpty()) {
            addBinding.addKeyNameLayout.error = getString(R.string.config_key_exists)
            return@setOnClickListener
          }
          existing.set(v)
          markDirty()
          if (currentScope != Scope.All) {
            currentScope = if (isOption) Scope.Options else Scope.Node(targetNode!!)
            renderScopeChips()
          }
          applyScope()
          val visIdx = visibleRows.indexOf(existing)
          if (visIdx >= 0) binding.configList.scrollToPosition(visIdx)
          dialog.dismiss()
          return@setOnClickListener
        }

        val newRow = if (isOption) {
          Row(
            kind = Row.Kind.OPTION,
            sectionTitle = R.string.config_section_options,
            sectionSort = 0,
            net = stanza,
            node = null,
            k = k,
            original = "",
            newlyAdded = true,
          ).apply { set(v) }
        } else {
          Row(
            kind = Row.Kind.HOST,
            sectionTitle = R.string.config_section_hosts,
            sectionSort = 1,
            net = stanza,
            node = targetNode,
            k = k,
            original = "",
            newlyAdded = true,
          ).apply { set(v) }
        }

        allRows.add(newRow)
        markDirty()
        if (currentScope != Scope.All) {
          currentScope = if (isOption) Scope.Options else Scope.Node(targetNode!!)
          renderScopeChips()
        }
        applyScope()
        val visIdx = visibleRows.indexOf(newRow)
        if (visIdx >= 0) binding.configList.scrollToPosition(visIdx)
        dialog.dismiss()
      }
    }
    dialog.show()
  }

  private fun markDirty() {
    dirty.set(true)
    binding.configSave.isEnabled = true
  }

  private fun save() {
    try {
      // Raw edits apply no matter which scope is on screen now: switching
      // tabs after typing YAML used to silently drop every raw change.
      val rawChanged = rawPendingText != null && rawPendingText != rawOriginalText
      if (rawChanged) {
        yaml.writeRawText(rawPendingText!!)
      }

      val structuredChange = deletedNodes.isNotEmpty() ||
        removedRows.isNotEmpty() ||
        allRows.any { it.changed() }

      if (!rawChanged || structuredChange) {
        for (delNode in deletedNodes) {
          yaml.removeHost(stanza, delNode)
        }

        val optChanges = LinkedHashMap<String, List<String>?>()
        if (deletedNodes.isNotEmpty()) {
          val blocked = yaml.optionValues(stanza, "BlockedNodes").flatMap { it.split(',', ' ') }.map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()
          for (delNode in deletedNodes) {
            if (delNode !in blocked) blocked.add(delNode)
          }
          optChanges["BlockedNodes"] = blocked
        }
        for (r in removedRows.filter { it.kind == Row.Kind.OPTION }) {
          optChanges[r.key()] = null
        }
        for (r in allRows.filter { it.kind == Row.Kind.OPTION }) {
          if (!r.changed()) continue
          val vals = r.value().split(',').map { it.trim() }.filter { it.isNotEmpty() }
          optChanges[r.key()] = vals.ifEmpty { null }
        }
        if (optChanges.isNotEmpty()) {
          yaml.setOptions(stanza, optChanges)
        }

        for (node in knownNodes) {
          val hostChanges = LinkedHashMap<String, List<String>?>()
          for (r in removedRows.filter { it.kind == Row.Kind.HOST && it.node == node }) {
            hostChanges[r.key()] = null
          }
          for (r in allRows.filter { it.kind == Row.Kind.HOST && it.node == node }) {
            if (!r.changed()) continue
            val vals = r.value().split(',').map { it.trim() }.filter { it.isNotEmpty() }
            hostChanges[r.key()] = vals.ifEmpty { null }
          }
          val isNewNode = node !in initialNodes
          if (hostChanges.isNotEmpty() || isNewNode) {
            yaml.setHostMultiVars(stanza, node, hostChanges, createIfMissing = true)
          }
        }
      }
    } catch (e: Exception) {
      val msg = e.cause?.defaultMessage() ?: e.defaultMessage()
      if (rawPendingText != null && rawPendingText != rawOriginalText) {
        binding.configRawLayout.error = msg
      }
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.config_save_failed)
        .setMessage(msg)
        .setPositiveButton(R.string.action_close, null)
        .show()
      return
    }

    dirty.set(false)
    reconnectIfActive()
    notifyDone()
    setResult(RESULT_OK)
    finish()
  }

  private fun notifyDone() {
    Snackbar.make(binding.configRoot, R.string.config_saved, Snackbar.LENGTH_SHORT).show()
  }

  private fun reconnectIfActive() {
    if (TincVpnService.isDaemonRunning()) {
      TincVpnService.connect(netName)
    }
  }

  private inner class Adapter : RecyclerView.Adapter<Holder>() {
    override fun getItemCount() = visibleRows.size

    override fun getItemViewType(position: Int) =
      if (visibleRows[position].header) VIEW_TYPE_HEADER else VIEW_TYPE_KEY

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
      Holder(ConfigKeyItemBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
      val r = visibleRows[position]
      val b = holder.binding
      holder.watcher?.let { b.keyValue.removeTextChangedListener(it) }
      holder.watcher = null

      if (r.header) {
        b.keySection.isVisible = true
        b.keySection.text = r.headerText
        b.keyRowContainer.isVisible = false
        return
      }

      b.keySection.isVisible = false
      b.keyRowContainer.isVisible = true
      b.keyName.text = r.key()

      val spec = findKeySpec(isOption = r.kind == Row.Kind.OPTION, key = r.key())
      if (spec != null && spec.description.isNotEmpty()) {
        b.keyDesc.text = spec.description
        b.keyDesc.isVisible = true
      } else {
        b.keyDesc.isVisible = false
      }

      b.keyValue.setText(r.value())

      val presets = spec?.valuePresets?.invoke(peerNodeNames()).orEmpty()
      b.keyValueChips.removeAllViews()
      if (presets.isEmpty()) {
        b.keyValueChipsScroll.isVisible = false
      } else {
        b.keyValueChipsScroll.isVisible = true
        populateRowValueChips(b.keyValueChips, b.keyValue, r, presets)
      }

      val w = SimpleWatcher { s ->
        r.set(s?.toString()?.trim().orEmpty())
        markDirty()
      }
      holder.watcher = w
      b.keyValue.addTextChangedListener(w)

      b.keyRemove.setOnClickListener {
        MaterialAlertDialogBuilder(this@ConfigEditorActivity)
          .setTitle(getString(R.string.config_remove_key_title, r.key()))
          .setMessage(R.string.config_remove_key_msg)
          .setPositiveButton(R.string.action_remove) { _, _ ->
            allRows.remove(r)
            r.set("")
            if (r.original.isNotEmpty()) removedRows.add(r)
            markDirty()
            rebuildVisibleRows()
            renderQuickAddBar()
          }
          .setNegativeButton(R.string.action_cancel, null)
          .show()
      }
    }

    private fun populateRowValueChips(
      chipGroup: ChipGroup,
      editText: TextInputEditText,
      row: Row,
      presets: List<String>,
    ) {
      val multiValueKey = row.key().equals("ConnectTo", ignoreCase = true) ||
        row.key().equals("Transports", ignoreCase = true) ||
        row.key().equals("PreferredTransports", ignoreCase = true)

      for (preset in presets) {
        val chip = Chip(this@ConfigEditorActivity).apply {
          text = preset
          isCheckable = false
          setOnClickListener {
            val nextVal = if (multiValueKey && !preset.contains(',')) {
              val currentItems = editText.text?.toString()
                ?.split(',')
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                .orEmpty()
              val updated = if (currentItems.any { it.equals(preset, ignoreCase = true) }) {
                currentItems.filterNot { it.equals(preset, ignoreCase = true) }
              } else {
                currentItems + preset
              }
              updated.joinToString(", ")
            } else {
              preset
            }
            editText.setText(nextVal)
            editText.setSelection(nextVal.length)
            row.set(nextVal)
            markDirty()
          }
        }
        chipGroup.addView(chip)
      }
    }
  }

  private class Holder(
    val binding: ConfigKeyItemBinding,
    var watcher: TextWatcher? = null,
  ) : RecyclerView.ViewHolder(binding.root)

  private class SimpleWatcher(private val onChange: (Editable?) -> Unit) : TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun afterTextChanged(s: Editable?) = onChange(s)
  }

  companion object {
    private const val EXTRA_NET_NAME = "netName"
    private const val EXTRA_FOCUS_NODE = "focusNode"
    private const val VIEW_TYPE_HEADER = 0
    private const val VIEW_TYPE_KEY = 1
    private const val MENU_DELETE_NODE = 100

    private val KEY_NAME_RE = Regex("^[A-Za-z][A-Za-z0-9_]*$")
    private val NODE_NAME_RE = Regex("^[A-Za-z0-9][A-Za-z0-9_]*$")

    private val BOOL_PRESETS: (List<String>) -> List<String> = { listOf("yes", "no") }

    val HOST_SPECS: List<KeySpec> = listOf(
      KeySpec(
        name = "Address",
        description = "Public IP or hostname of this node (optional port after space)",
        defaultSuggestion = "",
      ),
      KeySpec(
        name = "Port",
        description = "Standard tinc TCP/UDP meta port (1–65535)",
        defaultSuggestion = "655",
        valuePresets = { listOf("655", "443", "8443") },
      ),
      KeySpec(
        name = "HttpsPort",
        description = "HTTPS stealth transport TCP port (0 = disabled)",
        defaultSuggestion = "8443",
        valuePresets = { listOf("443", "8443", "0") },
      ),
      KeySpec(
        name = "QuicPort",
        description = "QUIC (HTTP/3) stealth transport UDP port (0 = disabled)",
        defaultSuggestion = "8443",
        valuePresets = { listOf("443", "8443", "0") },
      ),
      KeySpec(
        name = "ObfsPort",
        description = "Obfuscated UDP transport port (0 = disabled)",
        defaultSuggestion = "19505",
        valuePresets = { listOf("19505", "8444", "0") },
      ),
      KeySpec(
        name = "PreferredTransport",
        description = "Preferred transport when dialing this node",
        defaultSuggestion = "quic",
        valuePresets = { listOf("auto", "quic", "https", "obfs", "sf", "sftcp", "plain") },
      ),
      KeySpec(
        name = "Subnet",
        description = "VPN IP/CIDR owned by this node (comma-separated if multiple)",
        defaultSuggestion = "",
      ),
      KeySpec(
        name = "Ed25519PublicKey",
        description = "Node's Ed25519 public key (base64)",
        defaultSuggestion = "",
      ),
      KeySpec(
        name = "IndirectData",
        description = "Relay data packets through hub instead of direct UDP",
        defaultSuggestion = "yes",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "DirectOnly",
        description = "Only send data directly, never via intermediate relay",
        defaultSuggestion = "no",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "ClampMSS",
        description = "Clamp TCP MSS to tunnel MTU",
        defaultSuggestion = "yes",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "Weight",
        description = "Routing metric weight for this node",
        defaultSuggestion = "10",
      ),
    )

    val OPTION_SPECS: List<KeySpec> = listOf(
      KeySpec(
        name = "ConnectTo",
        description = "Peer nodes to dial on startup (tap a peer chip to toggle)",
        defaultSuggestion = "",
        valuePresets = { peers -> peers },
      ),
      KeySpec(
        name = "PreferredTransports",
        description = "Global transport dial priority (comma-separated)",
        defaultSuggestion = "quic, https, obfs, sf, sftcp, plain",
        valuePresets = { listOf("quic", "https", "obfs", "sf", "sftcp", "plain") },
      ),
      KeySpec(
        name = "SingleFlow",
        description = "Single-flow mode: udp (sf), tcp (sftcp), both, or no",
        defaultSuggestion = "no",
        valuePresets = { listOf("no", "udp", "tcp", "both") },
      ),
      KeySpec(
        name = "Transports",
        description = "Enabled transports on this device (comma-separated)",
        defaultSuggestion = "plain, sf, obfs, https, quic",
        valuePresets = { listOf("plain", "sf", "obfs", "https", "quic") },
      ),
      KeySpec(
        name = "Port",
        description = "Local tinc listen port",
        defaultSuggestion = "655",
        valuePresets = { listOf("655", "0") },
      ),
      KeySpec(
        name = "HttpsPort",
        description = "Local HTTPS listener port (0 = disabled)",
        defaultSuggestion = "0",
        valuePresets = { listOf("0", "443", "8443") },
      ),
      KeySpec(
        name = "QuicPort",
        description = "Local QUIC listener port (0 = disabled)",
        defaultSuggestion = "0",
        valuePresets = { listOf("0", "443", "8443") },
      ),
      KeySpec(
        name = "ObfsPort",
        description = "Local Obfuscated UDP listener port (0 = disabled)",
        defaultSuggestion = "0",
        valuePresets = { listOf("0", "19505") },
      ),
      KeySpec(
        name = "Mode",
        description = "Routing mode of the VPN mesh",
        defaultSuggestion = "router",
        valuePresets = { listOf("router", "switch", "hub") },
      ),
      KeySpec(
        name = "AutoConnect",
        description = "Automatically maintain mesh connections",
        defaultSuggestion = "yes",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "PingInterval",
        description = "Heartbeat ping interval in seconds",
        defaultSuggestion = "10",
        valuePresets = { listOf("5", "10", "15", "30") },
      ),
      KeySpec(
        name = "PingTimeout",
        description = "Heartbeat timeout in seconds before dead peer detection",
        defaultSuggestion = "5",
        valuePresets = { listOf("3", "5", "10") },
      ),
      KeySpec(
        name = "MaxTimeout",
        description = "Maximum reconnect backoff delay in seconds",
        defaultSuggestion = "30",
        valuePresets = { listOf("15", "30", "60") },
      ),
      KeySpec(
        name = "UdpDiscovery",
        description = "Probe direct UDP paths between peers",
        defaultSuggestion = "yes",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "UdpDiscoveryInterval",
        description = "Direct UDP probe interval in seconds",
        defaultSuggestion = "2",
        valuePresets = { listOf("1", "2", "5") },
      ),
      KeySpec(
        name = "UdpDiscoveryTimeout",
        description = "Direct UDP probe timeout in seconds",
        defaultSuggestion = "6",
        valuePresets = { listOf("4", "6", "10") },
      ),
      KeySpec(
        name = "DirectOnly",
        description = "Disable relay forwarding, require direct peer links",
        defaultSuggestion = "no",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "IndirectData",
        description = "Force all data through relay hubs (disable direct UDP)",
        defaultSuggestion = "no",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "LocalDiscovery",
        description = "Discover peers on the same LAN",
        defaultSuggestion = "yes",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "UDPRebindOnWake",
        description = "Rebind UDP sockets when phone wakes or changes network",
        defaultSuggestion = "yes",
        valuePresets = BOOL_PRESETS,
      ),
      KeySpec(
        name = "InterfaceRoute",
        description = "Subnets routed through the VPN (e.g. 0.0.0.0/0 for full tunnel)",
        defaultSuggestion = "0.0.0.0/0",
        valuePresets = { listOf("0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16") },
      ),
      KeySpec(
        name = "DNSServer",
        description = "DNS server(s) pushed to the VPN interface",
        defaultSuggestion = "1.1.1.1",
        valuePresets = { listOf("1.1.1.1", "8.8.8.8", "9.9.9.9") },
      ),
      KeySpec(
        name = "MTU",
        description = "VPN interface MTU",
        defaultSuggestion = "1380",
        valuePresets = { listOf("1280", "1380", "1400", "1420") },
      ),
      KeySpec(
        name = "AddressFamily",
        description = "Address family used for sockets",
        defaultSuggestion = "any",
        valuePresets = { listOf("any", "ipv4", "ipv6") },
      ),
    )

    fun findKeySpec(isOption: Boolean, key: String): KeySpec? {
      val list = if (isOption) OPTION_SPECS else HOST_SPECS
      return list.firstOrNull { it.name.equals(key, ignoreCase = true) }
    }

    fun intent(context: Context, netName: String): Intent =
      Intent(context, ConfigEditorActivity::class.java).putExtra(EXTRA_NET_NAME, netName)

    /** From a peer row: opens the editor directly in that node's dedicated tab. */
    fun intent(context: Context, netName: String, focusNode: String): Intent =
      Intent(context, ConfigEditorActivity::class.java)
        .putExtra(EXTRA_NET_NAME, netName)
        .putExtra(EXTRA_FOCUS_NODE, focusNode)
  }
}
