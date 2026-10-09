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
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.databinding.ActivityConfigEditorBinding
import org.pacien.tincapp.databinding.ConfigKeyItemBinding
import org.pacien.tincapp.databinding.DialogAddKeyBinding
import org.pacien.tincapp.extensions.Java.defaultMessage

/**
 * The interactive editor of everything in a network's tinc.yaml that the
 * daemon does not own:
 *
 *  - `options`: every key the file holds, one row per key, edited in place
 *    (a multi-value key shows the values comma-separated and is saved back
 *    as a list);
 *  - `hosts.<node>`: one section per node -- own node first -- each with the
 *    same per-key rows (Address, Port, HttpsPort, ..., Subnet, key PEMs are
 *    ordinary rows: the owner asked for the whole config, not a curated
 *    subset).
 *
 * Everything is editable while OFFLINE: this screen reads and writes
 * tinc.yaml only; the daemon is not involved and need not be running. That
 * is the point: a wrong or stale config is exactly the state one edits it
 * in. Save applies the rows through setOptions()/setHostVars() and asks the
 * running session (if any) to reconnect.
 */
class ConfigEditorActivity : BaseActivity() {
  private lateinit var binding: ActivityConfigEditorBinding
  override val snackbarRoot: View get() = binding.configRoot
  private val netName by lazy { intent.getStringExtra(EXTRA_NET_NAME)!! }
  private val yaml by lazy { TincYaml(AppPaths.tincYamlFile(netName)) }
  private lateinit var stanza: String
  private val adapter = Adapter()
  private val rows = mutableListOf<Row>()
  private val dirty = java.util.concurrent.atomic.AtomicBoolean(false)

  /** One editable key. `original` is what the file holds; `pending` is what
      the user typed. Save writes only rows whose pending differs. */
  data class Row(
    val kind: Kind,
    val sectionTitle: Int,
    val sectionSort: Int,
    val net: String,
    val node: String?,          // hosts row
    val k: String,
    val original: String,
  ) {
    var pending: String? = null
    fun key() = k
    fun value() = original
    fun set(v: String) { pending = v }
    fun changed() = pending != null && pending != original

    enum class Kind { OPTION, HOST }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = ActivityConfigEditorBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = true)
    supportActionBar?.subtitle = netName
    binding.configList.layoutManager = LinearLayoutManager(this)
    binding.configList.adapter = adapter
    binding.configAdd.setOnClickListener { addKeyDialog() }
    binding.configSave.setOnClickListener { save() }
    stanza = yaml.resolveNetwork(netName)
    reload()
  }

  private fun reload() {
    rows.clear()
    for ((k, v) in yaml.options(stanza)) {
      rows.add(Row(Row.Kind.OPTION, R.string.config_section_options, 0, stanza, null, k, TincYaml.valuesOf(v).joinToString(", ")))
    }
    for (node in hostNames()) {
      val text = yaml.hostText(stanza, node) ?: continue
      text.lineSequence()
        .map { it.trim() }
        .filter { !it.startsWith("#") && it.contains('=') }
        .map { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
        .forEach { (k, v) -> rows.add(Row(Row.Kind.HOST, R.string.config_section_hosts, 1, stanza, node, k, v)) }
    }
    adapter.notifyDataSetChanged()
  }

  /** Host names: the own node first, the rest after it. */
  private fun hostNames(): List<String> {
    val own = yaml.optionValue(stanza, "Name")
    val names = yaml.networkMapPublic(stanza)["hosts"]?.let { h ->
      (h as? Map<*, *>)?.keys?.map { it.toString() }.orEmpty()
    } ?: emptyList()
    return (listOfNotNull(own?.takeIf { it in names }) + names.filter { it != own })
  }

  private fun addKeyDialog() {
    val own = yaml.optionValue(stanza, "Name") ?: stanza
    val sections = arrayOf(getString(R.string.config_section_options), getString(R.string.config_section_host_format, own))
    val dialogView = layoutInflater.inflate(R.layout.dialog_add_key, null)
    val addBinding = DialogAddKeyBinding.bind(dialogView)
    addBinding.addKeySection.setText(sections[0])
    addBinding.addKeySection.setOnClickListener {
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.config_pick_section)
        .setItems(sections) { _, w -> addBinding.addKeySection.setText(sections[w]) }
        .show()
    }
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.config_add_key)
      .setView(dialogView)
      .setPositiveButton(R.string.action_add) { _, _ ->
        val k = addBinding.addKeyName.text?.toString()?.trim().orEmpty()
        if (!k.matches(Regex("[A-Za-z][A-Za-z0-9]*"))) {
          addBinding.addKeyNameLayout.error = getString(R.string.config_bad_key)
          return@setPositiveButton
        }
        if (rows.any { it.key().equals(k, ignoreCase = true) }) {
          addBinding.addKeyNameLayout.error = getString(R.string.config_key_exists)
          return@setPositiveButton
        }
        if (addBinding.addKeySection.text.toString() == sections[0]) {
          rows.add(0, Row(Row.Kind.OPTION, R.string.config_section_options, 0, stanza, null, k, ""))
        } else {
          rows.add(Row(Row.Kind.HOST, R.string.config_section_hosts, 1, stanza, own, k, ""))
        }
        adapter.notifyDataSetChanged()
        binding.configList.scrollToPosition(0)
        markDirty()
      }
      .setNegativeButton(R.string.action_cancel, null)
      .show()
  }

  private fun markDirty() {
    dirty.set(true)
    binding.configSave.isEnabled = true
  }

  private fun save() {
    var failed: Exception? = null
    for (r in rows) {
      if (!r.changed()) continue
      try {
        when (r.kind) {
          Row.Kind.OPTION -> {
            val values = (r.pending ?: r.original).split(',').map { it.trim() }.filter { it.isNotEmpty() }
            yaml.setOptions(r.net, mapOf(r.k to values.ifEmpty { null }))
          }
          Row.Kind.HOST -> yaml.setHostVars(r.net, r.node!!, mapOf(r.k to (r.pending ?: r.original).ifBlank { null }))
        }
      } catch (e: Exception) {
        failed = e
        break
      }
    }
    if (failed != null) {
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.config_save_failed)
        .setMessage(failed.cause?.defaultMessage() ?: failed.defaultMessage())
        .setPositiveButton(R.string.action_close, null)
        .show()
      return
    }
    reconnectIfActive()
    notifyDone()
    finish()
  }

  private fun notifyDone() {
    com.google.android.material.snackbar.Snackbar.make(binding.configRoot, R.string.config_saved, com.google.android.material.snackbar.Snackbar.LENGTH_SHORT).show()
  }

  private fun reconnectIfActive() {
    if (org.pacien.tincapp.service.TincVpnService.isDaemonRunning()) {
      org.pacien.tincapp.service.TincVpnService.connect(netName)
    }
    // not connected: the new config simply applies at the next manual connect
  }

  private inner class Adapter : RecyclerView.Adapter<Holder>() {
    override fun getItemCount() = rows.size
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
      Holder(ConfigKeyItemBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
      val r = rows[position]
      val b = holder.binding
      b.keySection.isVisible = position == 0 || rows[position - 1].sectionSort != r.sectionSort
      b.keySection.setText(r.sectionTitle)
      b.keyName.text = r.key()
      b.keyValue.setText(r.value())
      b.keyValue.addTextChangedListener(SimpleWatcher { s ->
        r.set(s?.toString()?.trim().orEmpty())
        markDirty()
      })
      b.keyRemove.isVisible = true
      b.keyRemove.setOnClickListener {
        val pos = rows.indexOf(r)
        if (pos == androidx.recyclerview.widget.RecyclerView.NO_POSITION) return@setOnClickListener
        MaterialAlertDialogBuilder(this@ConfigEditorActivity)
          .setTitle(getString(R.string.config_remove_key_title, rows[pos].key()))
          .setMessage(R.string.config_remove_key_msg)
          .setPositiveButton(R.string.action_remove) { _, _ ->
            rows[pos].set("")
            rows.removeAt(pos)
            adapter.notifyDataSetChanged()
            markDirty()
          }
          .setNegativeButton(R.string.action_cancel, null)
          .show()
      }
    }
  }

  private inner class Holder(val binding: ConfigKeyItemBinding) : RecyclerView.ViewHolder(binding.root)

  private class SimpleWatcher(private val onChange: (Editable?) -> Unit) : TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun afterTextChanged(s: Editable?) = onChange(s)
  }

  companion object {
    private const val EXTRA_NET_NAME = "netName"
    fun intent(context: Context, netName: String): Intent =
      Intent(context, ConfigEditorActivity::class.java).putExtra(EXTRA_NET_NAME, netName)
  }
}
