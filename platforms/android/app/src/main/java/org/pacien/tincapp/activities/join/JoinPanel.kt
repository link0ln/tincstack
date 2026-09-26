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

package org.pacien.tincapp.activities.join

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.view.View
import android.view.inputmethod.InputMethodManager
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.LifecycleOwner
import com.google.zxing.integration.android.IntentIntegrator
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.commands.Join
import org.pacien.tincapp.commands.JoinFailureKind
import org.pacien.tincapp.data.Invitation
import org.pacien.tincapp.databinding.JoinPanelBinding

/**
 * The join form (layout/join_panel.xml): paste, clipboard suggestion or QR
 * scan -> one button. The invitation is recognised in whatever was pasted
 * (surrounding text, blanks, a newline from a messenger, a token wrapped over
 * two lines: data/Invitation.kt) and the button only enables for a real one,
 * so the core is never handed a string it would reject before dialling.
 *
 * The join itself runs in [JoinController]; [onJoined] gets the new network's
 * name once, on whichever screen is showing when it completes.
 */
class JoinPanel(
  private val activity: BaseActivity,
  private val binding: JoinPanelBinding,
  owner: LifecycleOwner,
  private val onJoined: (String) -> Unit,
) {
  private val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  private var clipboardInvitation: Invitation? = null
  private var lastClipStamp: Long? = null
  private var detailsShown = false

  init {
    binding.invitationInput.doAfterTextChanged { onTextChanged() }
    binding.invitationLayout.setEndIconOnClickListener { pasteFromClipboard() }
    binding.clipboardUse.setOnClickListener { clipboardInvitation?.let { useInvitation(it) } }
    binding.joinButton.setOnClickListener { join() }
    binding.scanButton.setOnClickListener { scan() }
    binding.joinErrorDetails.setOnClickListener { toggleDetails() }
    JoinController.state.observe(owner) { render(it) }
  }

  fun prefill(text: String?) {
    if (!text.isNullOrBlank()) binding.invitationInput.setText(text.trim())
  }

  /** Android 10+ lets an app read the clipboard only while it has focus. */
  fun onWindowFocusChanged(hasFocus: Boolean) {
    if (hasFocus && binding.root.isShown) checkClipboard()
  }

  fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
    val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data) ?: return false
    val contents = result.contents ?: return true // cancelled
    val invitation = Invitation.find(contents)
    if (invitation == null) activity.notify(R.string.join_scan_no_invitation)
    else useInvitation(invitation)
    return true
  }

  private fun current(): Invitation? = Invitation.find(binding.invitationInput.text?.toString())

  private fun onTextChanged() {
    val text = binding.invitationInput.text?.toString().orEmpty()
    val invitation = current()
    binding.joinButton.isEnabled = invitation != null && JoinController.state.value !is JoinController.State.Running
    when {
      invitation != null -> {
        binding.invitationLayout.error = null
        binding.invitationLayout.helperText = activity.getString(R.string.join_detected_format, invitation.endpoint())
      }

      text.isBlank() -> {
        binding.invitationLayout.error = null
        binding.invitationLayout.helperText = activity.getString(R.string.join_input_help)
      }

      else -> binding.invitationLayout.error = activity.getString(R.string.join_not_an_invitation)
    }
    if (JoinController.state.value is JoinController.State.Failed) JoinController.reset()
    updateClipboardCard()
  }

  private fun useInvitation(invitation: Invitation) {
    binding.invitationInput.setText(invitation.toString())
    binding.invitationInput.setSelection(binding.invitationInput.length())
  }

  private fun pasteFromClipboard() {
    val text = clipboardText() ?: return
    val invitation = Invitation.find(text)
    if (invitation != null) useInvitation(invitation) else binding.invitationInput.setText(text.trim())
  }

  private fun clipboardText(): String? = try {
    clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(activity)?.toString()
  } catch (e: Exception) {
    null
  }

  /**
   * Offer an invitation found in the clipboard. Read once per new clip (its
   * timestamp, API 26+), so Android 12's "pasted from your clipboard" notice
   * does not pop up every time the app comes back to the front.
   */
  private fun checkClipboard() {
    if (!binding.invitationInput.text.isNullOrBlank()) return
    val description = clipboard.primaryClipDescription ?: return
    if (!description.hasMimeType("text/*")) return
    val stamp = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) description.timestamp else null
    if (stamp != null && stamp == lastClipStamp) return
    lastClipStamp = stamp
    clipboardInvitation = Invitation.find(clipboardText())
    updateClipboardCard()
  }

  private fun updateClipboardCard() {
    val invitation = clipboardInvitation
    val show = invitation != null && current() != invitation && JoinController.state.value !is JoinController.State.Running
    binding.clipboardCard.visibility = if (show) View.VISIBLE else View.GONE
    if (invitation != null) binding.clipboardEndpoint.text = invitation.endpoint()
  }

  private fun scan() {
    IntentIntegrator(activity)
      .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
      .setPrompt(activity.getString(R.string.join_scan_prompt))
      .setBeepEnabled(false)
      .setOrientationLocked(false)
      .initiateScan()
  }

  private fun join() {
    val invitation = current() ?: return
    (activity.getSystemService(Activity.INPUT_METHOD_SERVICE) as InputMethodManager)
      .hideSoftInputFromWindow(binding.invitationInput.windowToken, 0)
    binding.invitationInput.clearFocus()
    JoinController.start(invitation)
  }

  private fun toggleDetails() {
    detailsShown = !detailsShown
    binding.joinErrorLog.visibility = if (detailsShown) View.VISIBLE else View.GONE
    binding.joinErrorDetails.setText(if (detailsShown) R.string.join_hide_details else R.string.join_show_details)
  }

  private fun setBusy(busy: Boolean) {
    binding.invitationInput.isEnabled = !busy
    binding.invitationLayout.isEndIconVisible = !busy
    binding.scanButton.isEnabled = !busy
    binding.joinButton.isEnabled = !busy && current() != null
    binding.joinProgress.visibility = if (busy) View.VISIBLE else View.GONE
  }

  private fun render(state: JoinController.State) {
    when (state) {
      JoinController.State.Idle -> {
        setBusy(false)
        binding.joinError.visibility = View.GONE
      }

      is JoinController.State.Running -> {
        setBusy(true)
        binding.joinError.visibility = View.GONE
        binding.clipboardCard.visibility = View.GONE
        binding.joinProgressText.text = when (state.stage) {
          Join.Stage.CONTACTING -> activity.getString(R.string.join_stage_contacting_format, state.invitation.endpoint())
          Join.Stage.EXCHANGING -> activity.getString(R.string.join_stage_exchanging)
        }
      }

      is JoinController.State.Failed -> {
        setBusy(false)
        binding.joinError.visibility = View.VISIBLE
        binding.joinErrorMessage.text = listOf(failureMessage(state), activity.getString(R.string.join_nothing_saved))
          .joinToString("\n\n")
        binding.joinErrorLog.text = state.failure.details.joinToString("\n")
        detailsShown = true
        toggleDetails()
      }

      is JoinController.State.Joined -> {
        setBusy(false)
        binding.invitationInput.text = null
        clipboardInvitation = null
        JoinController.reset()
        onJoined(state.netName)
      }
    }
  }

  private fun failureMessage(state: JoinController.State.Failed): String {
    val inv = state.invitation
    return when (state.failure.kind) {
      JoinFailureKind.HOST_NOT_FOUND -> activity.getString(R.string.join_error_host_not_found_format, inv.host)
      JoinFailureKind.UNREACHABLE -> activity.getString(R.string.join_error_unreachable_format, inv.endpoint(), inv.port.toString())
      JoinFailureKind.WRONG_NODE -> activity.getString(R.string.join_error_wrong_node_format, inv.endpoint())
      JoinFailureKind.REJECTED -> activity.getString(R.string.join_error_rejected_format, inv.endpoint())
      JoinFailureKind.ALREADY_JOINED, JoinFailureKind.OTHER ->
        listOfNotNull(activity.getString(R.string.join_error_other), state.failure.details.lastOrNull { it.isNotBlank() })
          .joinToString(" ")
    }
  }
}
