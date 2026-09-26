/*
 * Tinc Mesh VPN: Android client and user interface
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

package org.pacien.tincapp.service

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.service.SessionStateMachine.Event

/**
 * Screen and keyguard broadcasts as [SessionStateMachine] events.
 *
 * SCREEN_OFF / SCREEN_ON / USER_PRESENT reach only receivers registered at
 * runtime, so the service registers one instance for the life of a session
 * that has `DisconnectOnScreenOff` and unregisters it when the session ends.
 * (The old tincapp registered a process-wide object and let `onDestroy` wipe
 * it; once the system stopped the idle service, nothing was left to hear the
 * unlock.)
 *
 * USER_PRESENT is the unlock signal. It is not sent in every configuration, so
 * SCREEN_ON also resumes when the keyguard is not locked at that moment (no
 * lock screen, or the screen came back before the lock timeout); with a locked
 * keyguard SCREEN_ON is ignored and USER_PRESENT follows the unlock.
 */
class ScreenStateReceiver(
  private val dispatch: (Event) -> CompletableFuture<Unit>,
) : BroadcastReceiver() {
  private var registered = false

  override fun onReceive(context: Context, intent: Intent) {
    val event = eventFor(intent, isKeyguardLocked(context)) ?: return
    // SCREEN_OFF may be followed by a CPU suspend as soon as onReceive returns:
    // hold the broadcast (and its wake lock) until the daemon is stopped.
    val pending = goAsyncOrNull()
    dispatch(event).whenComplete { _, _ -> pending?.finish() }
  }

  private fun goAsyncOrNull(): PendingResult? = try {
    goAsync()
  } catch (e: IllegalStateException) {
    null // not called from a real broadcast (tests)
  }

  fun register(context: Context) = synchronized(this) {
    if (registered) return
    val filter = IntentFilter().apply {
      addAction(Intent.ACTION_SCREEN_OFF)
      addAction(Intent.ACTION_SCREEN_ON)
      addAction(Intent.ACTION_USER_PRESENT)
    }
    // EXPORTED, not NOT_EXPORTED: USER_PRESENT is sent by SystemUI, which is
    // not the system uid, and a not-exported receiver never gets it (measured
    // on API 34: SCREEN_OFF/ON arrived, the PIN unlock's USER_PRESENT did not).
    // All three actions are protected broadcasts: no app can forge them.
    ContextCompat.registerReceiver(context, this, filter, ContextCompat.RECEIVER_EXPORTED)
    registered = true
  }

  fun unregister(context: Context) = synchronized(this) {
    if (!registered) return
    try {
      context.unregisterReceiver(this)
    } catch (e: IllegalArgumentException) {
      // already gone
    }
    registered = false
  }

  fun isRegistered() = registered

  companion object {
    fun eventFor(intent: Intent, keyguardLocked: Boolean): Event? = when (intent.action) {
      Intent.ACTION_SCREEN_OFF -> Event.ScreenOff
      Intent.ACTION_SCREEN_ON -> Event.ScreenOn(keyguardLocked)
      Intent.ACTION_USER_PRESENT -> Event.UserPresent
      else -> null
    }

    private fun isKeyguardLocked(context: Context): Boolean =
      (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager?)?.isKeyguardLocked ?: true
  }
}
