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

package org.pacien.tincapp.service

import android.content.Context
import android.os.SystemClock
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import org.pacien.tincapp.context.App

/**
 * What the VPN is doing, for the UI. Observable state rather than broadcasts:
 * the connect button's outcome used to travel as a local broadcast that the
 * activity only heard while resumed, so a failure that happened while a system
 * dialog (VPN consent, notification permission) covered the app was lost and
 * the "Starting VPN..." spinner stayed up for ever. A LiveData hands the
 * current value to whoever observes next.
 *
 * A failure is also kept on disk, so the reason is still shown after the
 * process was restarted; it is cleared by the next connect or by dismissing it.
 */
sealed class ConnectionState {
  object Disconnected : ConnectionState() {
    override fun toString() = "Disconnected"
  }

  /** Asked for; tun and daemon not up yet. */
  data class Connecting(val net: String) : ConnectionState()

  /** Tun established and tincd running (whether peers answer is the peers poller's business). */
  data class Connected(val net: String) : ConnectionState()

  /** DisconnectOnScreenOff: tincd stopped while the screen is locked, the tun kept. */
  data class Paused(val net: String) : ConnectionState()

  /** The last attempt or session ended in an error: [message] is for people, [details] for the log view. */
  data class Failed(val net: String?, val message: String, val details: String? = null, val lost: Boolean = false) : ConnectionState()

  val netName: String?
    get() = when (this) {
      is Connecting -> net
      is Connected -> net
      is Paused -> net
      is Failed -> net
      Disconnected -> null
    }

  /** A session exists or is being set up: the primary action is Disconnect. */
  val active: Boolean
    get() = this is Connecting || this is Connected || this is Paused
}

object VpnStatus {
  private const val STORE = "vpn_status"
  private const val KEY_NET = "failed_net"
  private const val KEY_MESSAGE = "failed_message"
  private const val KEY_DETAILS = "failed_details"
  private const val KEY_LOST = "failed_lost"

  private val store by lazy { App.getContext().getSharedPreferences(STORE, Context.MODE_PRIVATE) }

  private val mutable: MutableLiveData<ConnectionState> by lazy { MutableLiveData(restored()) }

  val state: LiveData<ConnectionState> get() = mutable

  @Volatile
  private var current: ConnectionState? = null

  @Volatile
  private var since: Long = SystemClock.elapsedRealtime()

  fun current(): ConnectionState = current ?: restored()

  /** When the current state began ([SystemClock.elapsedRealtime]). */
  fun since(): Long = since

  @Synchronized
  fun set(s: ConnectionState) {
    if (s != current) since = SystemClock.elapsedRealtime()
    current = s
    mutable.postValue(s)
    when (s) {
      is ConnectionState.Failed -> store.edit()
        .putString(KEY_NET, s.net)
        .putString(KEY_MESSAGE, s.message)
        .putString(KEY_DETAILS, s.details)
        .putBoolean(KEY_LOST, s.lost)
        .apply()

      else -> if (store.contains(KEY_MESSAGE)) store.edit().clear().apply()
    }
  }

  /** The user closed the error card. */
  fun dismissFailure() {
    if (current() is ConnectionState.Failed) set(ConnectionState.Disconnected)
  }

  private fun restored(): ConnectionState {
    val message = store.getString(KEY_MESSAGE, null) ?: return ConnectionState.Disconnected
    return ConnectionState.Failed(store.getString(KEY_NET, null), message, store.getString(KEY_DETAILS, null),
      store.getBoolean(KEY_LOST, false))
  }
}
