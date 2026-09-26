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

import android.app.Application
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import java8.util.concurrent.CompletableFuture
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.pacien.tincapp.service.SessionStateMachine.Action
import org.pacien.tincapp.service.SessionStateMachine.DaemonRun
import org.pacien.tincapp.service.SessionStateMachine.Event
import org.pacien.tincapp.service.SessionStateMachine.State
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Real broadcasts through a registered [ScreenStateReceiver], the keyguard
 * state from (shadowed) KeyguardManager, into the real [SessionStateMachine]:
 * the same wiring as TincVpnService, minus the daemon.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class ScreenStateReceiverTest {
  private val context: Context = ApplicationProvider.getApplicationContext()
  private val keyguard = shadowOf(context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager)

  private var state: State = State.Idle
  private val actions = mutableListOf<Action>()
  private val receiver = ScreenStateReceiver { event ->
    SessionStateMachine.next(state, event).let { state = it.state; actions += it.actions }
    CompletableFuture.completedFuture(Unit)
  }

  private fun broadcast(action: String) {
    context.sendBroadcast(Intent(action))
    shadowOf(Looper.getMainLooper()).idle()
  }

  private fun connect() {
    state = SessionStateMachine.next(State.Idle, Event.SessionStarted("net", DaemonRun(1, 0), true)).state
    receiver.register(context)
  }

  @Test
  fun lockAndUnlockWithASecureKeyguard() {
    connect()
    keyguard.setKeyguardLocked(true)
    broadcast(Intent.ACTION_SCREEN_OFF)
    assertEquals(State.Suspended("net", DaemonRun(1, 0)), state)

    broadcast(Intent.ACTION_SCREEN_ON) // keyguard still up: nothing yet
    assertTrue(state is State.Suspended)

    keyguard.setKeyguardLocked(false)
    broadcast(Intent.ACTION_USER_PRESENT)
    assertEquals(State.Connected("net", DaemonRun(1, 1), true), state)
    assertEquals(listOf(Action.StopDaemon("net"), Action.StartDaemon("net", DaemonRun(1, 1))), actions)
  }

  @Test
  fun screenOnWithoutKeyguardResumesWithoutUserPresent() {
    connect()
    keyguard.setKeyguardLocked(false)
    broadcast(Intent.ACTION_SCREEN_OFF)
    broadcast(Intent.ACTION_SCREEN_ON)
    assertEquals(State.Connected("net", DaemonRun(1, 1), true), state)
    // and the USER_PRESENT that may still follow does not relaunch twice
    broadcast(Intent.ACTION_USER_PRESENT)
    assertEquals(1, actions.filterIsInstance<Action.StartDaemon>().size)
  }

  @Test
  fun unregisteredReceiverHearsNothing() {
    connect()
    receiver.unregister(context)
    assertFalse(receiver.isRegistered())
    broadcast(Intent.ACTION_SCREEN_OFF)
    assertEquals(State.Connected("net", DaemonRun(1, 0), true), state)
    assertTrue(actions.isEmpty())
    receiver.unregister(context) // twice is harmless
  }

  @Test
  fun registerIsIdempotent() {
    connect()
    receiver.register(context)
    broadcast(Intent.ACTION_SCREEN_OFF)
    assertEquals(1, actions.size) // one delivery, not two
  }

  @Test
  fun unrelatedIntentsAreNotEvents() {
    assertEquals(null, ScreenStateReceiver.eventFor(Intent(Intent.ACTION_BATTERY_LOW), false))
    assertEquals(Event.ScreenOn(true), ScreenStateReceiver.eventFor(Intent(Intent.ACTION_SCREEN_ON), true))
  }
}
