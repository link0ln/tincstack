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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.pacien.tincapp.service.SessionStateMachine.Action
import org.pacien.tincapp.service.SessionStateMachine.DaemonRun
import org.pacien.tincapp.service.SessionStateMachine.Event
import org.pacien.tincapp.service.SessionStateMachine.State
import org.pacien.tincapp.service.SessionStateMachine.TearDownReason

class SessionStateMachineTest {
  private val run0 = DaemonRun(7, 0)

  /** Feed [events] from [start]; the final state and every action, in order. */
  private fun play(start: State, vararg events: Event): Pair<State, List<Action>> {
    var state = start
    val actions = mutableListOf<Action>()
    for (e in events) {
      val t = SessionStateMachine.next(state, e)
      state = t.state
      actions += t.actions
    }
    return state to actions
  }

  private fun started(suspend: Boolean = true) = Event.SessionStarted("net", run0, suspend)

  @Test
  fun lockStopsTheDaemonAndUnlockRelaunchesItOnTheSameSession() {
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.UserPresent)
    assertEquals(State.Connected("net", DaemonRun(7, 1), true), state)
    assertEquals(listOf(Action.StopDaemon("net"), Action.StartDaemon("net", DaemonRun(7, 1))), actions)
  }

  @Test
  fun withoutTheOptionTheScreenIsIgnored() {
    val (state, actions) = play(State.Idle, started(suspend = false), Event.ScreenOff, Event.UserPresent, Event.ScreenOn(false))
    assertEquals(State.Connected("net", run0, false), state)
    assertTrue(actions.isEmpty())
  }

  @Test
  fun repeatedCyclesUseAFreshRunEachTime() {
    val (state, actions) = play(State.Idle, started(),
      Event.ScreenOff, Event.UserPresent,
      Event.ScreenOff, Event.UserPresent,
      Event.ScreenOff, Event.UserPresent)
    assertEquals(State.Connected("net", DaemonRun(7, 3), true), state)
    assertEquals(listOf(1, 2, 3), actions.filterIsInstance<Action.StartDaemon>().map { it.run.launch })
    assertEquals(3, actions.filterIsInstance<Action.StopDaemon>().size)
  }

  @Test
  fun screenOnWithALockedKeyguardWaitsForUserPresent() {
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.ScreenOn(keyguardLocked = true))
    assertEquals(State.Suspended("net", run0), state)
    assertEquals(listOf(Action.StopDaemon("net")), actions)
  }

  @Test
  fun screenOnWithoutAKeyguardResumes() {
    // no lock screen, or the screen came back before the lock timeout: no USER_PRESENT to wait for
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.ScreenOn(keyguardLocked = false))
    assertEquals(State.Connected("net", DaemonRun(7, 1), true), state)
    assertEquals(Action.StartDaemon("net", DaemonRun(7, 1)), actions.last())
  }

  @Test
  fun screenOnThenUserPresentResumesOnce() {
    val (_, actions) = play(State.Idle, started(), Event.ScreenOff, Event.ScreenOn(false), Event.UserPresent)
    assertEquals(1, actions.filterIsInstance<Action.StartDaemon>().size)
  }

  @Test
  fun aSecondScreenOffWhileSuspendedDoesNothing() {
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.ScreenOff)
    assertEquals(State.Suspended("net", run0), state)
    assertEquals(1, actions.size)
  }

  @Test
  fun unlockWithoutAPriorLockDoesNothing() {
    val (state, actions) = play(State.Idle, started(), Event.UserPresent, Event.ScreenOn(false))
    assertEquals(State.Connected("net", run0, true), state)
    assertTrue(actions.isEmpty())
  }

  @Test
  fun userDisconnectWhileLockedIsFinal() {
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.UserDisconnect, Event.UserPresent, Event.ScreenOn(false))
    assertEquals(State.Idle, state)
    assertEquals(listOf(Action.StopDaemon("net"), Action.TearDown(7, TearDownReason.USER)), actions)
  }

  @Test
  fun userDisconnectWhileUnlockedThenLockCycleStaysDisconnected() {
    val (state, actions) = play(State.Idle, started(), Event.UserDisconnect, Event.ScreenOff, Event.UserPresent)
    assertEquals(State.Idle, state)
    assertEquals(listOf(Action.TearDown(7, TearDownReason.USER)), actions)
  }

  @Test
  fun revokeWinsInEveryState() {
    for (prefix in listOf(arrayOf<Event>(started()), arrayOf(started(), Event.ScreenOff))) {
      val (state, actions) = play(State.Idle, *prefix, Event.Revoked, Event.UserPresent)
      assertEquals(State.Idle, state)
      assertEquals(Action.TearDown(7, TearDownReason.REVOKED), actions.last())
    }
  }

  @Test
  fun theDaemonASuspendStoppedIsNotACrash() {
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.DaemonExited(run0))
    assertEquals(State.Suspended("net", run0), state)
    assertEquals(listOf(Action.StopDaemon("net")), actions)
  }

  @Test
  fun aLateExitOfTheStoppedDaemonAfterAQuickUnlockIsIgnored() {
    // lock, unlock before the first daemon's exit is reported: run 0's exit must not end run 1
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.UserPresent, Event.DaemonExited(run0))
    assertEquals(State.Connected("net", DaemonRun(7, 1), true), state)
    assertTrue(actions.none { it is Action.TearDown })
  }

  @Test
  fun anUnexpectedExitOfTheCurrentDaemonEndsTheSession() {
    val (state, actions) = play(State.Idle, started(), Event.DaemonExited(run0))
    assertEquals(State.Idle, state)
    assertEquals(listOf(Action.TearDown(7, TearDownReason.DAEMON_EXITED)), actions)
  }

  @Test
  fun anExitFromAPreviousSessionIsIgnored() {
    val next = Event.SessionStarted("net", DaemonRun(8, 0), true)
    val (state, actions) = play(State.Idle, started(), Event.UserDisconnect, next, Event.DaemonExited(run0))
    assertEquals(State.Connected("net", DaemonRun(8, 0), true), state)
    assertEquals(listOf(Action.TearDown(7, TearDownReason.USER)), actions)
  }

  @Test
  fun aFailedRelaunchEndsTheSession() {
    val run1 = DaemonRun(7, 1)
    val (state, actions) = play(State.Idle, started(), Event.ScreenOff, Event.UserPresent, Event.ResumeFailed(run1))
    assertEquals(State.Idle, state)
    assertEquals(Action.TearDown(7, TearDownReason.RESUME_FAILED), actions.last())
  }

  @Test
  fun aDisconnectWithNoSessionStillTearsDownWhateverIsQueued() {
    // a connect still starting on the worker: the tear-down is queued after it
    val (state, actions) = play(State.Idle, Event.UserDisconnect)
    assertEquals(State.Idle, state)
    assertEquals(listOf(Action.TearDown(null, TearDownReason.USER)), actions)
  }

  @Test
  fun theScreenCannotStartASession() {
    val (state, actions) = play(State.Idle, Event.ScreenOff, Event.UserPresent, Event.ScreenOn(false))
    assertEquals(State.Idle, state)
    assertTrue(actions.isEmpty())
  }
}
