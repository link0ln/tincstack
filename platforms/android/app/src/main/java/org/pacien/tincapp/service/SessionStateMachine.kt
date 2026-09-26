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

/**
 * The life of one VPN session, including the `DisconnectOnScreenOff` pause.
 *
 * A pure transition function: no Android, no I/O. [TincVpnService] feeds it
 * events and carries out the [Action]s it returns, so every rule below is unit
 * tested (SessionStateMachineTest) without an emulator.
 *
 *  - [State.Idle]: no session. Nothing the screen does can start one; this is
 *    what makes an explicit disconnect or a revoke final (no resurrection).
 *  - [State.Connected]: tun established by the service, tincd running.
 *  - [State.Suspended]: the screen went off with `DisconnectOnScreenOff`; tincd
 *    is stopped (no keepalives, no radio wake-ups) but the service keeps the
 *    tun fd, so the VPN stays established: traffic routed into it is dropped
 *    instead of leaking to the underlying network, and resuming needs neither
 *    `VpnService.prepare` nor a new `establish()`.
 *
 * Every tincd launch is identified by a [DaemonRun]: the session (unique per
 * connect, allocated by the service) and the launch within it. Asynchronous
 * results (a daemon that exits, a relaunch that fails) are tagged with the run
 * they belong to, and one from any other run is ignored: the exit of the daemon a suspend stopped
 * cannot tear down the session after a quick unlock already relaunched it, and
 * a late exit from a previous session cannot touch the next one.
 */
object SessionStateMachine {
  data class DaemonRun(val session: Long, val launch: Int) {
    fun next() = DaemonRun(session, launch + 1)
  }

  sealed class State {
    object Idle : State() {
      override fun toString() = "Idle"
    }

    data class Connected(val netName: String, val run: DaemonRun, val suspendOnScreenOff: Boolean) : State()
    data class Suspended(val netName: String, val lastRun: DaemonRun) : State()
  }

  sealed class Event {
    /** The tun is established and daemon [run] is launched for a new session. */
    data class SessionStarted(val netName: String, val run: DaemonRun, val suspendOnScreenOff: Boolean) : Event()

    object ScreenOff : Event()

    /** ACTION_SCREEN_ON; [keyguardLocked] from KeyguardManager.isKeyguardLocked at that moment. */
    data class ScreenOn(val keyguardLocked: Boolean) : Event()

    /** ACTION_USER_PRESENT: the keyguard is gone. */
    object UserPresent : Event()

    /** The user asked to disconnect (UI, notification action, intent API). */
    object UserDisconnect : Event()

    /** VpnService.onRevoke: another VPN app took over, or the user revoked the consent. */
    object Revoked : Event()

    /** tincd [run] exited. */
    data class DaemonExited(val run: DaemonRun) : Event()

    /** Relaunching tincd as [run] failed. */
    data class ResumeFailed(val run: DaemonRun) : Event()
  }

  sealed class Action {
    /** Stop tincd, keep the tun fd and the session. */
    data class StopDaemon(val netName: String) : Action()

    /** Relaunch tincd as [run] on the kept tun fd. */
    data class StartDaemon(val netName: String, val run: DaemonRun) : Action()

    /**
     * End [session] (null: whatever is left): stop tincd if running, close the
     * tun, leave the foreground, forget the network.
     */
    data class TearDown(val session: Long?, val reason: TearDownReason) : Action()
  }

  enum class TearDownReason { USER, REVOKED, DAEMON_EXITED, RESUME_FAILED }

  data class Transition(val state: State, val actions: List<Action> = emptyList())

  fun next(state: State, event: Event): Transition = when (event) {
    is Event.SessionStarted -> Transition(State.Connected(event.netName, event.run, event.suspendOnScreenOff))

    Event.UserDisconnect -> Transition(State.Idle, listOf(Action.TearDown(sessionOf(state), TearDownReason.USER)))
    Event.Revoked -> Transition(State.Idle, listOf(Action.TearDown(sessionOf(state), TearDownReason.REVOKED)))

    Event.ScreenOff -> when (state) {
      is State.Connected ->
        if (state.suspendOnScreenOff)
          Transition(State.Suspended(state.netName, state.run), listOf(Action.StopDaemon(state.netName)))
        else Transition(state)

      else -> Transition(state)
    }

    Event.UserPresent -> resume(state)
    is Event.ScreenOn -> if (event.keyguardLocked) Transition(state) else resume(state)

    is Event.DaemonExited ->
      if (state is State.Connected && state.run == event.run)
        Transition(State.Idle, listOf(Action.TearDown(state.run.session, TearDownReason.DAEMON_EXITED)))
      else Transition(state) // a daemon we stopped ourselves, or one from another run

    is Event.ResumeFailed ->
      if (state is State.Connected && state.run == event.run)
        Transition(State.Idle, listOf(Action.TearDown(state.run.session, TearDownReason.RESUME_FAILED)))
      else Transition(state)
  }

  private fun sessionOf(state: State): Long? = when (state) {
    is State.Connected -> state.run.session
    is State.Suspended -> state.lastRun.session
    State.Idle -> null
  }

  private fun resume(state: State): Transition = when (state) {
    is State.Suspended -> state.lastRun.next().let { run ->
      Transition(
        State.Connected(state.netName, run, suspendOnScreenOff = true),
        listOf(Action.StartDaemon(state.netName, run)))
    }

    else -> Transition(state)
  }
}
