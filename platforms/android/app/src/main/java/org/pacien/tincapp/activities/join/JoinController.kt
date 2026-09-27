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

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import org.pacien.tincapp.commands.Join
import org.pacien.tincapp.commands.JoinFailure
import org.pacien.tincapp.commands.JoinFailureKind
import org.pacien.tincapp.data.Invitation

/**
 * The join in progress, process-wide: it outlives the screen that started it
 * (rotation, dark mode switch, the user looking elsewhere), and whichever join
 * screen is showing picks up its progress and outcome.
 */
object JoinController {
  sealed class State {
    object Idle : State()
    data class Running(val invitation: Invitation, val stage: Join.Stage) : State()
    data class Joined(val netName: String) : State()
    data class Failed(val invitation: Invitation, val failure: JoinFailure) : State()
  }

  private val mutable = MutableLiveData<State>(State.Idle)
  val state: LiveData<State> get() = mutable

  @Volatile private var running = false

  @Synchronized
  fun start(invitation: Invitation) {
    if (running) return
    running = true
    mutable.value = State.Running(invitation, Join.Stage.CONTACTING)
    Join.join(invitation) { stage -> if (running) mutable.postValue(State.Running(invitation, stage)) }
      .whenComplete { netName, e ->
        running = false
        mutable.postValue(
          if (e == null) State.Joined(netName)
          else State.Failed(invitation, (e.cause ?: e) as? JoinFailure
            ?: JoinFailure(JoinFailureKind.OTHER, listOf((e.cause ?: e).message ?: e.toString()))))
      }
  }

  /** The outcome was shown (or acted upon): back to a blank form. */
  fun reset() {
    if (!running) mutable.value = State.Idle
  }
}
