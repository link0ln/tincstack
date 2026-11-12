/*
 * tincstack for Android
 * Copyright (C) 2017-2019 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.activities.common

import androidx.lifecycle.LiveData
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * @author euxane
 */
abstract class SelfRefreshingLiveData<T>(private val refreshInterval: Long, private val timeUnit: TimeUnit) : LiveData<T>() {
  private var scheduledFuture: ScheduledFuture<*>? = null

  override fun onActive() {
    scheduledFuture?.cancel(false)
    scheduledFuture = sharedScheduler.scheduleWithFixedDelay({
      try {
        onRefresh()
      } catch (e: Exception) {
        // one failed poll must not cancel the schedule
      }
    }, 0, refreshInterval, timeUnit)
  }

  override fun onInactive() {
    scheduledFuture?.cancel(false)
    scheduledFuture = null
  }

  abstract fun onRefresh()

  companion object {
    private val threadSeq = AtomicInteger(0)
    private val sharedScheduler: ScheduledExecutorService =
      Executors.newScheduledThreadPool(2) { r ->
        Thread(r, "tinc-livedata-${threadSeq.incrementAndGet()}").apply { isDaemon = true }
      }
  }
}
