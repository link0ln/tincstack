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
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.AudioPlaybackConfiguration
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import androidx.core.content.ContextCompat
import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.service.SessionStateMachine.Event

/**
 * Screen, keyguard, and active audio/media playback signals as [SessionStateMachine] events.
 *
 * SCREEN_OFF / SCREEN_ON / USER_PRESENT reach only receivers registered at
 * runtime, so the service registers one instance for the life of a session
 * that has `DisconnectOnScreenOff` and unregisters it when the session ends.
 *
 * While audio/media is actively playing (e.g. YouTube Music, Spotify, podcasts,
 * voice calls), screen lock does not suspend `tincd` until playback stops and
 * a grace period ([mediaStopGraceMs]) elapses without new playback starting.
 * Conversely, if audio playback starts while the session is already suspended
 * on a locked screen, [Event.MediaStarted] wakes `tincd` automatically.
 */
class ScreenStateReceiver(
  private val mediaStopGraceMs: Long = DEFAULT_MEDIA_STOP_GRACE_MS,
  private val dispatch: (Event) -> CompletableFuture<Unit>,
) : BroadcastReceiver() {
  private var registered = false
  private var appContext: Context? = null
  private var lastAudioActive = false
  private val handler = Handler(Looper.getMainLooper())

  private val mediaStopRunnable = Runnable {
    val ctx = appContext ?: return@Runnable
    if (!registered) return@Runnable
    if (!isAudioActive(ctx)) {
      lastAudioActive = false
      dispatch(Event.MediaStopped)
    }
  }

  private val audioCallback = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
    object : AudioManager.AudioPlaybackCallback() {
      override fun onPlaybackConfigChanged(configs: MutableList<AudioPlaybackConfiguration>?) {
        val ctx = appContext ?: return
        handleAudioStateChanged(ctx, configs)
      }
    }
  } else null

  override fun onReceive(context: Context, intent: Intent) {
    val event = eventFor(intent, isKeyguardLocked(context)) ?: return
    if (event is Event.ScreenOff && isAudioActive(context)) {
      handler.removeCallbacks(mediaStopRunnable)
      lastAudioActive = true
      dispatch(Event.MediaStarted)
    }
    // SCREEN_OFF may be followed by a CPU suspend as soon as onReceive returns:
    // hold the broadcast (and its wake lock) until the daemon is stopped,
    // capped at 5 seconds so a busy worker can never trigger a 10s BroadcastReceiver ANR.
    val pending = goAsyncOrNull()
    val finished = java.util.concurrent.atomic.AtomicBoolean(false)
    val finishOnce = Runnable {
      if (finished.compareAndSet(false, true)) {
        try {
          pending?.finish()
        } catch (_: Exception) {
        }
      }
    }
    handler.postDelayed(finishOnce, 5000L)
    dispatch(event).whenComplete { _, _ ->
      handler.removeCallbacks(finishOnce)
      finishOnce.run()
    }
  }

  fun handleAudioStateChanged(context: Context, configs: List<AudioPlaybackConfiguration>? = null) {
    if (!registered) return
    val active = isAudioActive(context, configs)
    if (active) {
      handler.removeCallbacks(mediaStopRunnable)
      if (!lastAudioActive) {
        lastAudioActive = true
        dispatch(Event.MediaStarted)
      }
    } else if (lastAudioActive) {
      handler.removeCallbacks(mediaStopRunnable)
      handler.postDelayed(mediaStopRunnable, mediaStopGraceMs)
    }
  }

  private fun goAsyncOrNull(): PendingResult? = try {
    goAsync()
  } catch (e: IllegalStateException) {
    null // not called from a real broadcast (tests)
  }

  fun register(context: Context) = synchronized(this) {
    if (registered) return
    appContext = context.applicationContext ?: context
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
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && audioCallback != null) {
      try {
        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager?
        audioManager?.registerAudioPlaybackCallback(audioCallback, handler)
      } catch (_: Exception) {
      }
    }
    registered = true
    if (isAudioActive(context)) {
      lastAudioActive = true
      dispatch(Event.MediaStarted)
    }
    val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager?
    if (powerManager != null && !powerManager.isInteractive) {
      dispatch(Event.ScreenOff)
    }
  }

  fun unregister(context: Context) = synchronized(this) {
    if (!registered) return
    handler.removeCallbacks(mediaStopRunnable)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && audioCallback != null) {
      try {
        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager?
        audioManager?.unregisterAudioPlaybackCallback(audioCallback)
      } catch (_: Exception) {
      }
    }
    try {
      context.unregisterReceiver(this)
    } catch (e: IllegalArgumentException) {
      // already gone
    }
    lastAudioActive = false
    appContext = null
    registered = false
  }

  fun isRegistered() = registered

  companion object {
    const val DEFAULT_MEDIA_STOP_GRACE_MS = 30_000L

    fun eventFor(intent: Intent, keyguardLocked: Boolean): Event? = when (intent.action) {
      Intent.ACTION_SCREEN_OFF -> Event.ScreenOff
      Intent.ACTION_SCREEN_ON -> Event.ScreenOn(keyguardLocked)
      Intent.ACTION_USER_PRESENT -> Event.UserPresent
      else -> null
    }

    private fun isKeyguardLocked(context: Context): Boolean =
      (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager?)?.isKeyguardLocked ?: true

    fun isAudioActive(context: Context, configs: List<AudioPlaybackConfiguration>? = null): Boolean {
      val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager? ?: return false
      if (audioManager.isMusicActive) return true
      val mode = audioManager.mode
      if (mode == AudioManager.MODE_IN_COMMUNICATION || mode == AudioManager.MODE_IN_CALL) return true
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val activeConfigs = configs ?: try {
          audioManager.activePlaybackConfigurations
        } catch (_: Exception) {
          emptyList()
        }
        // Note: For non-system apps, AOSP AudioService filters getActivePlaybackConfigurations()
        // to only return configurations currently in PLAYER_STATE_STARTED.
        if (activeConfigs.any { cfg ->
            val usage = cfg.audioAttributes?.usage ?: AudioAttributes.USAGE_UNKNOWN
            usage == AudioAttributes.USAGE_MEDIA ||
              usage == AudioAttributes.USAGE_GAME ||
              usage == AudioAttributes.USAGE_VOICE_COMMUNICATION ||
              usage == AudioAttributes.USAGE_UNKNOWN
          }) {
          return true
        }
      }
      return false
    }
  }
}
