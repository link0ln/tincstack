/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2018 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.context

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.LoggerContext
import ch.qos.logback.classic.android.LogcatAppender
import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.Context
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy
import ch.qos.logback.core.rolling.RollingFileAppender
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy
import ch.qos.logback.core.util.FileSize
import org.slf4j.LoggerFactory

/**
 * @author euxane
 */
object AppLogger {
  private const val LOGCAT_PATTERN = "[%thread] %msg%n%rEx"
  private const val LOGFILE_PATTERN = "%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n%rEx"
  private const val MAX_FILE_SIZE = "2MB"
  private const val MAX_BACKUP_INDEX = 2

  fun configure() {
    val logPath = AppPaths.appLogFile().absolutePath
    (LoggerFactory.getILoggerFactory() as LoggerContext)
      .apply { reset() }
      .let { loggerContext ->
        (LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger)
          .apply {
            addAppender(LogcatAppender()
              .apply { context = loggerContext }
              .apply { encoder = patternEncoder(loggerContext, LOGCAT_PATTERN) }
              .apply { start() })
          }
          .apply {
            val fileAppender = RollingFileAppender<ILoggingEvent>().apply {
              context = loggerContext
              file = logPath
              encoder = patternEncoder(loggerContext, LOGFILE_PATTERN)
            }
            val rollingPolicy = FixedWindowRollingPolicy().apply {
              context = loggerContext
              setParent(fileAppender)
              fileNamePattern = "$logPath.%i"
              minIndex = 1
              maxIndex = MAX_BACKUP_INDEX
              start()
            }
            val triggerPolicy = SizeBasedTriggeringPolicy<ILoggingEvent>().apply {
              context = loggerContext
              maxFileSize = FileSize.valueOf(MAX_FILE_SIZE)
              start()
            }
            fileAppender.rollingPolicy = rollingPolicy
            fileAppender.triggeringPolicy = triggerPolicy
            fileAppender.start()
            addAppender(fileAppender)
          }
      }
  }

  private fun patternEncoder(ctx: Context, pat: String) =
    PatternLayoutEncoder()
      .apply { context = ctx }
      .apply { pattern = pat }
      .apply { start() }
}
