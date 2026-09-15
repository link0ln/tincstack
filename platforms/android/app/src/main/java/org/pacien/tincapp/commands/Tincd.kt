/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2020 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.commands

import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.context.AppPaths

/**
 * The daemon, started in YAML mode (`-c <net>/tinc.yaml -n <stanza>`): it reads
 * and writes the one config file itself, including materialising keys and
 * defaults into it on first start.
 *
 * @author euxane
 */
object Tincd {
  fun start(netName: String, stanza: String, device: String): CompletableFuture<Unit> =
    Executor.call(Command(AppPaths.tincd().absolutePath)
      .withOption("no-detach")
      .withOption("config", AppPaths.tincYamlFile(netName).absolutePath)
      .withOption("net", stanza)
      .withOption("pidfile", AppPaths.pidFile(netName).absolutePath)
      .withOption("logfile", AppPaths.logFile(netName).absolutePath)
      .withOption("option", "DeviceType=fd")
      .withOption("option", "Device=@$device")
    ).thenApply { }
}
