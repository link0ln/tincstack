/*
 * tincstack for Android
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

package org.pacien.tincapp.utils

import java.io.File
import java.io.RandomAccessFile

/** Owner-only permissions, recursively: the network directory holds private keys. */
fun File.makePrivate() {
  this.setExecutable(this.isDirectory, false)
  this.setReadable(true, true)
  this.setWritable(true, true)

  if (this.isDirectory)
    for (file in this.listFiles()!!)
      file.makePrivate()
}

/**
 * The last [n] lines of the file, in order, read from at most its last
 * [maxBytes]; empty if it does not exist or cannot be read. Plain
 * RandomAccessFile: commons-io's reverse reader needs java.nio.file (API 26).
 */
fun File.lastLines(n: Int, maxBytes: Int = 256 * 1024): List<String> = try {
  if (!isFile) emptyList()
  else RandomAccessFile(this, "r").use { f ->
    val start = maxOf(0L, f.length() - maxBytes)
    val bytes = ByteArray((f.length() - start).toInt())
    f.seek(start)
    f.readFully(bytes)
    val lines = String(bytes, Charsets.UTF_8).lines()
      .let { if (start > 0) it.drop(1) else it } // the first one is cut
      .let { if (it.lastOrNull()?.isEmpty() == true) it.dropLast(1) else it }
    lines.takeLast(n)
  }
} catch (e: Exception) {
  emptyList()
}
