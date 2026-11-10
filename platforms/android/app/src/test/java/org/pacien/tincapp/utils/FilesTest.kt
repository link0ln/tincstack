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

package org.pacien.tincapp.utils

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

class FilesTest {
  @get:Rule
  val tmp = TemporaryFolder()

  @Test
  fun makePrivateClearsGroupAndOtherPermissionsAndHandlesMissingFiles() {
    val dir = tmp.newFolder("netconf")
    val subDir = File(dir, "sub").apply { mkdirs() }
    val secretFile = File(subDir, "tinc.yaml").apply {
      writeText("secret")
      setReadable(true, false)
      setWritable(true, false)
      setExecutable(true, false)
    }

    dir.makePrivate()

    assertTrue(dir.canRead())
    assertTrue(dir.canWrite())
    assertTrue(dir.canExecute())
    assertTrue(secretFile.canRead())
    assertTrue(secretFile.canWrite())

    val perms = Files.getPosixFilePermissions(secretFile.toPath())
    assertFalse(PosixFilePermission.GROUP_READ in perms)
    assertFalse(PosixFilePermission.GROUP_WRITE in perms)
    assertFalse(PosixFilePermission.OTHERS_READ in perms)
    assertFalse(PosixFilePermission.OTHERS_WRITE in perms)
    assertFalse(PosixFilePermission.OWNER_EXECUTE in perms)

    val dirPerms = Files.getPosixFilePermissions(subDir.toPath())
    assertFalse(PosixFilePermission.GROUP_READ in dirPerms)
    assertFalse(PosixFilePermission.OTHERS_READ in dirPerms)
    assertTrue(PosixFilePermission.OWNER_EXECUTE in dirPerms)

    // Non-existent file must not throw NullPointerException on listFiles()
    File(dir, "does-not-exist").makePrivate()
  }
}
