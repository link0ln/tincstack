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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class AppUpdaterTest {

  private fun releaseJson(
    tag: String = "v0.5.14",
    apkName: String = "tincstack-$tag.apk",
    withSums: Boolean = true,
    digest: String = "sha256:" + "a".repeat(64),
    notes: String = "## Checksums\\n\\nSHA256SUMS: " + "b".repeat(64),
  ): String {
    val sumsAsset = if (withSums) {
      """,{"name":"SHA256SUMS","browser_download_url":"https://x/SHA256SUMS"}"""
    } else {
      ""
    }
    return """
      {
        "tag_name": "$tag",
        "draft": false,
        "prerelease": false,
        "body": "$notes",
        "assets": [
          {"name": "tincstack-$tag-windows-x86_64.zip", "browser_download_url": "https://x/$tag.zip"},
          {"name": "$apkName", "browser_download_url": "https://x/$apkName", "digest": "$digest"}$sumsAsset
        ]
      }
    """.trimIndent()
  }

  @Test
  fun parseVersionHandlesSemverAndDev() {
    assertEquals(Triple(0, 5, 14), AppUpdater.parseVersion("v0.5.14"))
    assertEquals(Triple(0, 10, 2), AppUpdater.parseVersion("0.10.2"))
    assertNull(AppUpdater.parseVersion("0.5.0-dev"))
    assertNull(AppUpdater.parseVersion("dev"))
    assertNull(AppUpdater.parseVersion(""))
  }

  @Test
  fun isNewerComparesSemverNumericOrder() {
    assertTrue(AppUpdater.isNewer("0.5.13", "v0.5.14"))
    assertTrue(AppUpdater.isNewer("v0.5.9", "v0.5.10"))
    assertTrue(AppUpdater.isNewer("0.5.0-dev", "v0.5.1"))
    assertFalse(AppUpdater.isNewer("0.5.14", "v0.5.14"))
    assertFalse(AppUpdater.isNewer("0.5.15", "v0.5.14"))
  }

  @Test
  fun findAssetsPicksSignedApkAndSums() {
    val rel = AppUpdater.findAssets(releaseJson("v0.5.14"))
    assertNotNull(rel)
    assertEquals("v0.5.14", rel!!.version)
    assertEquals("tincstack-v0.5.14.apk", rel.apkName)
    assertEquals("https://x/tincstack-v0.5.14.apk", rel.apkUrl)
    assertEquals("https://x/SHA256SUMS", rel.sumsUrl)
  }

  @Test
  fun findAssetsRefusesUnsignedApk() {
    val json = releaseJson("v0.5.14", apkName = "tincstack-v0.5.14-UNSIGNED-WILL-NOT-INSTALL.apk")
    assertNull(AppUpdater.findAssets(json))
  }

  @Test
  fun checkIfDueRespectsThreeHourCooldownUnlessForced() {
    val now = 1_000_000_000L
    val recent = now - 60_000L
    var called = 0
    val fetcher: (String) -> String = {
      called++
      releaseJson("v0.5.14")
    }
    assertNull(AppUpdater.checkIfDue("0.5.13", now, recent, force = false, fetcher = fetcher))
    assertEquals(0, called)

    val forced = AppUpdater.checkIfDue("0.5.13", now, recent, force = true, fetcher = fetcher)
    assertNotNull(forced)
    assertEquals("v0.5.14", forced!!.version)
    assertEquals(1, called)
  }

  @Test
  fun expectedApkSha256VerifiesSumsAndNotesDigest() {
    val apkSha = "c".repeat(64)
    val sumsContent = "$apkSha  tincstack-v0.5.14.apk\n"
    val sumsSha = AppUpdater.sha256Bytes(sumsContent.toByteArray(Charsets.UTF_8))
    val rel = AppUpdater.Release(
      tag = "v0.5.14",
      version = "v0.5.14",
      apkName = "tincstack-v0.5.14.apk",
      apkUrl = "https://x/tincstack-v0.5.14.apk",
      sumsUrl = "https://x/SHA256SUMS",
      notes = "## Checksums\n\nSHA256SUMS: $sumsSha\n",
    )
    val got = AppUpdater.expectedApkSha256(rel) { sumsContent.toByteArray(Charsets.UTF_8) }
    assertEquals(apkSha, got)
  }

  @Test(expected = IOException::class)
  fun expectedApkSha256RejectsTamperedSums() {
    val apkSha = "c".repeat(64)
    val sumsContent = "$apkSha  tincstack-v0.5.14.apk\n"
    val rel = AppUpdater.Release(
      tag = "v0.5.14",
      version = "v0.5.14",
      apkName = "tincstack-v0.5.14.apk",
      apkUrl = "https://x/tincstack-v0.5.14.apk",
      sumsUrl = "https://x/SHA256SUMS",
      notes = "SHA256SUMS: " + "d".repeat(64),
    )
    AppUpdater.expectedApkSha256(rel) { sumsContent.toByteArray(Charsets.UTF_8) }
  }
}
