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

package org.pacien.tincapp.data

/**
 * A tinc invitation, `<host>[:port]/<48 characters>` (core/tincd/src/invitation.c,
 * `invitation_url_parse`), found in whatever the user pasted, shared or scanned.
 *
 * People get invitations through messengers and mail: the string arrives with
 * leading/trailing blanks, a trailing newline, a sentence around it, quotes or
 * angle brackets, sometimes a `tinc://` or `http://` a linkifier added, and a
 * long token may be wrapped onto two lines. The core takes the string as is
 * (`argv`, no trimming), so everything is normalised here, once, before the
 * core ever sees it.
 */
data class Invitation(val host: String, val port: Int, val token: String) {
  /** The exact string handed to `tinc join`. */
  override fun toString(): String = "${hostForUrl()}:$port/$token"

  /** `host:port` for messages. */
  fun endpoint(): String = "${hostForUrl()}:$port"

  private fun hostForUrl() = if (host.contains(':')) "[$host]" else host

  companion object {
    const val DEFAULT_PORT = 655
    private const val TOKEN_CHARS = "A-Za-z0-9+/_\\-"
    private const val TOKEN_LENGTH = 48

    // host: a DNS name / IPv4 literal, or a bracketed IPv6 literal; optional port;
    // the 48-character token (tinc's base64, both alphabets), not followed by
    // another token character (a longer run is not an invitation). A host never
    // starts right after a colon: in "1.2.3.4:99999/..." the "99999" is a bad
    // port, not a host name.
    private val PATTERN = Regex(
      "(?<![A-Za-z0-9.:\\-\\[])" +
        "(\\[[0-9A-Fa-f:.]+]|[A-Za-z0-9](?:[A-Za-z0-9\\-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9\\-]*[A-Za-z0-9])?)*)" +
        "(?::([0-9]{1,5}))?" +
        "/([$TOKEN_CHARS]{$TOKEN_LENGTH})(?![$TOKEN_CHARS])")

    private val INVISIBLE = Regex("[\\u200B-\\u200D\\u2060\\uFEFF\\u00AD]")
    private val WHITESPACE = Regex("\\s+")

    /**
     * The invitation in [text], or null. Tried on the text as it is first (so a
     * sentence around the invitation does not matter), then with every blank
     * removed (a token a messenger wrapped onto two lines).
     */
    fun find(text: String?): Invitation? {
      if (text.isNullOrBlank()) return null
      val clean = INVISIBLE.replace(text, "")
      return match(clean) ?: match(WHITESPACE.replace(clean, ""))
    }

    /** Whether [text] contains an invitation. */
    fun looksLikeOne(text: String?) = find(text) != null

    private fun match(text: String): Invitation? {
      for (m in PATTERN.findAll(text)) {
        val host = m.groupValues[1].removePrefix("[").removeSuffix("]")
        val port = m.groupValues[2].takeIf { it.isNotEmpty() }?.toIntOrNull() ?: DEFAULT_PORT
        if (port !in 1..65535) continue
        // "http://host/..." : the scheme's letters are not a host
        if (host.isEmpty()) continue
        return Invitation(host, port, m.groupValues[3])
      }
      return null
    }
  }
}
