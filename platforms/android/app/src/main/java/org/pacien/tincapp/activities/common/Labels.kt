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

package org.pacien.tincapp.activities.common

import android.content.Context
import org.pacien.tincapp.R
import org.pacien.tincapp.data.Transport

/** User-facing names of core concepts. */
object Labels {
  fun transportName(t: Transport): Int = when (t) {
    Transport.PLAIN -> R.string.transport_plain
    Transport.SF -> R.string.transport_sf
    Transport.OBFS -> R.string.transport_obfs
    Transport.HTTPS -> R.string.transport_https
    Transport.QUIC -> R.string.transport_quic
  }

  fun transportDescription(t: Transport): Int = when (t) {
    Transport.PLAIN -> R.string.transport_plain_desc
    Transport.SF -> R.string.transport_sf_desc
    Transport.OBFS -> R.string.transport_obfs_desc
    Transport.HTTPS -> R.string.transport_https_desc
    Transport.QUIC -> R.string.transport_quic_desc
  }

  /** The name of a carrier as `tinc dump connections` prints it, or null if unknown. */
  fun transportName(context: Context, id: String?): String? =
    Transport.byId(id)?.let { context.getString(transportName(it)) }
}
