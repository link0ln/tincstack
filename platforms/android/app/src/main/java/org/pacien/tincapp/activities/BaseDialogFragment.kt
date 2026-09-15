/*
 * Tinc Mesh VPN: Android client and user interface
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

package org.pacien.tincapp.activities

import android.content.Context
import androidx.fragment.app.DialogFragment
import android.view.LayoutInflater

/**
 * @author euxane
 */
abstract class BaseDialogFragment : DialogFragment() {
  protected val parentActivity by lazy { activity as BaseActivity }
  // getLayoutInflater() calls onCreateDialog. See https://stackoverflow.com/a/15152788
  protected val dialogLayoutInflater by lazy { requireActivity().getSystemService(Context.LAYOUT_INFLATER_SERVICE) as LayoutInflater }
}
