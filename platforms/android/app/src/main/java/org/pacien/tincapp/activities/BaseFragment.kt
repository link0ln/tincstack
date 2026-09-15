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

import android.content.ActivityNotFoundException
import androidx.fragment.app.Fragment
import org.pacien.tincapp.R
import org.pacien.tincapp.storageprovider.BrowseFilesIntents

/**
 * @author euxane
 */
abstract class BaseFragment : Fragment() {
  protected val parentActivity by lazy { activity as BaseActivity }

  fun openDocumentTree(documentId: String) {
    try {
      BrowseFilesIntents.openDocumentTree(requireContext(), documentId)
    } catch (e: ActivityNotFoundException) {
      parentActivity.runOnUiThread {
        parentActivity.showErrorDialog(
          R.string.configure_browse_directories_error_no_file_manager,
          docTopic = "troubleshooting.html#no-file-manager-found",
        )
      }
    }
  }
}
