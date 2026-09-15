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

package org.pacien.tincapp.activities.apps

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Filter
import android.widget.Filterable
import org.pacien.tincapp.databinding.AppsPickerItemBinding

data class InstalledApp(val packageName: String, val label: String, val system: Boolean)

/**
 * Installed apps with a checkbox each, filtered by label or package name.
 * Packages ticked in the config but not installed on this device are kept in
 * the selection (and shown at the top) so a config written on another device,
 * or for an app that is not installed yet, is not silently truncated.
 */
class InstalledAppsAdapter(private val context: Context) : BaseAdapter(), Filterable {
  private val inflater = LayoutInflater.from(context)
  private val packageManager: PackageManager = context.packageManager
  private val icons = HashMap<String, Drawable?>()

  private var all: List<InstalledApp> = emptyList()
  private var shown: List<InstalledApp> = emptyList()
  private val checked = LinkedHashSet<String>()
  private var query: String = ""

  fun setApps(apps: List<InstalledApp>, preselected: Set<String>) {
    val installed = apps.map { it.packageName }.toSet()
    val missing = preselected.filter { it !in installed }.sorted().map { InstalledApp(it, it, false) }
    all = missing + apps
    checked.clear()
    checked.addAll(preselected)
    applyFilter()
  }

  fun selected(): Set<String> = checked.toSet()

  fun toggle(position: Int) {
    val pkg = shown[position].packageName
    if (!checked.remove(pkg)) checked.add(pkg)
    notifyDataSetChanged()
  }

  override fun getCount() = shown.size
  override fun getItem(position: Int) = shown[position]
  override fun getItemId(position: Int) = position.toLong()
  override fun hasStableIds() = false

  override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
    val binding = convertView?.tag as? AppsPickerItemBinding
      ?: AppsPickerItemBinding.inflate(inflater, parent, false).also { it.root.tag = it }
    val app = shown[position]
    binding.appLabel.text = app.label
    binding.appPackage.text = app.packageName
    binding.appChecked.isChecked = app.packageName in checked
    binding.appIcon.setImageDrawable(iconOf(app.packageName))
    return binding.root
  }

  private fun iconOf(packageName: String): Drawable? = icons.getOrPut(packageName) {
    try {
      packageManager.getApplicationIcon(packageName)
    } catch (e: PackageManager.NameNotFoundException) {
      null
    }
  }

  private fun applyFilter() {
    val q = query.trim().lowercase()
    shown = if (q.isEmpty()) all
    else all.filter { it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q) }
    notifyDataSetChanged()
  }

  override fun getFilter(): Filter = object : Filter() {
    override fun performFiltering(constraint: CharSequence?) = FilterResults().apply { values = constraint?.toString() ?: "" }
    override fun publishResults(constraint: CharSequence?, results: FilterResults?) {
      query = results?.values as? String ?: ""
      applyFilter()
    }
  }
}
