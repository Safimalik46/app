package com.security.appdetector.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.security.appdetector.databinding.ItemAppBinding
import com.security.appdetector.model.AppInfo

/**
 * Adapter for displaying list of installed apps
 */
class AppListAdapter(
    private val apps: List<AppInfo>,
    private val onAnalyzeClick: (AppInfo) -> Unit
) : RecyclerView.Adapter<AppListAdapter.AppViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        val binding = ItemAppBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return AppViewHolder(binding)
    }

    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        holder.bind(apps[position])
    }

    override fun getItemCount(): Int = apps.size

    inner class AppViewHolder(
        private val binding: ItemAppBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(app: AppInfo) {
            binding.appIcon.setImageDrawable(app.icon)
            binding.appName.text = app.appName
            binding.packageName.text = app.packageName
            binding.permissionsCount.text = "${app.permissionCount} permissions"
            
            binding.analyzeButton.setOnClickListener {
                onAnalyzeClick(app)
            }
        }
    }
}

