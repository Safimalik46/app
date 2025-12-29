package com.security.appdetector.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.security.appdetector.databinding.ItemPermissionBinding

/**
 * Adapter for displaying dangerous permissions list
 */
class PermissionListAdapter(
    private val permissions: List<String>
) : RecyclerView.Adapter<PermissionListAdapter.PermissionViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PermissionViewHolder {
        val binding = ItemPermissionBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return PermissionViewHolder(binding)
    }

    override fun onBindViewHolder(holder: PermissionViewHolder, position: Int) {
        holder.bind(permissions[position])
    }

    override fun getItemCount(): Int = permissions.size

    inner class PermissionViewHolder(
        private val binding: ItemPermissionBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(permission: String) {
            // Format permission name for display (remove android.permission. prefix)
            val displayName = permission
                .removePrefix("android.permission.")
                .replace("_", " ")
                .lowercase()
                .split(" ")
                .joinToString(" ") { it.replaceFirstChar { char -> char.uppercase() } }
            
            binding.permissionName.text = displayName
        }
    }
}

