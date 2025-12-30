package com.security.appdetector.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.security.appdetector.databinding.ItemFileScanBinding
import com.security.appdetector.model.FileScanResult
import java.text.SimpleDateFormat
import java.util.*

/**
 * Adapter for displaying file scan results
 */
class FileScanAdapter(
    private val files: List<FileScanResult>,
    private val onItemClick: (FileScanResult) -> Unit
) : RecyclerView.Adapter<FileScanAdapter.FileScanViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): FileScanViewHolder {
        val binding = ItemFileScanBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return FileScanViewHolder(binding)
    }

    override fun onBindViewHolder(holder: FileScanViewHolder, position: Int) {
        holder.bind(files[position])
    }

    override fun getItemCount(): Int = files.size

    inner class FileScanViewHolder(
        private val binding: ItemFileScanBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(fileResult: FileScanResult) {
            binding.fileNameText.text = fileResult.fileName
            binding.fileSizeText.text = formatFileSize(fileResult.fileSize)
            binding.threatLevelText.text = fileResult.threatLevel
            binding.scanDetailsText.text = fileResult.scanDetails
            
            // Set threat level color
            val threatColor = when (fileResult.threatLevel.uppercase()) {
                "MALWARE DETECTED", "SUSPICIOUS" -> android.graphics.Color.parseColor("#F44336")
                "CLEAN", "SAFE" -> android.graphics.Color.parseColor("#4CAF50")
                else -> android.graphics.Color.parseColor("#FF9800")
            }
            binding.threatLevelText.setTextColor(threatColor)
            
            binding.root.setOnClickListener {
                onItemClick(fileResult)
            }
        }
        
        private fun formatFileSize(bytes: Long): String {
            val kb = bytes / 1024.0
            val mb = kb / 1024.0
            return when {
                mb >= 1 -> String.format("%.2f MB", mb)
                kb >= 1 -> String.format("%.2f KB", kb)
                else -> "$bytes B"
            }
        }
    }
}

