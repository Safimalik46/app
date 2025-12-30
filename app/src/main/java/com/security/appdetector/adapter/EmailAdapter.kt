package com.security.appdetector.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import com.security.appdetector.databinding.ItemEmailBinding
import com.security.appdetector.model.EmailScanResult

/**
 * Adapter for displaying email scan results
 */
class EmailAdapter(
    private val emails: List<EmailScanResult>
) : RecyclerView.Adapter<EmailAdapter.EmailViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EmailViewHolder {
        val binding = ItemEmailBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return EmailViewHolder(binding)
    }

    override fun onBindViewHolder(holder: EmailViewHolder, position: Int) {
        holder.bind(emails[position])
    }

    override fun getItemCount(): Int = emails.size

    inner class EmailViewHolder(
        private val binding: ItemEmailBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(email: EmailScanResult) {
            binding.subjectText.text = email.subject
            binding.senderText.text = email.sender
            binding.previewText.text = email.preview
            
            if (email.isPhishing) {
                binding.phishingBadge.visibility = android.view.View.VISIBLE
                binding.phishingBadge.text = "⚠️ PHISHING"
                binding.phishingBadge.setBackgroundColor(android.graphics.Color.parseColor("#F44336"))
                binding.root.setBackgroundColor(android.graphics.Color.parseColor("#FFEBEE"))
                
                // Show reasons
                binding.reasonsText.text = "Reasons: ${email.phishingReasons.joinToString(", ")}"
                binding.reasonsText.visibility = android.view.View.VISIBLE
            } else {
                binding.phishingBadge.visibility = View.GONE
                binding.reasonsText.visibility = View.GONE
                binding.root.setBackgroundColor(android.graphics.Color.parseColor("#FFFFFF"))
            }
        }
    }
}

