package com.security.appdetector.model

/**
 * Data class for email scan results
 */
data class EmailScanResult(
    val id: String,
    val sender: String,
    val subject: String,
    val preview: String,
    val date: Long,
    val isPhishing: Boolean,
    val threatLevel: String,
    val phishingReasons: List<String> = emptyList()
)
