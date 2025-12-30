package com.security.appdetector.model

/**
 * Data class for email scan results
 */
data class EmailScanResult(
    val subject: String,
    val sender: String,
    val preview: String,
    val isPhishing: Boolean,
    val phishingReasons: List<String> = emptyList()
)

