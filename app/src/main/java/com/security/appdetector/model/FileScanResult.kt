package com.security.appdetector.model

/**
 * Data class for file scan results
 */
data class FileScanResult(
    val fileName: String,
    val filePath: String,
    val fileSize: Long,
    val fileExtension: String,
    val threatDetected: Boolean,
    val threatLevel: String,
    val scanDetails: String
)

