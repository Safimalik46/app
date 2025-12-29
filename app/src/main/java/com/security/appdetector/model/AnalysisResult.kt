package com.security.appdetector.model

/**
 * Data class representing the AI analysis result for an app
 */
data class AnalysisResult(
    val appInfo: AppInfo,
    val riskLevel: RiskLevel,
    val confidence: Float,
    val dangerousPermissions: List<String>,
    val recommendation: String
)

