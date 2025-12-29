package com.security.appdetector.model

/**
 * Enum representing the risk level classification of an app
 */
enum class RiskLevel(val displayName: String, val colorRes: Int) {
    SAFE("Safe", android.R.color.holo_green_dark),
    RISKY("Risky", android.R.color.holo_orange_dark),
    MALWARE("Malware", android.R.color.holo_red_dark)
}

