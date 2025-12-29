package com.security.appdetector.model

import android.graphics.drawable.Drawable

/**
 * Data class representing an installed Android application
 */
data class AppInfo(
    val packageName: String,
    val appName: String,
    val icon: Drawable,
    val permissions: List<String>,
    val dangerousPermissions: List<String>
) {
    val permissionCount: Int
        get() = permissions.size
    
    val dangerousPermissionCount: Int
        get() = dangerousPermissions.size
}

