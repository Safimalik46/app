package com.security.appdetector.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import com.security.appdetector.model.AppInfo

/**
 * Utility class to scan installed applications using PackageManager
 */
object AppScanner {
    
    // Dangerous permissions that indicate potential security risks
    private val DANGEROUS_PERMISSIONS = setOf(
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR"
    )

    /**
     * Scans and returns all installed applications
     */
    fun scanInstalledApps(context: Context): List<AppInfo> {
        val packageManager = context.packageManager
        val installedApps = mutableListOf<AppInfo>()
        
        try {
            // Get all installed packages
            val packages = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstalledPackages(0)
            }
            
            packages.forEach { packageInfo ->
                try {
                    // Skip system apps for cleaner list (optional - can be removed)
                    val appInfo = packageInfo.applicationInfo
                    if ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0 ||
                        (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                        
                        val appName = packageManager.getApplicationLabel(appInfo).toString()
                        val icon = packageManager.getApplicationIcon(appInfo)
                        
                        // Get permissions
                        val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
                        val dangerousPermissions = requestedPermissions.filter { 
                            DANGEROUS_PERMISSIONS.contains(it) 
                        }
                        
                        installedApps.add(
                            AppInfo(
                                packageName = packageInfo.packageName,
                                appName = appName,
                                icon = icon,
                                permissions = requestedPermissions,
                                dangerousPermissions = dangerousPermissions
                            )
                        )
                    }
                } catch (e: Exception) {
                    // Skip apps that can't be processed
                    e.printStackTrace()
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        // Sort alphabetically by app name
        return installedApps.sortedBy { it.appName }
    }
    
    /**
     * Gets app info for a specific package name
     */
    fun getAppInfo(context: Context, packageName: String): AppInfo? {
        return try {
            val packageManager = context.packageManager
            val packageInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, 0)
            }
            
            val appInfo = packageInfo.applicationInfo
            val appName = packageManager.getApplicationLabel(appInfo).toString()
            val icon = packageManager.getApplicationIcon(appInfo)
            
            val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
            val dangerousPermissions = requestedPermissions.filter { 
                DANGEROUS_PERMISSIONS.contains(it) 
            }
            
            AppInfo(
                packageName = packageName,
                appName = appName,
                icon = icon,
                permissions = requestedPermissions,
                dangerousPermissions = dangerousPermissions
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}

