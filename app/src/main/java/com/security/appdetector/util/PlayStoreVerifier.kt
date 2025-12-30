package com.security.appdetector.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.util.Log

/**
 * Utility to check if an app is from Google Play Store
 * Marks APKs and non-Play Store apps as potentially risky
 */
object PlayStoreVerifier {
    
    private const val PLAY_STORE_PACKAGE = "com.android.vending"
    private const val GOOGLE_PACKAGE_PREFIX = "com.google."
    private const val PLAY_STORE_INSTALLER = "com.android.vending"
    
    /**
     * Checks if an app is installed from Google Play Store
     */
    fun isFromPlayStore(context: Context, packageName: String): Boolean {
        return try {
            val packageManager = context.packageManager
            val installerPackageName = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
            }
            
            installerPackageName == PLAY_STORE_INSTALLER || 
            installerPackageName == PLAY_STORE_PACKAGE
        } catch (e: Exception) {
            Log.e("PlayStoreVerifier", "Error checking Play Store: ${e.message}")
            false
        }
    }
    
    /**
     * Checks if app is a system app or Google app
     */
    fun isSystemOrGoogleApp(context: Context, packageName: String): Boolean {
        return try {
            val packageManager = context.packageManager
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            
            val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isGoogleApp = packageName.startsWith(GOOGLE_PACKAGE_PREFIX)
            
            isSystemApp || isGoogleApp
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Determines if app is from unknown source (APK installation)
     */
    fun isFromUnknownSource(context: Context, packageName: String): Boolean {
        return try {
            val packageManager = context.packageManager
            val installerPackageName = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
            }
            
            // If installer is null or not Play Store, it's from unknown source
            installerPackageName.isNullOrEmpty() || 
            (installerPackageName != PLAY_STORE_INSTALLER && installerPackageName != PLAY_STORE_PACKAGE)
        } catch (e: Exception) {
            true // Assume unknown if we can't check
        }
    }
    
    /**
     * Get installation source info
     */
    fun getInstallationSource(context: Context, packageName: String): String {
        return try {
            val packageManager = context.packageManager
            val installerPackageName = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
            }
            
            when {
                installerPackageName == null || installerPackageName.isEmpty() -> "Unknown/APK"
                installerPackageName == PLAY_STORE_INSTALLER -> "Google Play Store"
                installerPackageName.contains("amazon") -> "Amazon Appstore"
                installerPackageName.contains("samsung") -> "Samsung Galaxy Store"
                else -> "Third-party ($installerPackageName)"
            }
        } catch (e: Exception) {
            "Unknown"
        }
    }
}

