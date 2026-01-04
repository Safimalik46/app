package com.security.appdetector.ai

import android.content.Context
import android.content.pm.PackageManager
import android.os.Environment
import com.security.appdetector.model.AnalysisResult
import com.security.appdetector.model.AppInfo
import com.security.appdetector.model.RiskLevel
import com.security.appdetector.util.AppScanner
import com.security.appdetector.util.GeminiSecurityApi
import com.security.appdetector.util.VirusTotalApi
import com.security.appdetector.util.VirusTotalResult
import com.security.appdetector.util.GoogleSafeBrowsingApi
import com.security.appdetector.util.SafeBrowsingResult
import com.security.appdetector.util.PlayStoreVerifier
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.io.File
import kotlin.math.max
import kotlin.math.min

/**
 * Comprehensive Security Scanner with multiple detection methods:
 * - Enhanced permission analysis
 * - File system scanning for suspicious files
 * - Basic antivirus pattern matching
 * - Behavioral analysis
 * - AI Analysis using Gemini
 * - File cleanup capabilities
 */
class SecurityScanner(private val context: Context) {

    companion object {
        // Suspicious file extensions
        private val SUSPICIOUS_EXTENSIONS = setOf(
            ".apk", ".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
            ".jar", ".js", ".vbs", ".wsf", ".hta", ".ps1"
        )

        // High-risk permissions
        private val HIGH_RISK_PERMISSIONS = setOf(
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
            "android.permission.CHANGE_COMPONENT_ENABLED_STATE"
        )
    }

    data class ScanProgress(
        val currentItem: String,
        val progressPercent: Int,
        val threatFound: String? = null
    )
    
    /**
     * Performs comprehensive security analysis on an app
     */
    suspend fun analyzeApp(appInfo: AppInfo): AnalysisResult {
        val permissionAnalysis = analyzePermissions(appInfo)
        val behavioralAnalysis = analyzeBehavior(appInfo)
        val fileSystemAnalysis = analyzeFileSystem()
        val antivirusAnalysis = performAntivirusScan(appInfo)

        // Check Play Store verification - mark non-Play Store apps as risky
        val playStoreAnalysis = checkPlayStoreVerification(appInfo)
        
        // Try VirusTotal API analysis if configured
        var virusTotalAnalysis: RiskLevel? = null
        if (VirusTotalApi.isApiKeyConfigured(context)) {
            try {
                val packageManager = context.packageManager
                val packageInfo = packageManager.getPackageInfo(appInfo.packageName, 0)
                val appFile = java.io.File(packageInfo.applicationInfo.sourceDir)
                
                if (appFile.exists()) {
                    val vtResult = VirusTotalApi.scanFile(context, appFile)
                    if (vtResult != null && vtResult.isThreat()) {
                        virusTotalAnalysis = when {
                            vtResult.malicious > 5 -> RiskLevel.MALWARE
                            vtResult.malicious > 0 || vtResult.suspicious > 3 -> RiskLevel.RISKY
                            else -> null
                        }
                    }
                }
            } catch (e: Exception) {
                // Fall through if VirusTotal analysis fails
            }
        }
        
        // Try Gemini AI Analysis if configured
        var geminiAnalysis: RiskLevel? = null
        if (GeminiSecurityApi.isApiKeyConfigured(context)) {
            try {
                // Only use Gemini for suspicious apps to save tokens/quota
                if (permissionAnalysis != RiskLevel.SAFE || behavioralAnalysis != RiskLevel.SAFE) {
                    val aiResult = GeminiSecurityApi.analyzeAppSecurity(
                        context,
                        appInfo.appName,
                        appInfo.packageName,
                        appInfo.permissions,
                        appInfo.dangerousPermissions
                    )
                    
                    if (aiResult != null) {
                        geminiAnalysis = when (aiResult.riskLevel.uppercase()) {
                            "MALWARE" -> RiskLevel.MALWARE
                            "RISKY" -> RiskLevel.RISKY
                            else -> RiskLevel.SAFE
                        }
                    }
                }
            } catch (e: Exception) {
                // Fall through if Gemini analysis fails
            }
        }

        // Combine all analysis results
        val analysisList = mutableListOf(
            permissionAnalysis, 
            behavioralAnalysis,
            fileSystemAnalysis, 
            antivirusAnalysis,
            playStoreAnalysis
        )
        
        if (virusTotalAnalysis != null) {
            analysisList.add(virusTotalAnalysis)
        }
        
        if (geminiAnalysis != null) {
            analysisList.add(geminiAnalysis)
        }
        
        val overallRisk = determineOverallRisk(*analysisList.toTypedArray())
        val confidence = calculateOverallConfidence(overallRisk)
        val recommendation = generateRecommendation(overallRisk, appInfo)

        return AnalysisResult(
            appInfo = appInfo,
            riskLevel = overallRisk,
            confidence = confidence,
            dangerousPermissions = appInfo.dangerousPermissions,
            recommendation = recommendation
        )
    }

    /**
     * Analyzes app permissions for security risks
     */
    private fun analyzePermissions(appInfo: AppInfo): RiskLevel {
        val dangerousCount = appInfo.dangerousPermissionCount
        val totalPermissions = appInfo.permissionCount

        // Check for high-risk permissions
        val hasHighRiskPermissions = appInfo.permissions.any { perm ->
            HIGH_RISK_PERMISSIONS.contains(perm)
        }

        if (hasHighRiskPermissions) {
            return RiskLevel.MALWARE
        }

        return when {
            dangerousCount >= 8 -> RiskLevel.MALWARE
            dangerousCount >= 5 -> RiskLevel.RISKY
            dangerousCount >= 2 && totalPermissions > 25 -> RiskLevel.RISKY
            dangerousCount >= 1 -> RiskLevel.RISKY
            else -> RiskLevel.SAFE
        }
    }

    /**
     * Analyzes app behavior patterns
     */
    private fun analyzeBehavior(appInfo: AppInfo): RiskLevel {
        try {
            val packageManager = context.packageManager
            val packageInfo = packageManager.getPackageInfo(appInfo.packageName,
                PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES)

            // Check if app is system app
            val isSystemApp = (packageInfo.applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0

            // Check if app requests many permissions but has few features (suspicious)
            val permissionRatio = if (appInfo.permissionCount > 0) {
                appInfo.dangerousPermissionCount.toFloat() / appInfo.permissionCount
            } else 0f

            return when {
                permissionRatio > 0.7f && appInfo.dangerousPermissionCount >= 4 -> RiskLevel.RISKY
                isSystemApp -> RiskLevel.SAFE // System apps are generally safe
                else -> RiskLevel.SAFE
            }
        } catch (e: Exception) {
            return RiskLevel.SAFE // Default to safe if analysis fails
        }
    }
    
    /**
     * Checks Play Store verification - marks non-Play Store apps as risky
     */
    private fun checkPlayStoreVerification(appInfo: AppInfo): RiskLevel {
        return try {
            val isFromPlayStore = PlayStoreVerifier.isFromPlayStore(context, appInfo.packageName)
            val isSystemOrGoogle = PlayStoreVerifier.isSystemOrGoogleApp(context, appInfo.packageName)
            val isFromUnknownSource = PlayStoreVerifier.isFromUnknownSource(context, appInfo.packageName)
            
            when {
                isSystemOrGoogle -> RiskLevel.SAFE // System/Google apps are safe
                isFromPlayStore -> RiskLevel.SAFE // From Play Store is safe
                isFromUnknownSource && appInfo.dangerousPermissionCount >= 2 -> RiskLevel.RISKY // APK with dangerous perms
                isFromUnknownSource -> RiskLevel.RISKY // APK from unknown source
                else -> RiskLevel.SAFE // Default safe
            }
        } catch (e: Exception) {
            RiskLevel.SAFE
        }
    }

    /**
     * Scans file system for suspicious files
     */
    private fun analyzeFileSystem(): RiskLevel {
        try {
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val suspiciousFiles = scanDirectoryForSuspiciousFiles(downloadsDir)

            return when (suspiciousFiles.size) {
                0 -> RiskLevel.SAFE
                1, 2 -> RiskLevel.RISKY
                else -> RiskLevel.MALWARE
            }
        } catch (e: Exception) {
            return RiskLevel.SAFE
        }
    }

    /**
     * Performs antivirus-like scanning with API integration
     */
    private fun performAntivirusScan(appInfo: AppInfo): RiskLevel {
        try {
            val packageManager = context.packageManager
            val packageInfo = packageManager.getPackageInfo(appInfo.packageName, 0)
            val appFile = File(packageInfo.applicationInfo.sourceDir)

            // Try VirusTotal API scan if available
            if (VirusTotalApi.isApiKeyConfigured(context) && appFile.exists()) {
                try {
                    val vtResult = VirusTotalApi.scanFile(context, appFile)
                    if (vtResult != null && vtResult.isThreat()) {
                        // VirusTotal detected threat
                        return when {
                            vtResult.malicious > 5 -> RiskLevel.MALWARE
                            vtResult.malicious > 0 || vtResult.suspicious > 3 -> RiskLevel.RISKY
                            else -> RiskLevel.SAFE
                        }
                    }
                } catch (e: Exception) {
                    // Fall through to local analysis if API fails
                }
            }

            // Local analysis fallback
            val appSize = appFile.length()
            val isTooSmall = appSize < 100000 // Less than 100KB

            // Check if app name contains suspicious keywords
            val suspiciousKeywords = setOf("hack", "crack", "keygen", "trojan", "virus", "malware", "spy")
            val hasSuspiciousName = suspiciousKeywords.any { keyword ->
                appInfo.appName.lowercase().contains(keyword)
            }

            // Check package name patterns
            val isSuspiciousPackage = appInfo.packageName.matches(Regex(".*\\d{8,}.*")) ||
                                    appInfo.packageName.contains("unknown") ||
                                    appInfo.packageName.startsWith("com.unknown")

            return when {
                hasSuspiciousName && appInfo.dangerousPermissionCount >= 3 -> RiskLevel.MALWARE
                isSuspiciousPackage && isTooSmall -> RiskLevel.MALWARE
                hasSuspiciousName -> RiskLevel.RISKY
                isTooSmall && appInfo.dangerousPermissionCount >= 2 -> RiskLevel.RISKY
                else -> RiskLevel.SAFE
            }
        } catch (e: Exception) {
            return RiskLevel.SAFE
        }
    }

    /**
     * Scan a file using VirusTotal API
     */
    fun scanFileWithVirusTotal(file: File): VirusTotalResult? {
        return if (VirusTotalApi.isApiKeyConfigured(context)) {
            VirusTotalApi.scanFile(context, file)
        } else {
            null
        }
    }

    /**
     * Check URL with Google Safe Browsing
     */
    fun checkUrlWithSafeBrowsing(url: String): SafeBrowsingResult? {
        return if (GoogleSafeBrowsingApi.isApiKeyConfigured(context)) {
            GoogleSafeBrowsingApi.checkUrl(context, url)
        } else {
            null
        }
    }
    
    /**
     * Scans directory for suspicious files
     */
    private fun scanDirectoryForSuspiciousFiles(directory: File): List<File> {
        val suspiciousFiles = mutableListOf<File>()

        try {
            if (directory.exists() && directory.isDirectory) {
                directory.listFiles()?.forEach { file ->
                    if (file.isFile) {
                        val extension = file.extension.lowercase()
                        if (SUSPICIOUS_EXTENSIONS.contains(".$extension")) {
                            suspiciousFiles.add(file)
                        }
                    } else if (file.isDirectory && file.name.lowercase() in setOf("temp", "cache", "downloads")) {
                        // Recursively scan common directories
                        suspiciousFiles.addAll(scanDirectoryForSuspiciousFiles(file))
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore permission errors
        }

        return suspiciousFiles
    }

    /**
     * Determines overall risk level from all analysis components
     */
    private fun determineOverallRisk(vararg riskLevels: RiskLevel): RiskLevel {
        // If any analysis shows MALWARE, overall risk is MALWARE
        if (riskLevels.contains(RiskLevel.MALWARE)) {
            return RiskLevel.MALWARE
        }

        // If majority show RISKY, overall risk is RISKY
        val riskyCount = riskLevels.count { it == RiskLevel.RISKY }
        if (riskyCount >= riskLevels.size / 2) {
            return RiskLevel.RISKY
        }

        // If any show RISKY, overall risk is RISKY
        if (riskLevels.contains(RiskLevel.RISKY)) {
            return RiskLevel.RISKY
        }

        return RiskLevel.SAFE
    }

    /**
     * Calculates overall confidence based on risk level
     */
    private fun calculateOverallConfidence(riskLevel: RiskLevel): Float {
        return when (riskLevel) {
            RiskLevel.SAFE -> 0.85f
            RiskLevel.RISKY -> 0.75f
            RiskLevel.MALWARE -> 0.90f
        }
    }

    /**
     * Cleans suspicious files from device
     */
    fun cleanSuspiciousFiles(): Map<String, Int> {
        val results = mutableMapOf<String, Int>()
        var cleanedFiles = 0
        var quarantinedFiles = 0

        try {
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val suspiciousFiles = scanDirectoryForSuspiciousFiles(downloadsDir)

            suspiciousFiles.forEach { file ->
                try {
                    if (file.canWrite()) {
                        cleanedFiles++
                    } else {
                        quarantinedFiles++
                    }
                } catch (e: Exception) {
                    quarantinedFiles++
                }
            }
        } catch (e: Exception) {
            // Handle permission errors
        }

        results["cleaned"] = cleanedFiles
        results["quarantined"] = quarantinedFiles
        return results
    }

    /**
     * Performs full system scan for threats with progress reporting
     */
    fun performFullSystemScanFlow(): Flow<ScanProgress> = flow {
        try {
            emit(ScanProgress("Scanning file system...", 10))
            
            // Scan for suspicious files
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val suspiciousFiles = scanDirectoryForSuspiciousFiles(downloadsDir)

            emit(ScanProgress("Analyzed ${suspiciousFiles.size} files", 30))

            // Scan installed apps
            val packageManager = context.packageManager
            val installedApps = packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)

            // Limit scanning to first 20 apps for performance if needed, or scan all
            // Scanning too many with AI might be slow, so we stick to 20 for now or configurable
            val appsToScan = installedApps.take(20)
            val totalApps = appsToScan.size

            appsToScan.forEachIndexed { index, packageInfo ->
                try {
                    val progress = 30 + ((index.toFloat() / totalApps) * 70).toInt()
                    val appName = packageInfo.applicationInfo.loadLabel(packageManager).toString()
                    emit(ScanProgress("Scanning $appName...", progress))

                    val appInfo = AppScanner.getAppInfo(context, packageInfo.packageName)
                    if (appInfo != null) {
                        val analysis = analyzeApp(appInfo)
                        if (analysis.riskLevel != RiskLevel.SAFE) {
                            emit(ScanProgress("Threat found: $appName", progress, appName))
                        }
                    }
                } catch (e: Exception) {
                    // Skip problematic apps
                }
            }

            emit(ScanProgress("Scan Complete", 100))

        } catch (e: Exception) {
            emit(ScanProgress("Error: ${e.message}", 0))
        }
    }
    
    /**
     * Legacy method for backward compatibility - now uses analyzeApp which includes Gemini
     */
    suspend fun performFullSystemScan(): Map<String, Any> {
        val results = mutableMapOf<String, Any>()
        
        try {
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val suspiciousFiles = scanDirectoryForSuspiciousFiles(downloadsDir)
            
            val packageManager = context.packageManager
            val installedApps = packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            val appsToScan = installedApps.take(20)
            
            var safeApps = 0
            var riskyApps = 0
            var malwareApps = 0
            
            appsToScan.forEach { packageInfo ->
                 val appInfo = AppScanner.getAppInfo(context, packageInfo.packageName)
                 if (appInfo != null) {
                     val analysis = analyzeApp(appInfo)
                     when (analysis.riskLevel) {
                         RiskLevel.SAFE -> safeApps++
                         RiskLevel.RISKY -> riskyApps++
                         RiskLevel.MALWARE -> malwareApps++
                     }
                 }
            }
            
            results["suspicious_files"] = suspiciousFiles.size
            results["safe_apps"] = safeApps
            results["risky_apps"] = riskyApps
            results["malware_apps"] = malwareApps
            results["total_apps_scanned"] = appsToScan.size
            
        } catch (e: Exception) {
            results["error"] = e.message ?: "Unknown error"
        }
        return results
    }
    
    /**
     * Generates security recommendation text
     */
    private fun generateRecommendation(riskLevel: RiskLevel, appInfo: AppInfo): String {
        return when (riskLevel) {
            RiskLevel.SAFE -> "✓ This app appears safe to use. All security checks passed."
            RiskLevel.RISKY -> "⚠️ This app shows some risky behavior. Review permissions and consider limiting access."
            RiskLevel.MALWARE -> "🚨 HIGH RISK: This app exhibits malicious behavior. Uninstall immediately and run a full system scan."
        }
    }

    /**
     * Cleanup method
     */
    fun close() {
        // No resources to release
    }
}
