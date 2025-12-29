package com.security.appdetector

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import com.security.appdetector.ai.SecurityScanner
import com.security.appdetector.databinding.ActivityAntivirusBinding
import com.security.appdetector.util.VirusTotalApi
import com.security.appdetector.util.GoogleSafeBrowsingApi
import com.security.appdetector.util.OpenAISecurityApi

/**
 * Activity for performing antivirus scanning
 */
class AntivirusActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAntivirusBinding
    private lateinit var securityScanner: SecurityScanner

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAntivirusBinding.inflate(layoutInflater)
        setContentView(binding.root)

        securityScanner = SecurityScanner(this)

        binding.startScanButton.setOnClickListener {
            performFullScan()
        }

        binding.backButton.setOnClickListener {
            finish()
        }
    }

    private fun performFullScan() {
        // Check API status
        val vtEnabled = VirusTotalApi.isApiKeyConfigured(this)
        val sbEnabled = GoogleSafeBrowsingApi.isApiKeyConfigured(this)
        val aiEnabled = OpenAISecurityApi.isApiKeyConfigured(this)
        
        val apiStatus = when {
            vtEnabled && sbEnabled && aiEnabled -> "🔍 Scanning with VirusTotal, Safe Browsing & AI APIs..."
            vtEnabled && aiEnabled -> "🔍 Scanning with VirusTotal & AI APIs..."
            vtEnabled && sbEnabled -> "🔍 Scanning with VirusTotal & Safe Browsing APIs..."
            vtEnabled -> "🔍 Scanning with VirusTotal API..."
            sbEnabled -> "🔍 Scanning with Safe Browsing API..."
            aiEnabled -> "🔍 Scanning with AI Security API..."
            else -> "🔍 Scanning system (Local analysis only - Configure APIs in Settings for enhanced detection)..."
        }
        
        // Show scanning state
        binding.scanStatusText.text = apiStatus
        binding.scanProgress.visibility = android.view.View.VISIBLE
        binding.startScanButton.isEnabled = false
        binding.scanResultsLayout.visibility = android.view.View.GONE

        // Perform scan in background
        Thread {
            val scanResults = securityScanner.performFullSystemScan()

            runOnUiThread {
                displayScanResults(scanResults, vtEnabled || sbEnabled)
                binding.scanProgress.visibility = android.view.View.GONE
                binding.startScanButton.isEnabled = true
            }
        }.start()
    }

    private fun displayScanResults(results: Map<String, Any>, apiEnabled: Boolean) {
        binding.scanResultsLayout.visibility = android.view.View.VISIBLE
        
        val statusText = if (apiEnabled) {
            "✅ Scan Complete (API Enhanced)"
        } else {
            "✅ Scan Complete (Local Only)"
        }
        binding.scanStatusText.text = statusText

        // Check for errors
        if (results.containsKey("error")) {
            val error = results["error"] as? String
            binding.overallStatusText.text = "❌ Error: $error"
            binding.overallStatusText.setTextColor(android.graphics.Color.RED)
            return
        }

        // Display results
        val suspiciousFiles = results["suspicious_files"] as? Int ?: 0
        val safeApps = results["safe_apps"] as? Int ?: 0
        val riskyApps = results["risky_apps"] as? Int ?: 0
        val malwareApps = results["malware_apps"] as? Int ?: 0
        val totalApps = results["total_apps_scanned"] as? Int ?: 0

        binding.suspiciousFilesCount.text = suspiciousFiles.toString()
        binding.safeAppsCount.text = safeApps.toString()
        binding.riskyAppsCount.text = riskyApps.toString()
        binding.malwareAppsCount.text = malwareApps.toString()
        binding.totalAppsScanned.text = totalApps.toString()

        // Set result colors and status
        val resultStatusText = when {
            malwareApps > 0 -> "🚨 Threats Found!"
            riskyApps > 0 -> "⚠️ Potential Risks"
            suspiciousFiles > 0 -> "⚠️ Suspicious Files"
            else -> "✅ System Secure"
        }

        binding.overallStatusText.text = resultStatusText
        binding.overallStatusText.setTextColor(
            when {
                malwareApps > 0 -> android.graphics.Color.RED
                riskyApps > 0 || suspiciousFiles > 0 -> android.graphics.Color.YELLOW
                else -> android.graphics.Color.GREEN
            }
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        securityScanner.close()
    }
}
