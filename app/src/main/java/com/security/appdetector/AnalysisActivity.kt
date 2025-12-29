package com.security.appdetector

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import com.security.appdetector.ai.SecurityScanner
import com.security.appdetector.databinding.ActivityAnalysisBinding
import com.security.appdetector.model.AnalysisResult
import com.security.appdetector.util.AppScanner

/**
 * Activity that performs AI analysis on selected app
 * Shows loading animation and then navigates to result screen
 */
class AnalysisActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAnalysisBinding
    private lateinit var securityScanner: SecurityScanner
    private var packageName: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAnalysisBinding.inflate(layoutInflater)
        setContentView(binding.root)

        packageName = intent.getStringExtra("package_name")
        securityScanner = SecurityScanner(this)

        if (packageName != null) {
            loadAppInfoAndAnalyze()
        } else {
            finish()
        }
    }

    private fun loadAppInfoAndAnalyze() {
        // Show loading state
        binding.analysisStatusText.text = getString(R.string.analyzing)
        binding.analysisProgress.visibility = android.view.View.VISIBLE

        // Perform analysis in background thread
        Thread {
            val appInfo = AppScanner.getAppInfo(this, packageName!!)
            
            if (appInfo != null) {
                // Update UI with app info
                runOnUiThread {
                    binding.appIconLarge.setImageDrawable(appInfo.icon)
                    binding.appNameText.text = appInfo.appName
                }

                // Simulate analysis delay for better UX
                Handler(Looper.getMainLooper()).postDelayed({
                    // Perform comprehensive security analysis
                    val result = securityScanner.analyzeApp(appInfo)
                    
                    // Navigate to result screen
                    val intent = Intent(this, ResultDetailActivity::class.java).apply {
                        putExtra("package_name", result.appInfo.packageName)
                        putExtra("app_name", result.appInfo.appName)
                        putExtra("risk_level", result.riskLevel.name)
                        putStringArrayListExtra("dangerous_permissions", 
                            ArrayList(result.dangerousPermissions))
                        putExtra("recommendation", result.recommendation)
                        putExtra("confidence", result.confidence)
                    }
                    startActivity(intent)
                    finish()
                }, 2000) // 2 second delay for analysis animation
            } else {
                runOnUiThread {
                    finish()
                }
            }
        }.start()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Clean up security scanner resources
        if (::securityScanner.isInitialized) {
            securityScanner.close()
        }
    }
}

