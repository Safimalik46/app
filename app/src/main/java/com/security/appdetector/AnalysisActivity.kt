package com.security.appdetector

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.security.appdetector.ai.SecurityScanner
import com.security.appdetector.databinding.ActivityAnalysisBinding
import com.security.appdetector.util.AppScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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

        lifecycleScope.launch {
            // Get app info on a background thread
            val appInfo = withContext(Dispatchers.IO) {
                AppScanner.getAppInfo(this@AnalysisActivity, packageName!!)
            }

            if (appInfo != null) {
                // Update UI on the main thread
                binding.appIconLarge.setImageDrawable(appInfo.icon)
                binding.appNameText.text = appInfo.appName

                // Simulate analysis delay for better UX
                delay(2000)

                // Perform comprehensive security analysis (suspend function)
                val result = securityScanner.analyzeApp(appInfo)
                
                // Navigate to result screen on the main thread
                val intent = Intent(this@AnalysisActivity, ResultDetailActivity::class.java).apply {
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
            } else {
                finish()
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Clean up security scanner resources
        if (::securityScanner.isInitialized) {
            securityScanner.close()
        }
    }
}
