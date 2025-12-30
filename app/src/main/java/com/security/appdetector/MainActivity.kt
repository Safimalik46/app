package com.security.appdetector

import android.animation.ObjectAnimator
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.appcompat.app.AppCompatActivity
import com.security.appdetector.ai.SecurityScanner
import com.security.appdetector.databinding.ActivityMainBinding
import com.security.appdetector.util.AppScanner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Main/Home Screen Activity - Interactive with animations and statistics
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var securityScanner: SecurityScanner

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        securityScanner = SecurityScanner(this)
        setupClickListeners()
        setupAnimations()
        loadStatistics()
    }

    private fun setupClickListeners() {
        binding.scanButton.setOnClickListener {
            animateButtonClick(binding.scanButton) {
                val intent = Intent(this, AppScanActivity::class.java)
                startActivity(intent)
            }
        }

        binding.antivirusButton.setOnClickListener {
            animateButtonClick(binding.antivirusButton) {
                val intent = Intent(this, AntivirusActivity::class.java)
                startActivity(intent)
            }
        }
        
        binding.fileScanButton.setOnClickListener {
            animateButtonClick(binding.fileScanButton) {
                val intent = Intent(this, FileScanActivity::class.java)
                startActivity(intent)
            }
        }
        
        binding.gmailScanButton.setOnClickListener {
            animateButtonClick(binding.gmailScanButton) {
                val intent = Intent(this, GmailPhishingActivity::class.java)
                startActivity(intent)
            }
        }

        binding.chatbotButton.setOnClickListener {
            animateButtonClick(binding.chatbotButton) {
                val intent = Intent(this, ChatbotActivity::class.java)
                startActivity(intent)
            }
        }

        binding.settingsButton.setOnClickListener {
            animateButtonClick(binding.settingsButton) {
                val intent = Intent(this, SettingsActivity::class.java)
                startActivity(intent)
            }
        }
    }
    
    private fun setupAnimations() {
        // Fade in animation for header
        binding.headerCard.alpha = 0f
        binding.headerCard.animate()
            .alpha(1f)
            .setDuration(600)
            .setInterpolator(AccelerateDecelerateInterpolator())
            .start()
        
        // Scale animation for shield icon
        binding.shieldIconMain.scaleX = 0f
        binding.shieldIconMain.scaleY = 0f
        binding.shieldIconMain.animate()
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(500)
            .setStartDelay(200)
            .setInterpolator(AccelerateDecelerateInterpolator())
            .start()
        
        // Animate buttons from bottom
        val buttons = listOf(
            binding.scanButton,
            binding.antivirusButton,
            binding.fileScanButton,
            binding.gmailScanButton,
            binding.chatbotButton,
            binding.settingsButton
        )
        
        buttons.forEachIndexed { index, button ->
            button.translationY = 100f
            button.alpha = 0f
            button.animate()
                .translationY(0f)
                .alpha(1f)
                .setDuration(400)
                .setStartDelay((300 + (index * 50)).toLong())
                .setInterpolator(AccelerateDecelerateInterpolator())
                .start()
        }
    }
    
    private fun animateButtonClick(button: View, action: () -> Unit) {
        val scaleX = ObjectAnimator.ofFloat(button, "scaleX", 1f, 0.95f, 1f)
        val scaleY = ObjectAnimator.ofFloat(button, "scaleY", 1f, 0.95f, 1f)
        scaleX.duration = 150
        scaleY.duration = 150
        scaleX.start()
        scaleY.start()
        
        Handler(Looper.getMainLooper()).postDelayed({
            action()
        }, 100L)
    }
    
    private fun loadStatistics() {
        binding.statsLoading.visibility = View.VISIBLE
        
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val installedApps = AppScanner.scanInstalledApps(this@MainActivity)
                val totalApps = installedApps.size
                
                // Scan all apps for real-time statistics
                var safeCount = 0
                var riskyCount = 0
                var malwareCount = 0
                
                installedApps.forEach { appInfo ->
                    try {
                        val analysis = securityScanner.analyzeApp(appInfo)
                        when (analysis.riskLevel) {
                            com.security.appdetector.model.RiskLevel.SAFE -> safeCount++
                            com.security.appdetector.model.RiskLevel.RISKY -> riskyCount++
                            com.security.appdetector.model.RiskLevel.MALWARE -> malwareCount++
                        }
                    } catch (e: Exception) {
                        // Skip apps that can't be analyzed
                    }
                }
                
                runOnUiThread {
                    binding.totalAppsText.text = "$totalApps"
                    binding.safeAppsText.text = "$safeCount"
                    binding.riskyAppsText.text = "$riskyCount"
                    binding.malwareAppsText.text = "$malwareCount"
                    
                    // Animate numbers
                    animateNumber(binding.totalAppsText, totalApps)
                    binding.statsLoading.visibility = View.GONE
                    binding.statsCard.visibility = View.VISIBLE
                    
                    // Fade in stats
                    binding.statsCard.alpha = 0f
                    binding.statsCard.animate()
                        .alpha(1f)
                        .setDuration(500)
                        .start()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    binding.statsLoading.visibility = View.GONE
                }
            }
        }
    }
    
    private fun animateNumber(view: android.widget.TextView, target: Int) {
        // Simple animation - just set the text with a slight delay for visual effect
        view.text = "0"
        var current = 0
        val handler = Handler(Looper.getMainLooper())
        val runnable = object : Runnable {
            override fun run() {
                if (current < target) {
                    current += maxOf(1, target / 20)
                    if (current > target) current = target
                    view.text = current.toString()
                    handler.postDelayed(this, 30L)
                }
            }
        }
        handler.postDelayed(runnable, 100L)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::securityScanner.isInitialized) {
            securityScanner.close()
        }
    }
}

