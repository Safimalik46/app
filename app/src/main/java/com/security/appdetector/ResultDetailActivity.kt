package com.security.appdetector

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.security.appdetector.adapter.PermissionListAdapter
import com.security.appdetector.databinding.ActivityResultDetailBinding
import com.security.appdetector.model.RiskLevel
import com.security.appdetector.util.AppScanner
import com.security.appdetector.util.PlayStoreVerifier

/**
 * Activity that displays detailed analysis results for an app
 */
class ResultDetailActivity : AppCompatActivity() {

    private lateinit var binding: ActivityResultDetailBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityResultDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupToolbar()
        displayResults()
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
    }

    private fun displayResults() {
        val packageName = intent.getStringExtra("package_name") ?: return
        val appName = intent.getStringExtra("app_name") ?: ""
        val riskLevelStr = intent.getStringExtra("risk_level") ?: RiskLevel.SAFE.name
        val dangerousPermissions = intent.getStringArrayListExtra("dangerous_permissions") ?: emptyList()
        val recommendation = intent.getStringExtra("recommendation") ?: ""

        // Get app icon
        val appInfo = AppScanner.getAppInfo(this, packageName)
        appInfo?.let {
            binding.appIconDetail.setImageDrawable(it.icon)
        }

        // Set app name and package with installation source
        binding.appNameDetail.text = appName
        val installationSource = PlayStoreVerifier.getInstallationSource(this, packageName)
        binding.packageNameDetail.text = "$packageName\nSource: $installationSource"

        // Set risk level with appropriate color
        val riskLevel = RiskLevel.valueOf(riskLevelStr)
        binding.riskLevelText.text = riskLevel.displayName
        
        // Update risk level background color
        val riskLevelBackground = binding.riskLevelText.background as? GradientDrawable
            ?: GradientDrawable().apply {
                cornerRadius = 8f
            }
        
        val riskColor = when (riskLevel) {
            RiskLevel.SAFE -> resources.getColor(com.security.appdetector.R.color.safe_green, theme)
            RiskLevel.RISKY -> resources.getColor(com.security.appdetector.R.color.risky_orange, theme)
            RiskLevel.MALWARE -> resources.getColor(com.security.appdetector.R.color.malware_red, theme)
        }
        
        riskLevelBackground.setColor(riskColor)
        binding.riskLevelText.background = riskLevelBackground

        // Set up permissions list
        if (dangerousPermissions.isNotEmpty()) {
            val adapter = PermissionListAdapter(dangerousPermissions)
            binding.permissionsRecyclerView.layoutManager = LinearLayoutManager(this)
            binding.permissionsRecyclerView.adapter = adapter
        } else {
            // Hide permissions card if no dangerous permissions
            binding.permissionsCard.visibility = android.view.View.GONE
        }

        // Set recommendation
        binding.recommendationText.text = recommendation
    }
}

