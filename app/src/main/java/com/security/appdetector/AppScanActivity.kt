package com.security.appdetector

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.security.appdetector.adapter.AppListAdapter
import com.security.appdetector.databinding.ActivityAppScanBinding
import com.security.appdetector.model.AppInfo
import com.security.appdetector.util.AppScanner

/**
 * Activity that displays list of installed apps for scanning
 */
class AppScanActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAppScanBinding
    private lateinit var appListAdapter: AppListAdapter
    private var installedApps: List<AppInfo> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAppScanBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupToolbar()
        setupRecyclerView()
        loadInstalledApps()
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
    }

    private fun setupRecyclerView() {
        appListAdapter = AppListAdapter(installedApps) { app ->
            // Navigate to analysis screen
            val intent = Intent(this, AnalysisActivity::class.java).apply {
                putExtra("package_name", app.packageName)
            }
            startActivity(intent)
        }

        binding.appsRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@AppScanActivity)
            adapter = appListAdapter
        }
    }

    private fun loadInstalledApps() {
        // Show loading state
        binding.emptyStateText.visibility = android.view.View.GONE
        
        // Load apps in background thread
        Thread {
            installedApps = AppScanner.scanInstalledApps(this)
            
            runOnUiThread {
                if (installedApps.isEmpty()) {
                    binding.emptyStateText.visibility = android.view.View.VISIBLE
                } else {
                    binding.emptyStateText.visibility = android.view.View.GONE
                    appListAdapter = AppListAdapter(installedApps) { app ->
                        val intent = Intent(this@AppScanActivity, AnalysisActivity::class.java).apply {
                            putExtra("package_name", app.packageName)
                        }
                        startActivity(intent)
                    }
                    binding.appsRecyclerView.adapter = appListAdapter
                }
            }
        }.start()
    }
}

