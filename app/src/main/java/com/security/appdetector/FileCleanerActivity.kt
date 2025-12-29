package com.security.appdetector

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Environment
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.security.appdetector.ai.SecurityScanner
import com.security.appdetector.databinding.ActivityFileCleanerBinding
import com.security.appdetector.util.VirusTotalApi
import com.security.appdetector.util.VirusTotalResult
import java.io.File

/**
 * Activity for cleaning suspicious files from device
 */
class FileCleanerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityFileCleanerBinding
    private lateinit var securityScanner: SecurityScanner
    private val STORAGE_PERMISSION_REQUEST = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileCleanerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        securityScanner = SecurityScanner(this)

        binding.scanFilesButton.setOnClickListener {
            if (checkStoragePermission()) {
                scanForSuspiciousFiles()
            } else {
                requestStoragePermission()
            }
        }

        binding.cleanFilesButton.setOnClickListener {
            if (checkStoragePermission()) {
                cleanSuspiciousFiles()
            } else {
                requestStoragePermission()
            }
        }

        binding.backButton.setOnClickListener {
            finish()
        }

        // Initial scan if permission granted
        if (checkStoragePermission()) {
            scanForSuspiciousFiles()
        }
    }

    private fun checkStoragePermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this, Manifest.permission.READ_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED &&
               ContextCompat.checkSelfPermission(
                   this, Manifest.permission.WRITE_EXTERNAL_STORAGE
               ) == PackageManager.PERMISSION_GRANTED
    }

    private fun requestStoragePermission() {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            ),
            STORAGE_PERMISSION_REQUEST
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == STORAGE_PERMISSION_REQUEST) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                scanForSuspiciousFiles()
            } else {
                Toast.makeText(this, "Storage permission required for file scanning", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun scanForSuspiciousFiles() {
        binding.scanProgress.visibility = android.view.View.VISIBLE
        binding.scanFilesButton.isEnabled = false

        Thread {
            try {
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val suspiciousFiles = scanDirectoryForSuspiciousFiles(downloadsDir)

                runOnUiThread {
                    displayScanResults(suspiciousFiles)
                    binding.scanProgress.visibility = android.view.View.GONE
                    binding.scanFilesButton.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Error scanning files: ${e.message}", Toast.LENGTH_SHORT).show()
                    binding.scanProgress.visibility = android.view.View.GONE
                    binding.scanFilesButton.isEnabled = true
                }
            }
        }.start()
    }

    private fun scanDirectoryForSuspiciousFiles(directory: File): List<File> {
        val suspiciousFiles = mutableListOf<File>()
        val suspiciousExtensions = setOf(".apk", ".exe", ".bat", ".cmd", ".scr", ".pif", ".com")

        try {
            if (directory.exists() && directory.isDirectory) {
                directory.listFiles()?.forEach { file ->
                    if (file.isFile) {
                        val extension = file.extension.lowercase()
                        if (suspiciousExtensions.contains(".$extension")) {
                            suspiciousFiles.add(file)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore permission errors for individual directories
        }

        return suspiciousFiles
    }

    private fun displayScanResults(suspiciousFiles: List<File>) {
        binding.suspiciousFilesList.removeAllViews()

        if (suspiciousFiles.isEmpty()) {
            val noFilesText = android.widget.TextView(this).apply {
                text = "✅ No suspicious files found"
                setTextColor(android.graphics.Color.GREEN)
                textSize = 16f
                setPadding(16, 16, 16, 16)
            }
            binding.suspiciousFilesList.addView(noFilesText)
            binding.cleanFilesButton.isEnabled = false
        } else {
            binding.cleanFilesButton.isEnabled = true

            // Scan files with VirusTotal API
            suspiciousFiles.forEach { file ->
                val fileItem = android.widget.TextView(this).apply {
                    var fileText = "⚠️ ${file.name}\n   Size: ${file.length()} bytes\n   Path: ${file.parent}"
                    
                    // Try VirusTotal scan if API is configured
                    if (VirusTotalApi.isApiKeyConfigured(this@FileCleanerActivity)) {
                        fileText += "\n   🔍 Scanning with VirusTotal..."
                    }
                    
                    text = fileText
                    textSize = 14f
                    setPadding(16, 8, 16, 8)
                    background = android.graphics.drawable.ColorDrawable(
                        android.graphics.Color.parseColor("#333333")
                    )
                    setTextColor(android.graphics.Color.WHITE)
                }
                binding.suspiciousFilesList.addView(fileItem)

                // Perform VirusTotal scan in background
                if (VirusTotalApi.isApiKeyConfigured(this)) {
                    Thread {
                        val vtResult = securityScanner.scanFileWithVirusTotal(file)
                        runOnUiThread {
                            updateFileItemWithVirusTotalResult(fileItem, file, vtResult)
                        }
                    }.start()
                }
            }
        }
    }

    private fun updateFileItemWithVirusTotalResult(
        textView: android.widget.TextView,
        file: File,
        vtResult: VirusTotalResult?
    ) {
        var fileText = "⚠️ ${file.name}\n   Size: ${file.length()} bytes\n   Path: ${file.parent}"
        
        if (vtResult != null) {
            if (vtResult.isThreat()) {
                fileText += "\n   🚨 VirusTotal: ${vtResult.verdict}"
                fileText += "\n   ${vtResult.getDetectionRatio()}"
                textView.setTextColor(android.graphics.Color.RED)
            } else {
                fileText += "\n   ✅ VirusTotal: ${vtResult.verdict}"
                fileText += "\n   ${vtResult.getDetectionRatio()}"
                textView.setTextColor(android.graphics.Color.GREEN)
            }
        } else {
            fileText += "\n   ⚠️ VirusTotal: Not scanned (API unavailable)"
        }
        
        textView.text = fileText
    }

    private fun cleanSuspiciousFiles() {
        binding.cleanProgress.visibility = android.view.View.VISIBLE
        binding.cleanFilesButton.isEnabled = false

        Thread {
            val cleanResults = securityScanner.cleanSuspiciousFiles()

            runOnUiThread {
                val cleaned = cleanResults["cleaned"] ?: 0
                val quarantined = cleanResults["quarantined"] ?: 0

                val message = "Cleaned: $cleaned files\nQuarantined: $quarantined files"
                Toast.makeText(this, message, Toast.LENGTH_LONG).show()

                binding.cleanProgress.visibility = android.view.View.GONE
                binding.cleanFilesButton.isEnabled = true

                // Rescan to update the list
                scanForSuspiciousFiles()
            }
        }.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        securityScanner.close()
    }
}
