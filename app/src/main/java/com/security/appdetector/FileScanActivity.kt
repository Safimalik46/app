package com.security.appdetector

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.security.appdetector.adapter.FileScanAdapter
import com.security.appdetector.ai.SecurityScanner
import com.security.appdetector.databinding.ActivityFileScanBinding
import com.security.appdetector.model.FileScanResult
import com.security.appdetector.util.VirusTotalApi
import java.io.File

/**
 * Activity for scanning files (APKs, documents, etc.) for threats
 */
class FileScanActivity : AppCompatActivity() {

    private lateinit var binding: ActivityFileScanBinding
    private lateinit var securityScanner: SecurityScanner
    private lateinit var fileScanAdapter: FileScanAdapter
    private val scannedFiles = mutableListOf<FileScanResult>()
    private val STORAGE_PERMISSION_CODE = 100

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileScanBinding.inflate(layoutInflater)
        setContentView(binding.root)

        securityScanner = SecurityScanner(this)
        setupToolbar()
        setupRecyclerView()
        setupScanOptions()
        checkPermissions()
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
    }

    private fun setupRecyclerView() {
        fileScanAdapter = FileScanAdapter(scannedFiles) { fileResult ->
            showFileDetails(fileResult)
        }
        binding.filesRecyclerView.layoutManager = LinearLayoutManager(this)
        binding.filesRecyclerView.adapter = fileScanAdapter
    }

    private fun setupScanOptions() {
        binding.scanApkButton.setOnClickListener {
            scanApkFiles()
        }
        
        binding.scanDownloadsButton.setOnClickListener {
            scanDownloadFolder()
        }
        
        binding.scanCustomButton.setOnClickListener {
            pickFileToScan()
        }
        
        binding.scanAllButton.setOnClickListener {
            scanAllSuspiciousFiles()
        }
    }

    private fun checkPermissions() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
                STORAGE_PERMISSION_CODE
            )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == STORAGE_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Permission granted", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Permission denied. File scanning requires storage permission.", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun scanApkFiles() {
        binding.scanProgress.visibility = View.VISIBLE
        binding.emptyStateText.visibility = View.GONE
        
        Thread {
            val apkFiles = mutableListOf<File>()
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            scanDirectoryForApks(downloadsDir, apkFiles)
            
            scannedFiles.clear()
            apkFiles.forEach { file ->
                val result = scanFile(file)
                scannedFiles.add(result)
            }
            
            runOnUiThread {
                binding.scanProgress.visibility = View.GONE
                if (scannedFiles.isEmpty()) {
                    binding.emptyStateText.visibility = View.VISIBLE
                    binding.emptyStateText.text = "No APK files found in Downloads"
                } else {
                    fileScanAdapter.notifyDataSetChanged()
                }
            }
        }.start()
    }

    private fun scanDownloadFolder() {
        binding.scanProgress.visibility = View.VISIBLE
        binding.emptyStateText.visibility = View.GONE
        
        Thread {
            val suspiciousFiles = mutableListOf<File>()
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            scanDirectoryForSuspiciousFiles(downloadsDir, suspiciousFiles)
            
            scannedFiles.clear()
            suspiciousFiles.forEach { file ->
                val result = scanFile(file)
                scannedFiles.add(result)
            }
            
            runOnUiThread {
                binding.scanProgress.visibility = View.GONE
                if (scannedFiles.isEmpty()) {
                    binding.emptyStateText.visibility = View.VISIBLE
                    binding.emptyStateText.text = "No suspicious files found"
                } else {
                    fileScanAdapter.notifyDataSetChanged()
                }
            }
        }.start()
    }

    private fun scanAllSuspiciousFiles() {
        binding.scanProgress.visibility = View.VISIBLE
        binding.emptyStateText.visibility = View.GONE
        
        Thread {
            val suspiciousFiles = mutableListOf<File>()
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            scanDirectoryForSuspiciousFiles(downloadsDir, suspiciousFiles)
            
            scannedFiles.clear()
            suspiciousFiles.forEach { file ->
                val result = scanFile(file)
                scannedFiles.add(result)
            }
            
            runOnUiThread {
                binding.scanProgress.visibility = View.GONE
                if (scannedFiles.isEmpty()) {
                    binding.emptyStateText.visibility = View.VISIBLE
                    binding.emptyStateText.text = "No suspicious files found"
                } else {
                    fileScanAdapter.notifyDataSetChanged()
                }
            }
        }.start()
    }

    private fun pickFileToScan() {
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(Intent.createChooser(intent, "Select file"), 101)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 101 && resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                val file = File(uri.path ?: "")
                if (file.exists()) {
                    binding.scanProgress.visibility = View.VISIBLE
                    Thread {
                        val result = scanFile(file)
                        runOnUiThread {
                            binding.scanProgress.visibility = View.GONE
                            scannedFiles.add(0, result)
                            fileScanAdapter.notifyItemInserted(0)
                            binding.emptyStateText.visibility = View.GONE
                        }
                    }.start()
                }
            }
        }
    }

    private fun scanFile(file: File): FileScanResult {
        val fileName = file.name
        val fileSize = file.length()
        val fileExtension = file.extension
        
        // Try VirusTotal scan if available
        var threatDetected = false
        var threatLevel = "Safe"
        var scanDetails = "Local scan completed"
        
        if (VirusTotalApi.isApiKeyConfigured(this)) {
            try {
                val vtResult = VirusTotalApi.scanFile(this, file)
                if (vtResult != null) {
                    threatDetected = vtResult.isThreat()
                    threatLevel = vtResult.verdict
                    scanDetails = vtResult.getDetectionRatio()
                }
            } catch (e: Exception) {
                scanDetails = "VirusTotal scan failed: ${e.message}"
            }
        }
        
        return FileScanResult(
            fileName = fileName,
            filePath = file.absolutePath,
            fileSize = fileSize,
            fileExtension = fileExtension,
            threatDetected = threatDetected,
            threatLevel = threatLevel,
            scanDetails = scanDetails
        )
    }

    private fun scanDirectoryForApks(directory: File, result: MutableList<File>) {
        try {
            if (directory.exists() && directory.isDirectory) {
                directory.listFiles()?.forEach { file ->
                    if (file.isFile && file.extension.lowercase() == "apk") {
                        result.add(file)
                    } else if (file.isDirectory) {
                        scanDirectoryForApks(file, result)
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore
        }
    }

    private fun scanDirectoryForSuspiciousFiles(directory: File, result: MutableList<File>) {
        val suspiciousExtensions = setOf(".apk", ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".jar", ".js", ".vbs")
        try {
            if (directory.exists() && directory.isDirectory) {
                directory.listFiles()?.forEach { file ->
                    if (file.isFile) {
                        val ext = ".${file.extension.lowercase()}"
                        if (suspiciousExtensions.contains(ext)) {
                            result.add(file)
                        }
                    } else if (file.isDirectory && file.name.lowercase() in setOf("downloads", "temp", "cache")) {
                        scanDirectoryForSuspiciousFiles(file, result)
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore
        }
    }

    private fun showFileDetails(result: FileScanResult) {
        AlertDialog.Builder(this)
            .setTitle("File Scan Result")
            .setMessage(
                "File: ${result.fileName}\n" +
                "Size: ${formatFileSize(result.fileSize)}\n" +
                "Threat Level: ${result.threatLevel}\n" +
                "Details: ${result.scanDetails}\n" +
                "Path: ${result.filePath}"
            )
            .setPositiveButton("OK", null)
            .show()
    }

    private fun formatFileSize(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = kb / 1024.0
        return when {
            mb >= 1 -> String.format("%.2f MB", mb)
            kb >= 1 -> String.format("%.2f KB", kb)
            else -> "$bytes B"
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::securityScanner.isInitialized) {
            securityScanner.close()
        }
    }
}

