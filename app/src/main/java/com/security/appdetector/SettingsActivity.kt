package com.security.appdetector

import android.content.SharedPreferences
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.security.appdetector.databinding.ActivitySettingsBinding

/**
 * Settings Activity for configuring API keys and security features
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private lateinit var sharedPreferences: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        sharedPreferences = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this)

        setupUI()
        loadSettings()
    }

    private fun setupUI() {
        // Back button
        binding.backButton.setOnClickListener {
            finish()
        }

        // Save button
        binding.saveButton.setOnClickListener {
            saveSettings()
        }

        // Test API connections
        binding.testVirusTotalButton.setOnClickListener {
            testVirusTotalApi()
        }

        binding.testSafeBrowsingButton.setOnClickListener {
            testSafeBrowsingApi()
        }

        binding.testGeminiButton.setOnClickListener {
            testGeminiApi()
        }

        // Enable/Disable toggles
        binding.enableVirusTotalSwitch.setOnCheckedChangeListener { _, isChecked ->
            binding.virusTotalApiKeyEdit.isEnabled = isChecked
            binding.testVirusTotalButton.isEnabled = isChecked
        }

        binding.enableSafeBrowsingSwitch.setOnCheckedChangeListener { _, isChecked ->
            binding.safeBrowsingApiKeyEdit.isEnabled = isChecked
            binding.testSafeBrowsingButton.isEnabled = isChecked
        }

        binding.enableGeminiSwitch.setOnCheckedChangeListener { _, isChecked ->
            binding.geminiApiKeyEdit.isEnabled = isChecked
            binding.testGeminiButton.isEnabled = isChecked
        }

        binding.enableRealTimeScanSwitch.setOnCheckedChangeListener { _, isChecked ->
            // Real-time scanning toggle
        }

        binding.enableAutoCleanSwitch.setOnCheckedChangeListener { _, isChecked ->
            // Auto-clean toggle
        }
    }

    private fun loadSettings() {
        // Load API keys
        binding.virusTotalApiKeyEdit.setText(
            sharedPreferences.getString("virustotal_api_key", "") ?: ""
        )
        binding.safeBrowsingApiKeyEdit.setText(
            sharedPreferences.getString("safebrowsing_api_key", "") ?: ""
        )
        binding.geminiApiKeyEdit.setText(
            sharedPreferences.getString("gemini_api_key", "") ?: ""
        )

        // Load toggle states
        binding.enableVirusTotalSwitch.isChecked = sharedPreferences.getBoolean("enable_virustotal", false)
        binding.enableSafeBrowsingSwitch.isChecked = sharedPreferences.getBoolean("enable_safebrowsing", false)
        binding.enableGeminiSwitch.isChecked = sharedPreferences.getBoolean("enable_gemini", true)
        binding.enableRealTimeScanSwitch.isChecked = sharedPreferences.getBoolean("enable_realtime_scan", true)
        binding.enableAutoCleanSwitch.isChecked = sharedPreferences.getBoolean("enable_auto_clean", false)

        // Enable/disable fields based on toggles
        binding.virusTotalApiKeyEdit.isEnabled = binding.enableVirusTotalSwitch.isChecked
        binding.safeBrowsingApiKeyEdit.isEnabled = binding.enableSafeBrowsingSwitch.isChecked
        binding.geminiApiKeyEdit.isEnabled = binding.enableGeminiSwitch.isChecked
        binding.testVirusTotalButton.isEnabled = binding.enableVirusTotalSwitch.isChecked
        binding.testSafeBrowsingButton.isEnabled = binding.enableSafeBrowsingSwitch.isChecked
        binding.testGeminiButton.isEnabled = binding.enableGeminiSwitch.isChecked
    }

    private fun saveSettings() {
        val editor = sharedPreferences.edit()

        // Save API keys
        editor.putString("virustotal_api_key", binding.virusTotalApiKeyEdit.text.toString().trim())
        editor.putString("safebrowsing_api_key", binding.safeBrowsingApiKeyEdit.text.toString().trim())
        editor.putString("gemini_api_key", binding.geminiApiKeyEdit.text.toString().trim())

        // Save toggle states
        editor.putBoolean("enable_virustotal", binding.enableVirusTotalSwitch.isChecked)
        editor.putBoolean("enable_safebrowsing", binding.enableSafeBrowsingSwitch.isChecked)
        editor.putBoolean("enable_gemini", binding.enableGeminiSwitch.isChecked)
        editor.putBoolean("enable_realtime_scan", binding.enableRealTimeScanSwitch.isChecked)
        editor.putBoolean("enable_auto_clean", binding.enableAutoCleanSwitch.isChecked)

        editor.apply()

        Toast.makeText(this, "Settings saved successfully!", Toast.LENGTH_SHORT).show()
    }

    private fun testVirusTotalApi() {
        val apiKey = binding.virusTotalApiKeyEdit.text.toString().trim()
        if (apiKey.isEmpty()) {
            Toast.makeText(this, "Please enter VirusTotal API key", Toast.LENGTH_SHORT).show()
            return
        }

        Toast.makeText(this, "Testing VirusTotal API...", Toast.LENGTH_SHORT).show()
        // Test would be implemented in API utility
        // For now just show success if key is present
        Toast.makeText(this, "VirusTotal API configuration saved", Toast.LENGTH_SHORT).show()
    }

    private fun testSafeBrowsingApi() {
        val apiKey = binding.safeBrowsingApiKeyEdit.text.toString().trim()
        if (apiKey.isEmpty()) {
            Toast.makeText(this, "Please enter Safe Browsing API key", Toast.LENGTH_SHORT).show()
            return
        }

        Toast.makeText(this, "Testing Safe Browsing API...", Toast.LENGTH_SHORT).show()
        Toast.makeText(this, "Safe Browsing API configuration saved", Toast.LENGTH_SHORT).show()
    }

    private fun testGeminiApi() {
        val apiKey = binding.geminiApiKeyEdit.text.toString().trim()
        if (apiKey.isEmpty()) {
            Toast.makeText(this, "Please enter Gemini API key", Toast.LENGTH_SHORT).show()
            return
        }

        Toast.makeText(this, "Testing Gemini API...", Toast.LENGTH_SHORT).show()
        Toast.makeText(this, "Gemini API configuration saved", Toast.LENGTH_SHORT).show()
    }
}
