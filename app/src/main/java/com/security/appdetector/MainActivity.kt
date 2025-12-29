package com.security.appdetector

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.security.appdetector.databinding.ActivityMainBinding

/**
 * Main/Home Screen Activity
 * Entry point after splash screen with scan button
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupClickListeners()
    }

    private fun setupClickListeners() {
        binding.scanButton.setOnClickListener {
            val intent = Intent(this, AppScanActivity::class.java)
            startActivity(intent)
        }

        binding.antivirusButton.setOnClickListener {
            val intent = Intent(this, AntivirusActivity::class.java)
            startActivity(intent)
        }

        binding.fileCleanerButton.setOnClickListener {
            val intent = Intent(this, FileCleanerActivity::class.java)
            startActivity(intent)
        }

        binding.chatbotButton.setOnClickListener {
            val intent = Intent(this, ChatbotActivity::class.java)
            startActivity(intent)
        }

        binding.settingsButton.setOnClickListener {
            val intent = Intent(this, SettingsActivity::class.java)
            startActivity(intent)
        }
    }
}

