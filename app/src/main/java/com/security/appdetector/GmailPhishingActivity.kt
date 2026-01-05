package com.security.appdetector

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.Scope
import com.security.appdetector.adapter.EmailAdapter
import com.security.appdetector.databinding.ActivityGmailPhishingBinding
import com.security.appdetector.model.EmailScanResult

/**
 * Activity for scanning Gmail inbox for phishing emails
 */
class GmailPhishingActivity : AppCompatActivity() {

    private lateinit var binding: ActivityGmailPhishingBinding
    private lateinit var emailAdapter: EmailAdapter
    private val emailResults = mutableListOf<EmailScanResult>()
    private lateinit var googleSignInClient: GoogleSignInClient

    private val signInLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                handleSignInResult(result.data)
            } else {
                showError("Sign-in was cancelled.")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityGmailPhishingBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupToolbar()
        setupRecyclerView()
        setupGoogleSignIn()
        
        binding.scanInboxButton.setOnClickListener {
            startGmailSignIn()
        }
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener { finish() }
    }

    private fun setupRecyclerView() {
        emailAdapter = EmailAdapter(emailResults) { email ->
            if (email.isPhishing) {
                showPhishingDetails(email)
            }
        }
        binding.emailsRecyclerView.layoutManager = LinearLayoutManager(this)
        binding.emailsRecyclerView.adapter = emailAdapter
    }

    private fun setupGoogleSignIn() {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestScopes(
                Scope("https://www.googleapis.com/auth/gmail.readonly")
            )
            .build()

        googleSignInClient = GoogleSignIn.getClient(this, gso)
    }

    private fun startGmailSignIn() {
        signInLauncher.launch(googleSignInClient.signInIntent)
    }

    private fun handleSignInResult(data: Intent?) {
        try {
            val task = GoogleSignIn.getSignedInAccountFromIntent(data)
            val account = task.getResult(ApiException::class.java)

            if (account == null) {
                showError("Google account not found")
                return
            }

            // ✅ Phase 5 COMPLETE
            onGmailAccountReady(account)

        } catch (e: ApiException) {
            showError("Sign-in failed: ${e.statusCode}")
        }
    }

    private fun onGmailAccountReady(account: GoogleSignInAccount) {
        Toast.makeText(this, "Signed in as ${account.email}", Toast.LENGTH_SHORT).show()
        
        // Update UI for the signed-in state
        binding.connectGmailButton.visibility = View.GONE
        binding.scanInboxButton.visibility = View.VISIBLE
        binding.scanSummaryText.text = "Ready to scan inbox for ${account.email}."
    }

    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun showPhishingDetails(email: EmailScanResult) {
        val reasons = email.phishingReasons.joinToString("\n- ")
        AlertDialog.Builder(this)
            .setTitle("Phishing Details")
            .setMessage("Subject: ${email.subject}\n\nSender: ${email.sender}\n\nReasons why this email is suspicious:\n- $reasons")
            .setPositiveButton("OK", null)
            .show()
    }
}
