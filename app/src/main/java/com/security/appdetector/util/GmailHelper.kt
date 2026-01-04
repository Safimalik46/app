package com.security.appdetector.util

import android.accounts.Account
import android.content.Context
import android.util.Log
import com.google.api.client.extensions.android.http.AndroidHttp
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.gmail.Gmail
import com.google.api.services.gmail.GmailScopes
import com.security.appdetector.model.EmailScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Collections

/**
 * Helper class for Gmail integration
 * Uses Gmail API to fetch emails for scanning
 */
object GmailHelper {
    
    private const val TAG = "GmailHelper"
    private const val APPLICATION_NAME = "Suspicious App Detector"
    
    /**
     * Get Gmail account from device
     */
    fun getGmailAccount(context: Context): Account? {
        return try {
            val accountManager = android.accounts.AccountManager.get(context)
            
            // Try multiple account types
            val accountTypes = arrayOf(
                "com.google",
                "com.google.android.gm",
                "com.google.android.gms"
            )
            
            for (accountType in accountTypes) {
                try {
                    val accounts = accountManager.getAccountsByType(accountType)
                    if (accounts.isNotEmpty()) {
                        return accounts.first()
                    }
                } catch (e: Exception) {
                    // Continue to next account type
                }
            }
            
            // Try to find any email account that looks like Gmail
            try {
                val allAccounts = accountManager.accounts
                return allAccounts.firstOrNull { account ->
                    account.name.contains("@") && (
                        account.name.contains("gmail.com") ||
                        account.name.contains("googlemail.com") ||
                        account.type.contains("google") ||
                        account.type.contains("gmail")
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error filtering accounts: ${e.message}")
            }
            
            null
        } catch (e: SecurityException) {
            Log.e(TAG, "Permission denied: ${e.message}")
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error getting Gmail account: ${e.message}")
            null
        }
    }

    /**
     * Check if Gmail account is available
     */
    fun hasGmailAccount(context: Context): Boolean {
        return getGmailAccount(context) != null
    }

    /**
     * Get Gmail service instance
     */
    fun getGmailService(context: Context, account: Account): Gmail? {
        return try {
            val credential = GoogleAccountCredential.usingOAuth2(
                context, Collections.singleton(GmailScopes.GMAIL_READONLY)
            )
            credential.selectedAccount = account
            
            Gmail.Builder(
                AndroidHttp.newCompatibleTransport(),
                GsonFactory.getDefaultInstance(),
                credential
            )
            .setApplicationName(APPLICATION_NAME)
            .build()
        } catch (e: Exception) {
            Log.e(TAG, "Error creating Gmail service: ${e.message}")
            null
        }
    }
    
    /**
     * Fetch emails from Gmail API
     */
    suspend fun fetchGmailEmails(context: Context, account: Account, maxResults: Long = 20): List<EmailScanResult> = withContext(Dispatchers.IO) {
        val results = mutableListOf<EmailScanResult>()
        
        try {
            val service = getGmailService(context, account) ?: return@withContext results
            
            // List messages
            val listResponse = service.users().messages().list("me")
                .setMaxResults(maxResults)
                .setQ("category:primary") // Focus on primary inbox
                .execute()
                
            val messages = listResponse.messages
            if (messages != null) {
                for (message in messages) {
                    try {
                        // Get full message details
                        val fullMessage = service.users().messages().get("me", message.id)
                            .setFormat("full")
                            .execute()
                            
                        val headers = fullMessage.payload.headers
                        val subject = headers.find { it.name.equals("Subject", ignoreCase = true) }?.value ?: "(No Subject)"
                        val sender = headers.find { it.name.equals("From", ignoreCase = true) }?.value ?: "Unknown"
                        val date = headers.find { it.name.equals("Date", ignoreCase = true) }?.value?.toLongOrNull() ?: System.currentTimeMillis()
                        
                        val snippet = fullMessage.snippet ?: ""
                        
                        // Use PhishingDetector for more sophisticated analysis
                        val (isPhishing, reasons) = PhishingDetector.detectPhishing(subject, sender, snippet)
                        
                        results.add(EmailScanResult(
                            id = message.id,
                            sender = sender,
                            subject = subject,
                            preview = snippet,
                            date = date,
                            isPhishing = isPhishing,
                            threatLevel = if (isPhishing) "HIGH" else "LOW",
                            phishingReasons = reasons
                        ))
                        
                    } catch (e: Exception) {
                        Log.e(TAG, "Error fetching message ${message.id}: ${e.message}")
                    }
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Gmail API Error: ${e.message}")
            // In a real app, you would handle specific API errors (e.g., auth required)
        }
        
        results
    }
}
