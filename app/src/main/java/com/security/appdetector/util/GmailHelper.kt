package com.security.appdetector.util

import android.accounts.Account
import android.content.Context
import com.security.appdetector.model.EmailScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Helper class for Gmail integration (DEMO MODE)
 */
object GmailHelper {
    
    private const val TAG = "GmailHelper"
    
    /**
     * This is a placeholder for a real Gmail API implementation.
     * In demo mode, this does nothing.
     */
    suspend fun fetchGmailEmails(context: Context, account: Account, maxResults: Long = 20): List<EmailScanResult> = withContext(Dispatchers.IO) {
        // In a real implementation, you would fetch emails here.
        // Returning an empty list for demo purposes.
        emptyList<EmailScanResult>()
    }
}
