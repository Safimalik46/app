package com.security.appdetector.util

import android.util.Log
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Google Safe Browsing API integration
 * Get your API key from: https://console.cloud.google.com/apis/credentials
 */
object GoogleSafeBrowsingApi {
    private const val BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    private const val TIMEOUT = 10000

    /**
     * Get API key from SharedPreferences
     */
    private fun getApiKey(context: android.content.Context): String? {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(context)
        val apiKey = prefs.getString("safebrowsing_api_key", null)
        val isEnabled = prefs.getBoolean("enable_safebrowsing", false)
        return if (isEnabled && !apiKey.isNullOrBlank()) apiKey else null
    }

    /**
     * Check if API key is configured
     */
    fun isApiKeyConfigured(context: android.content.Context? = null): Boolean {
        return if (context != null) {
            getApiKey(context) != null
        } else {
            false
        }
    }

    /**
     * Check URL against Google Safe Browsing database
     */
    fun checkUrl(context: android.content.Context, url: String): SafeBrowsingResult? {
        val apiKey = getApiKey(context) ?: run {
            Log.w("SafeBrowsingApi", "API key not configured")
            return null
        }

        return try {
            val apiUrl = URL("$BASE_URL?key=$apiKey")
            val connection = apiUrl.openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.connectTimeout = TIMEOUT
            connection.readTimeout = TIMEOUT
            connection.doOutput = true

            // Build request body
            val requestBody = JSONObject().apply {
                put("client", JSONObject().apply {
                    put("clientId", "SecurityScanner")
                    put("clientVersion", "1.0")
                })
                put("threatInfo", JSONObject().apply {
                    put("threatTypes", listOf("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"))
                    put("platformTypes", listOf("ANY_PLATFORM"))
                    put("threatEntryTypes", listOf("URL"))
                    put("threatEntries", listOf(JSONObject().apply {
                        put("url", url)
                    }))
                })
            }

            connection.outputStream.use { os ->
                os.write(requestBody.toString().toByteArray())
            }

            val responseCode = connection.responseCode
            if (responseCode == 200) {
                val response = connection.inputStream.bufferedReader().readText()
                parseSafeBrowsingResponse(response)
            } else {
                Log.e("SafeBrowsingApi", "API error: $responseCode")
                null
            }
        } catch (e: IOException) {
            Log.e("SafeBrowsingApi", "Network error: ${e.message}")
            null
        } catch (e: Exception) {
            Log.e("SafeBrowsingApi", "Error: ${e.message}")
            null
        }
    }

    /**
     * Parse Google Safe Browsing response
     */
    private fun parseSafeBrowsingResponse(json: String): SafeBrowsingResult? {
        return try {
            val obj = JSONObject(json)
            if (obj.has("matches") && obj.getJSONArray("matches").length() > 0) {
                val matches = obj.getJSONArray("matches")
                val firstMatch = matches.getJSONObject(0)
                val threatType = firstMatch.getString("threatType")
                val platformType = firstMatch.getString("platformType")
                SafeBrowsingResult(true, threatType, platformType)
            } else {
                SafeBrowsingResult(false, "SAFE", "N/A")
            }
        } catch (e: Exception) {
            Log.e("SafeBrowsingApi", "Parse error: ${e.message}")
            null
        }
    }
}

/**
 * Data class for Safe Browsing results
 */
data class SafeBrowsingResult(
    val isThreat: Boolean,
    val threatType: String,
    val platformType: String
)

