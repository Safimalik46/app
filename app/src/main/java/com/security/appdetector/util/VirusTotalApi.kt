package com.security.appdetector.util

import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * VirusTotal API integration for real-time malware detection
 * Get your free API key at: https://www.virustotal.com/gui/join-us
 */
object VirusTotalApi {
    private const val BASE_URL = "https://www.virustotal.com/api/v3"
    private const val TIMEOUT = 10000 // 10 seconds

    /**
     * Get API key from SharedPreferences
     */
    private fun getApiKey(context: android.content.Context): String? {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(context)
        val apiKey = prefs.getString("virustotal_api_key", null)
        val isEnabled = prefs.getBoolean("enable_virustotal", false)
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
     * Calculate SHA-256 hash of a file
     */
    fun calculateFileHash(file: File): String? {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    md.update(buffer, 0, bytesRead)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.e("VirusTotalApi", "Error calculating hash: ${e.message}")
            null
        }
    }

    /**
     * Query VirusTotal for a file hash (SHA-256)
     * Returns VirusTotalResult or null if error
     */
    fun queryFileHash(context: android.content.Context, hash: String): VirusTotalResult? {
        val apiKey = getApiKey(context) ?: run {
            Log.w("VirusTotalApi", "API key not configured")
            return null
        }

        return try {
            val url = URL("$BASE_URL/files/$hash")
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.setRequestProperty("x-apikey", apiKey)
            connection.setRequestProperty("Accept", "application/json")
            connection.connectTimeout = TIMEOUT
            connection.readTimeout = TIMEOUT
            connection.doInput = true

            val responseCode = connection.responseCode
            when (responseCode) {
                200 -> {
                    val response = connection.inputStream.bufferedReader().readText()
                    parseVirusTotalResponse(response)
                }
                404 -> {
                    Log.d("VirusTotalApi", "File not found in VirusTotal database")
                    VirusTotalResult(0, 0, 0, 0, "Not found in database", false)
                }
                401 -> {
                    Log.e("VirusTotalApi", "Invalid API key")
                    null
                }
                else -> {
                    Log.e("VirusTotalApi", "API error: $responseCode")
                    null
                }
            }
        } catch (e: IOException) {
            Log.e("VirusTotalApi", "Network error: ${e.message}")
            null
        } catch (e: Exception) {
            Log.e("VirusTotalApi", "Error: ${e.message}")
            null
        }
    }

    /**
     * Parse VirusTotal JSON response
     */
    private fun parseVirusTotalResponse(json: String): VirusTotalResult? {
        return try {
            val obj = JSONObject(json)
            val data = obj.getJSONObject("data")
            val attributes = data.getJSONObject("attributes")
            val stats = attributes.getJSONObject("last_analysis_stats")

            val malicious = stats.getInt("malicious")
            val suspicious = stats.getInt("suspicious")
            val harmless = stats.getInt("harmless")
            val undetected = stats.getInt("undetected")
            val total = malicious + suspicious + harmless + undetected

            val verdict = when {
                malicious > 0 -> "MALWARE DETECTED"
                suspicious > 0 -> "SUSPICIOUS"
                else -> "CLEAN"
            }

            VirusTotalResult(malicious, suspicious, harmless, undetected, verdict, true)
        } catch (e: Exception) {
            Log.e("VirusTotalApi", "Parse error: ${e.message}")
            null
        }
    }

    /**
     * Scan a file using VirusTotal
     */
    fun scanFile(context: android.content.Context, file: File): VirusTotalResult? {
        val hash = calculateFileHash(file) ?: return null
        return queryFileHash(context, hash)
    }
}

/**
 * Data class for VirusTotal scan results
 */
data class VirusTotalResult(
    val malicious: Int,
    val suspicious: Int,
    val harmless: Int,
    val undetected: Int,
    val verdict: String,
    val found: Boolean
) {
    fun getDetectionRatio(): String {
        val total = malicious + suspicious + harmless + undetected
        val detected = malicious + suspicious
        return if (total > 0) {
            "$detected / $total engines detected threats"
        } else {
            "No data available"
        }
    }

    fun isThreat(): Boolean {
        return malicious > 0 || suspicious > 0
    }
}

