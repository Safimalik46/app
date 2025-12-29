package com.security.appdetector.util

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * OpenAI API integration for AI-powered security analysis
 * Uses GPT models to analyze app behavior and provide security insights
 */
object OpenAISecurityApi {
    private const val BASE_URL = "https://api.openai.com/v1/chat/completions"
    private const val TIMEOUT = 15000 // 15 seconds
    private const val MODEL = "gpt-3.5-turbo"

    /**
     * Get API key from SharedPreferences
     */
    private fun getApiKey(context: Context): String? {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(context)
        val apiKey = prefs.getString("openai_api_key", null)
        val isEnabled = prefs.getBoolean("enable_openai", false)
        return if (isEnabled && !apiKey.isNullOrBlank()) apiKey else null
    }

    /**
     * Check if OpenAI API is configured and enabled
     */
    fun isApiKeyConfigured(context: Context): Boolean {
        return getApiKey(context) != null
    }

    /**
     * Analyze app security using AI
     */
    fun analyzeAppSecurity(
        context: Context,
        appName: String,
        packageName: String,
        permissions: List<String>,
        dangerousPermissions: List<String>
    ): AISecurityAnalysis? {
        val apiKey = getApiKey(context) ?: return null

        return try {
            val prompt = buildSecurityPrompt(appName, packageName, permissions, dangerousPermissions)
            val response = callOpenAI(apiKey, prompt)
            parseSecurityAnalysis(response)
        } catch (e: Exception) {
            Log.e("OpenAISecurityApi", "Error analyzing app: ${e.message}")
            null
        }
    }

    /**
     * Build security analysis prompt for AI
     */
    private fun buildSecurityPrompt(
        appName: String,
        packageName: String,
        permissions: List<String>,
        dangerousPermissions: List<String>
    ): String {
        return """
            Analyze the security risk of this Android app and provide a detailed assessment.
            
            App Name: $appName
            Package: $packageName
            Total Permissions: ${permissions.size}
            Dangerous Permissions: ${dangerousPermissions.size}
            
            Dangerous Permissions List:
            ${dangerousPermissions.joinToString("\n")}
            
            Please provide:
            1. Risk Level (SAFE, RISKY, or MALWARE)
            2. Security Score (0-100)
            3. Key Security Concerns
            4. Recommendations
            
            Respond in JSON format:
            {
                "riskLevel": "SAFE|RISKY|MALWARE",
                "securityScore": 85,
                "concerns": ["concern1", "concern2"],
                "recommendations": ["recommendation1", "recommendation2"]
            }
        """.trimIndent()
    }

    /**
     * Call OpenAI API
     */
    private fun callOpenAI(apiKey: String, prompt: String): String? {
        return try {
            val url = URL(BASE_URL)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.setRequestProperty("Authorization", "Bearer $apiKey")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.connectTimeout = TIMEOUT
            connection.readTimeout = TIMEOUT
            connection.doOutput = true

            val requestBody = JSONObject().apply {
                put("model", MODEL)
                put("messages", listOf(
                    JSONObject().apply {
                        put("role", "system")
                        put("content", "You are a cybersecurity expert specializing in Android app security analysis.")
                    },
                    JSONObject().apply {
                        put("role", "user")
                        put("content", prompt)
                    }
                ))
                put("temperature", 0.3)
                put("max_tokens", 500)
            }

            connection.outputStream.use { os ->
                os.write(requestBody.toString().toByteArray())
            }

            val responseCode = connection.responseCode
            if (responseCode == 200) {
                connection.inputStream.bufferedReader().readText()
            } else {
                val error = connection.errorStream?.bufferedReader()?.readText()
                Log.e("OpenAISecurityApi", "API error $responseCode: $error")
                null
            }
        } catch (e: IOException) {
            Log.e("OpenAISecurityApi", "Network error: ${e.message}")
            null
        } catch (e: Exception) {
            Log.e("OpenAISecurityApi", "Error: ${e.message}")
            null
        }
    }

    /**
     * Parse OpenAI response
     */
    private fun parseSecurityAnalysis(json: String?): AISecurityAnalysis? {
        if (json == null) return null

        return try {
            val obj = JSONObject(json)
            val choices = obj.getJSONArray("choices")
            if (choices.length() > 0) {
                val message = choices.getJSONObject(0).getJSONObject("message")
                val content = message.getString("content")
                
                // Try to parse JSON from content
                val contentJson = JSONObject(content)
                AISecurityAnalysis(
                    riskLevel = contentJson.getString("riskLevel"),
                    securityScore = contentJson.getInt("securityScore"),
                    concerns = parseStringArray(contentJson, "concerns"),
                    recommendations = parseStringArray(contentJson, "recommendations")
                )
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e("OpenAISecurityApi", "Parse error: ${e.message}")
            null
        }
    }

    private fun parseStringArray(json: JSONObject, key: String): List<String> {
        return try {
            val array = json.getJSONArray(key)
            (0 until array.length()).map { array.getString(it) }
        } catch (e: Exception) {
            emptyList()
        }
    }
}

/**
 * Data class for AI security analysis results
 */
data class AISecurityAnalysis(
    val riskLevel: String,
    val securityScore: Int,
    val concerns: List<String>,
    val recommendations: List<String>
)

