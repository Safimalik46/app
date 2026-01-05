package com.security.appdetector.util

import android.content.Context
import android.util.Log
import com.google.ai.client.generativeai.GenerativeModel
import com.google.ai.client.generativeai.type.content
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Gemini API integration for AI-powered security analysis
 * Uses Google's Gemini Pro model to analyze app behavior and provide security insights
 */
object GeminiSecurityApi {
    private const val MODEL_NAME = "gemini-pro"

    /**
     * Get API key from SharedPreferences
     */
    private fun getApiKey(context: Context): String? {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(context)
        val apiKey = prefs.getString("gemini_api_key", null)
        val isEnabled = prefs.getBoolean("enable_gemini", true) // Default true for now
        return if (isEnabled && !apiKey.isNullOrBlank()) apiKey else null
    }

    /**
     * Check if Gemini API is configured
     */
    fun isApiKeyConfigured(context: Context): Boolean {
        return getApiKey(context) != null
    }

    /**
     * Chat with Gemini
     */
    suspend fun chatWithGemini(context: Context, userMessage: String): String? {
        val apiKey = getApiKey(context) ?: throw IllegalStateException("Gemini API Key not configured.")
        
        return withContext(Dispatchers.IO) {
            val generativeModel = GenerativeModel(
                modelName = MODEL_NAME,
                apiKey = apiKey
            )

            val chat = generativeModel.startChat(
                history = listOf(
                    content(role = "user") { text("You are a helpful cybersecurity assistant for Android mobile security. Answer concisely.") },
                    content(role = "model") { text("I understand. I am a cybersecurity assistant ready to help with Android security questions.") }
                )
            )

            val response = chat.sendMessage(userMessage)
            response.text?.takeIf { it.isNotBlank() } ?: throw IOException("Received an empty response from the AI.")
        }
    }

    /**
     * Analyze app security using Gemini
     */
    suspend fun analyzeAppSecurity(
        context: Context,
        appName: String,
        packageName: String,
        permissions: List<String>,
        dangerousPermissions: List<String>
    ): AISecurityAnalysis? {
        val apiKey = getApiKey(context) ?: throw IllegalStateException("Gemini API Key not configured.")

        return withContext(Dispatchers.IO) {
            val generativeModel = GenerativeModel(
                modelName = MODEL_NAME,
                apiKey = apiKey
            )

            val prompt = """
                Analyze the security risk of this Android app and provide a detailed assessment.
                
                App Name: $appName
                Package: $packageName
                Total Permissions: ${permissions.size}
                Dangerous Permissions Count: ${dangerousPermissions.size}
                
                Dangerous Permissions List:
                ${dangerousPermissions.joinToString("\n")}
                
                Please provide:
                1. Risk Level (SAFE, RISKY, or MALWARE)
                2. Security Score (0-100)
                3. Key Security Concerns
                4. Recommendations
                
                Respond ONLY with valid JSON format:
                {
                    "riskLevel": "SAFE|RISKY|MALWARE",
                    "securityScore": 85,
                    "concerns": ["concern1", "concern2"],
                    "recommendations": ["recommendation1", "recommendation2"]
                }
            """.trimIndent()

            val response = generativeModel.generateContent(prompt)
            val responseText = response.text ?: throw IOException("Received an empty response from the AI for app analysis.")
            
            // Clean up markdown code blocks if present
            val jsonText = responseText.replace("```json", "").replace("```", "").trim()
            
            parseSecurityAnalysis(jsonText)
        }
    }

    /**
     * Parse Gemini response
     */
    private fun parseSecurityAnalysis(json: String): AISecurityAnalysis? {
        return try {
            val obj = org.json.JSONObject(json)
            
            AISecurityAnalysis(
                riskLevel = obj.getString("riskLevel"),
                securityScore = obj.getInt("securityScore"),
                concerns = parseStringArray(obj, "concerns"),
                recommendations = parseStringArray(obj, "recommendations")
            )
        } catch (e: Exception) {
            Log.e("GeminiSecurityApi", "Parse error: ${e.message}")
            throw IOException("Failed to parse AI response.", e)
        }
    }

    private fun parseStringArray(json: org.json.JSONObject, key: String): List<String> {
        return try {
            val array = json.getJSONArray(key)
            (0 until array.length()).map { array.getString(it) }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
