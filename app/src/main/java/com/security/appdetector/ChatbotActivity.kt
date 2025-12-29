package com.security.appdetector

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.security.appdetector.adapter.ChatMessageAdapter
import com.security.appdetector.databinding.ActivityChatbotBinding
import com.security.appdetector.model.ChatMessage
import com.security.appdetector.util.OpenAISecurityApi
import kotlinx.coroutines.*

/**
 * Chatbot Assistant Activity for security-related questions
 */
class ChatbotActivity : AppCompatActivity() {

    private lateinit var binding: ActivityChatbotBinding
    private lateinit var chatAdapter: ChatMessageAdapter
    private val chatMessages = mutableListOf<ChatMessage>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityChatbotBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupRecyclerView()
        setupClickListeners()

        // Add welcome message
        addWelcomeMessage()
    }

    private fun setupRecyclerView() {
        chatAdapter = ChatMessageAdapter(chatMessages)
        binding.chatRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@ChatbotActivity)
            adapter = chatAdapter
        }
    }

    private fun setupClickListeners() {
        binding.backButton.setOnClickListener {
            finish()
        }

        binding.sendButton.setOnClickListener {
            sendMessage()
        }

        // Send on Enter key
        binding.messageEditText.setOnEditorActionListener { _, _, _ ->
            sendMessage()
            true
        }

        // Quick action buttons
        binding.quickAction1.setOnClickListener {
            binding.messageEditText.setText("What are dangerous permissions in Android?")
            sendMessage()
        }

        binding.quickAction2.setOnClickListener {
            binding.messageEditText.setText("How do I know if an app is safe?")
            sendMessage()
        }

        binding.quickAction3.setOnClickListener {
            binding.messageEditText.setText("What should I do if I find malware?")
            sendMessage()
        }
    }

    private fun addWelcomeMessage() {
        val welcomeMessage = ChatMessage(
            message = "👋 Hello! I'm your Security Assistant. I can help you with:\n\n" +
                    "• Understanding app permissions\n" +
                    "• Identifying security threats\n" +
                    "• Explaining risk levels\n" +
                    "• Providing security recommendations\n\n" +
                    "Ask me anything about mobile security!",
            isUser = false,
            timestamp = System.currentTimeMillis()
        )
        chatMessages.add(welcomeMessage)
        chatAdapter.notifyItemInserted(chatMessages.size - 1)
        scrollToBottom()
    }

    private fun sendMessage() {
        val messageText = binding.messageEditText.text.toString().trim()
        if (messageText.isEmpty()) {
            return
        }

        // Add user message
        val userMessage = ChatMessage(
            message = messageText,
            isUser = true,
            timestamp = System.currentTimeMillis()
        )
        chatMessages.add(userMessage)
        chatAdapter.notifyItemInserted(chatMessages.size - 1)
        scrollToBottom()

        // Clear input
        binding.messageEditText.setText("")

        // Show typing indicator
        showTypingIndicator()

        // Get AI response
        getAIResponse(messageText)
    }

    private fun showTypingIndicator() {
        binding.typingIndicator.visibility = View.VISIBLE
    }

    private fun hideTypingIndicator() {
        binding.typingIndicator.visibility = View.GONE
    }

    private fun getAIResponse(userMessage: String) {
        if (!OpenAISecurityApi.isApiKeyConfigured(this)) {
            hideTypingIndicator()
            val errorMessage = ChatMessage(
                message = "⚠️ OpenAI API is not configured. Please go to Settings and add your OpenAI API key to use the chatbot.",
                isUser = false,
                timestamp = System.currentTimeMillis()
            )
            chatMessages.add(errorMessage)
            chatAdapter.notifyItemInserted(chatMessages.size - 1)
            scrollToBottom()
            return
        }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val response = getChatbotResponse(userMessage)
                withContext(Dispatchers.Main) {
                    hideTypingIndicator()
                    val botMessage = ChatMessage(
                        message = response ?: "Sorry, I couldn't process your request. Please try again.",
                        isUser = false,
                        timestamp = System.currentTimeMillis()
                    )
                    chatMessages.add(botMessage)
                    chatAdapter.notifyItemInserted(chatMessages.size - 1)
                    scrollToBottom()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    hideTypingIndicator()
                    val errorMessage = ChatMessage(
                        message = "❌ Error: ${e.message}. Please check your internet connection and API key.",
                        isUser = false,
                        timestamp = System.currentTimeMillis()
                    )
                    chatMessages.add(errorMessage)
                    chatAdapter.notifyItemInserted(chatMessages.size - 1)
                    scrollToBottom()
                }
            }
        }
    }

    private suspend fun getChatbotResponse(userMessage: String): String? {
        return withContext(Dispatchers.IO) {
            try {
                val prompt = buildChatbotPrompt(userMessage)
                val response = callOpenAIChat(prompt)
                parseChatResponse(response)
            } catch (e: Exception) {
                null
            }
        }
    }

    private fun buildChatbotPrompt(userMessage: String): String {
        return """
            You are a helpful cybersecurity assistant for Android mobile security. 
            Answer the user's question about mobile app security, permissions, malware, or threats.
            Be concise, clear, and helpful. Use emojis when appropriate.
            
            User question: $userMessage
            
            Provide a helpful answer:
        """.trimIndent()
    }

    private fun callOpenAIChat(prompt: String): String? {
        return try {
            val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this)
            val apiKey = prefs.getString("openai_api_key", null) ?: return null

            val url = java.net.URL("https://api.openai.com/v1/chat/completions")
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "POST"
            connection.setRequestProperty("Authorization", "Bearer $apiKey")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.connectTimeout = 15000
            connection.readTimeout = 15000
            connection.doOutput = true

            val requestBody = org.json.JSONObject().apply {
                put("model", "gpt-3.5-turbo")
                put("messages", listOf(
                    org.json.JSONObject().apply {
                        put("role", "system")
                        put("content", "You are a helpful cybersecurity assistant specializing in Android mobile security.")
                    },
                    org.json.JSONObject().apply {
                        put("role", "user")
                        put("content", prompt)
                    }
                ))
                put("temperature", 0.7)
                put("max_tokens", 300)
            }

            connection.outputStream.use { os ->
                os.write(requestBody.toString().toByteArray())
            }

            val responseCode = connection.responseCode
            if (responseCode == 200) {
                connection.inputStream.bufferedReader().readText()
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun parseChatResponse(json: String?): String? {
        if (json == null) return null

        return try {
            val obj = org.json.JSONObject(json)
            val choices = obj.getJSONArray("choices")
            if (choices.length() > 0) {
                val message = choices.getJSONObject(0).getJSONObject("message")
                message.getString("content")
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun scrollToBottom() {
        binding.chatRecyclerView.post {
            if (chatMessages.isNotEmpty()) {
                binding.chatRecyclerView.smoothScrollToPosition(chatMessages.size - 1)
            }
        }
    }
}

