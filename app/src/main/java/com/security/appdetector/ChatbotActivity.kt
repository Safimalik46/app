package com.security.appdetector

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.security.appdetector.adapter.ChatMessageAdapter
import com.security.appdetector.databinding.ActivityChatbotBinding
import com.security.appdetector.model.ChatMessage
import com.security.appdetector.util.GeminiSecurityApi
import kotlinx.coroutines.*

/**
 * Chatbot Assistant Activity for security-related questions
 * Powered by Google Gemini AI
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
            message = "👋 Hello! I'm your Gemini-powered Security Assistant. I can help you with:\n\n" +
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
        if (!GeminiSecurityApi.isApiKeyConfigured(this)) {
            hideTypingIndicator()
            val errorMessage = ChatMessage(
                message = "⚠️ Gemini API is not configured. Please go to Settings and add your Gemini API key to use the chatbot.",
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
                // Use Gemini API directly
                val response = GeminiSecurityApi.chatWithGemini(this@ChatbotActivity, userMessage)
                
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

    private fun scrollToBottom() {
        binding.chatRecyclerView.post {
            if (chatMessages.isNotEmpty()) {
                binding.chatRecyclerView.smoothScrollToPosition(chatMessages.size - 1)
            }
        }
    }
}
