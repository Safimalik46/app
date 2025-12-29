package com.security.appdetector.model

/**
 * Data class representing a chat message
 */
data class ChatMessage(
    val message: String,
    val isUser: Boolean,
    val timestamp: Long
)

