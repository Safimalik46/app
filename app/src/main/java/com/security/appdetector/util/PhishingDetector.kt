package com.security.appdetector.util

/**
 * Utility for detecting phishing emails based on common patterns
 */
object PhishingDetector {
    
    // Common phishing keywords
    private val PHISHING_KEYWORDS = setOf(
        "urgent", "verify", "suspended", "expired", "locked", "won", "prize",
        "congratulations", "click here", "act now", "limited time", "verify account",
        "confirm identity", "security alert", "unusual activity", "paypal", "bank",
        "irs", "tax", "refund", "payment required"
    )
    
    // Suspicious sender patterns
    private val SUSPICIOUS_SENDER_PATTERNS = listOf(
        Regex(".*[0-9]{6,}.*"), // Numbers in domain
        Regex(".*(bitly|tinyurl|goo.gl).*"), // URL shorteners
        Regex(".*@.*\\..*\\..*\\..*") // Multiple subdomains
    )
    
    // Suspicious domain patterns
    private val SUSPICIOUS_DOMAINS = setOf(
        "paypal-security", "amazon-support", "apple-verify", "google-security",
        "bank-verify", "microsoft-support"
    )
    
    /**
     * Detects if an email is potentially phishing
     */
    fun detectPhishing(
        subject: String,
        sender: String,
        body: String
    ): Pair<Boolean, List<String>> {
        val reasons = mutableListOf<String>()
        val subjectLower = subject.lowercase()
        val senderLower = sender.lowercase()
        val bodyLower = body.lowercase()
        
        // Check for phishing keywords
        val keywordMatches = PHISHING_KEYWORDS.count { keyword ->
            subjectLower.contains(keyword) || bodyLower.contains(keyword)
        }
        if (keywordMatches >= 3) {
            reasons.add("Multiple phishing keywords detected")
        }
        
        // Check sender patterns
        SUSPICIOUS_SENDER_PATTERNS.forEach { pattern ->
            if (pattern.matches(senderLower)) {
                reasons.add("Suspicious sender pattern")
            }
        }
        
        // Check for suspicious domains
        SUSPICIOUS_DOMAINS.forEach { domain ->
            if (senderLower.contains(domain)) {
                reasons.add("Suspicious domain pattern")
            }
        }
        
        // Check for urgency tactics
        val urgencyKeywords = setOf("urgent", "immediately", "asap", "now", "expires")
        if (urgencyKeywords.any { subjectLower.contains(it) || bodyLower.contains(it) }) {
            reasons.add("Urgency tactics detected")
        }
        
        // Check for generic greetings
        val genericGreetings = setOf("dear customer", "dear user", "dear sir/madam", "valued customer")
        if (genericGreetings.any { bodyLower.contains(it) }) {
            reasons.add("Generic greeting (not personalized)")
        }
        
        // Check for suspicious links (simplified)
        if (bodyLower.contains("http://") && !bodyLower.contains("https://")) {
            reasons.add("Unsecured HTTP links")
        }
        
        val isPhishing = reasons.size >= 2
        
        return Pair(isPhishing, reasons)
    }
}

