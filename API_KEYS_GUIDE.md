# 🔑 API Keys Setup Guide

This guide will help you get free API keys for all the security features in the app.

---

## 1. 🔴 VirusTotal API (FREE - Recommended)

**What it does:** Scans files and apps against 70+ antivirus engines for real-time malware detection.

### Steps to Get API Key:
1. Go to: **https://www.virustotal.com/gui/join-us**
2. Sign up for a **free account** (email verification required)
3. After login, go to: **https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey**
   - Replace `YOUR_USERNAME` with your actual username
4. Click **"Show API Key"**
5. Copy your API key

### Free Tier Limits:
- ✅ **500 requests per day**
- ✅ **4 requests per minute**
- ✅ Perfect for personal use

### How to Use in App:
1. Open app → Tap **"⚙️ Settings & APIs"**
2. Toggle **"VirusTotal API"** ON
3. Paste your API key
4. Tap **"Test Connection"**
5. Tap **"Save Settings"**

---

## 2. 🟢 Google Safe Browsing API (FREE)

**What it does:** Checks URLs and domains against Google's threat database for phishing and malware.

### Steps to Get API Key:
1. Go to: **https://console.cloud.google.com/**
2. Sign in with your Google account
3. Click **"Create Project"** or select existing project
4. Name your project (e.g., "Security Scanner")
5. Click **"Create"**
6. In the search bar, type: **"Safe Browsing API"**
7. Click on **"Safe Browsing API"**
8. Click **"Enable"**
9. Go to **"Credentials"** (left sidebar)
10. Click **"Create Credentials"** → **"API Key"**
11. Copy your API key
12. (Optional) Click **"Restrict Key"** → Select **"Safe Browsing API"** → **"Save"**

### Free Tier Limits:
- ✅ **10,000 requests per day**
- ✅ More than enough for personal use

### How to Use in App:
1. Open app → Tap **"⚙️ Settings & APIs"**
2. Toggle **"Google Safe Browsing"** ON
3. Paste your API key
4. Tap **"Test Connection"**
5. Tap **"Save Settings"**

---

## 3. ✨ Google Gemini API (FREE - For AI Chatbot & Analysis)

**What it does:** Powers the AI chatbot assistant and provides AI-powered security analysis. Replaces OpenAI.

### Steps to Get API Key:
1. Go to: **https://aistudio.google.com/app/apikey**
2. Sign in with your Google account
3. Click **"Create API key"**
4. Select your project (or create one)
5. Click **"Create"**
6. Copy your API key

### Free Tier Limits:
- ✅ **60 requests per minute**
- ✅ Free of charge for personal use (within limits)

### How to Use in App:
1. Open app → Tap **"⚙️ Settings & APIs"**
2. Toggle **"Google Gemini AI"** ON
3. Paste your API key
4. Tap **"Test Connection"**
5. Tap **"Save Settings"**

---

## 4. 📧 Gmail API (For Phishing Detection)

**What it does:** Allows the app to scan your Gmail inbox for phishing emails.

### Steps to Setup:
1. Go to: **https://console.cloud.google.com/**
2. Select your project
3. Search for **"Gmail API"** and click **"Enable"**
4. Go to **"Credentials"**
5. Configure **OAuth Consent Screen**:
   - User Type: **External** (for testing) or **Internal**
   - Add Test Users (your email)
6. Create Credentials → **OAuth Client ID** → **Android**
7. Add your app's package name: `com.security.appdetector`
8. Add your SHA-1 Certificate Fingerprint (from Android Studio Gradle signing report)
   - Run Gradle task: `signingReport` to get SHA-1

### Note:
- Without this setup, the Gmail scan will fail or show limited results.
- The app uses `GoogleAccountCredential` to authenticate.

---

## 📱 Quick Setup Summary

### Minimum Setup (Free):
1. ✅ Get **VirusTotal API** key (free)
2. ✅ Get **Google Safe Browsing API** key (free)
3. ✅ Enable both in Settings
4. ✅ You now have full antivirus scanning!

### Full Setup (With AI):
1. ✅ Get all 3 API keys (VirusTotal + Safe Browsing + Gemini)
2. ✅ Enable all in Settings
3. ✅ You now have:
   - ✅ Real-time malware detection
   - ✅ AI-powered security analysis
   - ✅ Smart chatbot assistant

---

## 🔒 Security Notes

- ✅ API keys are stored **securely** in your device (SharedPreferences)
- ✅ Keys are **never** sent to third parties
- ✅ All API calls use **HTTPS encryption**
- ✅ You can disable any API anytime in Settings

---

## ❓ Troubleshooting

### "API key not configured"
- Make sure you toggled the API **ON** in Settings
- Check that you pasted the **full** API key (no spaces)

### "Test Connection Failed"
- Check your **internet connection**
- Verify the API key is **correct**
- For VirusTotal: Make sure you're not exceeding rate limits
- For Gemini: Check if the API key is active in Google AI Studio

---

## 🎉 You're All Set!

Once you've added your API keys, the app will automatically use them for:
- 🔍 **Enhanced malware detection**
- 🤖 **AI-powered security analysis**
- 💬 **Smart chatbot assistant**
- 🛡️ **Real-time threat scanning**
- 📧 **Phishing detection**

Enjoy your secure mobile experience! 🚀
