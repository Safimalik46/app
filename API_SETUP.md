# API Setup Guide

This app supports integration with security APIs for enhanced malware detection. Follow these steps to enable API features.

## 1. VirusTotal API (Recommended)

VirusTotal provides real-time malware detection using 70+ antivirus engines.

### Steps:
1. Go to https://www.virustotal.com/gui/join-us
2. Create a free account
3. Navigate to https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
4. Copy your API key
5. Open `app/src/main/java/com/security/appdetector/util/VirusTotalApi.kt`
6. Replace `YOUR_API_KEY_HERE` with your actual API key

### Free Tier Limits:
- 500 requests per day
- 4 requests per minute.

## 2. Google Safe Browsing API (Optional)

Google Safe Browsing checks URLs and domains against Google's threat database.

### Steps:
1. Go to https://console.cloud.google.com/
2. Create a new project or select existing
3. Enable "Safe Browsing API"
4. Go to "Credentials" → "Create Credentials" → "API Key"
5. Copy your API key
6. Open `app/src/main/java/com/security/appdetector/util/GoogleSafeBrowsingApi.kt`
7. Replace `YOUR_GOOGLE_API_KEY_HERE` with your actual API key

### Free Tier Limits:
- 10,000 requests per day

## Features Enabled with APIs:

### With VirusTotal API:
- ✅ Real-time file hash scanning
- ✅ Detection by 70+ antivirus engines
- ✅ Malware detection for APK files
- ✅ Threat verdicts (Malicious/Suspicious/Clean)

### With Google Safe Browsing API:
- ✅ URL threat checking
- ✅ Domain reputation checking
- ✅ Phishing detection

## Notes:
- APIs work without keys but will only use local analysis
- API keys are stored in source code (for production, use secure storage)
- Network connection required for API features
- All API calls are made securely over HTTPS

