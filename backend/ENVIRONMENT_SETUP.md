# Environment Setup for DNS Guard Backend

## Required Environment Variables

Create a `.env` file in the `backend` directory with the following variables:

```env
# API Keys for external services
# Get your API keys from:
# VirusTotal: https://www.virustotal.com/gui/join-us
# Google Safe Browsing: https://developers.google.com/safe-browsing
# AbuseIPDB: https://www.abuseipdb.com/api

VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

## How to get API keys:

1. **VirusTotal API Key**: 
   - Go to https://www.virustotal.com/gui/join-us
   - Sign up for a free account
   - Get your API key from your profile

2. **Google Safe Browsing API Key**:
   - Go to https://developers.google.com/safe-browsing
   - Enable the Safe Browsing API
   - Create credentials and get your API key

3. **AbuseIPDB API Key**:
   - Go to https://www.abuseipdb.com/api
   - Sign up for a free account
   - Get your API key from your account settings

## Note:
- The application will work without these API keys, but external threat checking will be disabled
- Only entropy-based detection and local blocklist checking will be active
- You can add domains to the blocklist in `dns_analyzer.py` for local threat detection
