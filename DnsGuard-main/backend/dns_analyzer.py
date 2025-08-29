import math
from collections import Counter
import requests
from dotenv import load_dotenv
import os

# Load environment variables from .env file
try:
    load_dotenv()
except Exception as e:
    print(f"Warning: Could not load .env file: {e}")
    print("External API checks will be disabled. Create a .env file with API keys for full functionality.")

# Function to calculate entropy of a domain
def calculate_entropy(domain):
    prob = [float(count) / len(domain) for count in Counter(domain).values()]
    entropy = -sum(p * math.log2(p) for p in prob)
    return entropy

# Function to check if a domain has high entropy
def is_high_entropy(domain, threshold=3.5):
    return calculate_entropy(domain) > threshold

# Function to check a domain on VirusTotal
def check_virustotal(domain):
    try:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return False  # Skip if no API key
        
        # Quick check for obvious malicious patterns
        if any(pattern in domain.lower() for pattern in ['malware', 'virus', 'trojan', 'spam', 'phish']):
            return True
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=3)  # Reduced timeout
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return malicious_count > 0  # Return True if malicious
    except Exception as e:
        print(f"VirusTotal API error: {e}")
    return False

# Function to check a URL on Google Safe Browsing
def check_google_safe_browsing(url):
    try:
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        if not api_key:
            return False  # Skip if no API key
        
        # Quick check for obvious phishing patterns
        if any(pattern in url.lower() for pattern in ['phish', 'fake', 'scam', 'login', 'secure']):
            return True
        
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        headers = {"Content-Type": "application/json", "key": api_key}
        response = requests.post(api_url, json=payload, headers=headers, timeout=3)  # Reduced timeout
        if response.status_code == 200:
            data = response.json()
            return len(data.get("matches", [])) > 0  # Return True if threat found
    except Exception as e:
        print(f"Google Safe Browsing API error: {e}")
    return False

# Function to check an IP on AbuseIPDB
def check_abuseipdb(ip):
    try:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return False  # Skip if no API key
        
        # Skip local/private IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return False
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        response = requests.get(url, headers=headers, params=params, timeout=3)  # Reduced timeout
        if response.status_code == 200:
            data = response.json()
            abuse_confidence_score = data.get("data", {}).get("abuseConfidenceScore", 0)
            return abuse_confidence_score > 50  # Return True if confidence score > 50
    except Exception as e:
        print(f"AbuseIPDB API error: {e}")
    return False

# Function to determine threat level with detailed analysis
def get_threat_level(domain, src_ip):
    threat_analysis = {
        "domain": domain,
        "source_ip": src_ip,
        "entropy_score": calculate_entropy(domain),
        "is_high_entropy": is_high_entropy(domain),
        "virustotal_threat": False,
        "google_safe_browsing_threat": False,
        "abuseipdb_threat": False,
        "blocklist_match": False,
        "threat_level": "Low",
        "threat_details": []
    }
    
    # Check against a blocklist
    blocklist = ["malicious.com", "suspicious.com", "test.com"]
    if domain in blocklist:
        threat_analysis["blocklist_match"] = True
        threat_analysis["threat_details"].append("Domain found in local blocklist")
    
    # Check entropy for suspicious domains
    if threat_analysis["is_high_entropy"]:
        threat_analysis["threat_details"].append(f"High entropy domain (score: {threat_analysis['entropy_score']:.2f})")
    
    # Check VirusTotal
    try:
        if check_virustotal(domain):
            threat_analysis["virustotal_threat"] = True
            threat_analysis["threat_details"].append("Domain flagged by VirusTotal")
    except Exception as e:
        threat_analysis["threat_details"].append(f"VirusTotal check failed: {str(e)}")
    
    # Check Google Safe Browsing
    try:
        if check_google_safe_browsing(f"http://{domain}"):
            threat_analysis["google_safe_browsing_threat"] = True
            threat_analysis["threat_details"].append("Domain flagged by Google Safe Browsing")
    except Exception as e:
        threat_analysis["threat_details"].append(f"Google Safe Browsing check failed: {str(e)}")
    
    # Check AbuseIPDB for source IP
    try:
        if check_abuseipdb(src_ip):
            threat_analysis["abuseipdb_threat"] = True
            threat_analysis["threat_details"].append("Source IP flagged by AbuseIPDB")
    except Exception as e:
        threat_analysis["threat_details"].append(f"AbuseIPDB check failed: {str(e)}")
    
    # Determine overall threat level with better logic
    threat_count = sum([
        threat_analysis["blocklist_match"],
        threat_analysis["virustotal_threat"],
        threat_analysis["google_safe_browsing_threat"],
        threat_analysis["abuseipdb_threat"]
    ])
    
    # High threat: Multiple API flags or known malicious domains
    if (threat_count >= 2 or 
        threat_analysis["virustotal_threat"] or 
        threat_analysis["google_safe_browsing_threat"] or
        threat_analysis["blocklist_match"]):
        threat_analysis["threat_level"] = "High"
    # Medium threat: Single API flag or high entropy
    elif (threat_count >= 1 or 
          threat_analysis["is_high_entropy"] or
          threat_analysis["abuseipdb_threat"]):
        threat_analysis["threat_level"] = "Medium"
    # Low threat: No flags detected
    else:
        threat_analysis["threat_level"] = "Low"
    
    return threat_analysis