#!/usr/bin/env python3
"""
Setup script to create .env file for DNS Guard Backend
"""

import os

def create_env_file():
    """Create a .env file with placeholder values"""
    
    env_content = """# API Keys for external services
# Get your API keys from:
# VirusTotal: https://www.virustotal.com/gui/join-us
# Google Safe Browsing: https://developers.google.com/safe-browsing
# AbuseIPDB: https://www.abuseipdb.com/api

VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
"""
    
    env_file_path = os.path.join(os.path.dirname(__file__), '.env')
    
    if os.path.exists(env_file_path):
        print(f".env file already exists at {env_file_path}")
        response = input("Do you want to overwrite it? (y/N): ")
        if response.lower() != 'y':
            print("Setup cancelled.")
            return
    
    try:
        with open(env_file_path, 'w') as f:
            f.write(env_content)
        print(f".env file created successfully at {env_file_path}")
        print("\nNext steps:")
        print("1. Edit the .env file and replace the placeholder values with your actual API keys")
        print("2. If you don't have API keys, the application will still work with basic threat detection")
        print("3. Restart the backend server after making changes")
    except Exception as e:
        print(f"Error creating .env file: {e}")

if __name__ == "__main__":
    create_env_file()
