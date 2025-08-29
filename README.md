DNS Guard - Real-time Network Vulnerabilities Checker
A real-time DNS monitoring application that detects potential security threats by analyzing DNS queries and checking them against various threat intelligence services.

Features
Real-time DNS Monitoring: Captures and analyzes DNS queries in real-time
Threat Detection: Uses multiple methods to detect potential threats:
Entropy analysis for suspicious domains
VirusTotal integration for malware detection
Google Safe Browsing for phishing/malware URLs
AbuseIPDB for malicious IP addresses
Local blocklist checking
Interactive Dashboard: Real-time charts and logs display
Web Interface: Modern React-based frontend with Tailwind CSS
Prerequisites
Node.js 18+ and npm
Python 3.8+
Administrator privileges (for DNS packet capture)
Installation
1. Clone the repository
git clone <repository-url>
cd DnsGuard-main
2. Install Frontend Dependencies
npm install
3. Install Backend Dependencies
cd backend
pip install -r requirements.txt
4. Set up Environment Variables
The app can run without API keys (external checks disabled). For full functionality:

Frontend (Next.js) – create .env.local at repo root (or copy from example):

# .env.example (copy to .env.local for local dev)
NEXT_PUBLIC_BACKEND_URL=http://localhost:5000
Backend (Flask) – create backend/.env (or copy from example) and fill values:

# backend/.env.example (copy to backend/.env and fill values)
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
ABUSEIPDB_API_KEY=

# Optional
FLASK_ENV=development
PORT=5000
You can also auto-generate a starter backend .env:

cd backend
python setup_env.py
Then add your API keys:

VirusTotal: https://www.virustotal.com/gui/join-us
Google Safe Browsing: https://developers.google.com/safe-browsing
AbuseIPDB: https://www.abuseipdb.com/api
Running the Application
1. Start the Backend Server
cd backend
python app.py
The backend will start on http://localhost:5000

2. Start the Frontend Development Server
In a new terminal:

npm run dev
The frontend will start on http://localhost:3000

3. Access the Application
Open your browser and navigate to http://localhost:3000

Deploying
Deploy frontend to Vercel
The frontend can be deployed to Vercel. Real-time packet monitoring will not run on Vercel, but the Manual Domain Analysis works if it points to a reachable backend.

Push this repository to GitHub (fork or your own repo).
Import the repo in Vercel and select the Next.js app.
In Vercel Project Settings → Environment Variables, add:
NEXT_PUBLIC_BACKEND_URL = URL of your hosted backend (e.g., Railway)
Deploy.
Notes:

In production, the app avoids real-time fetching if the backend isn’t reachable.
Set a valid backend URL to enable Manual Domain Analysis in production.
Deploy backend to Railway (or your server)
Packet sniffing requires low-level network access and typically won’t work on managed hosts. You can still deploy the backend to expose the /analyze_domain endpoint for manual checks.

Create a new project on Railway (or similar PaaS).
Deploy the backend/ folder (Python/Flask).
Set environment variables in your service:
VIRUSTOTAL_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY
ABUSEIPDB_API_KEY
Expose port 5000 and obtain your public service URL.
In Vercel, set NEXT_PUBLIC_BACKEND_URL to this backend URL.
Usage
Start Monitoring: Click the "Start Fetching" button to begin DNS monitoring
View Real-time Data: The dashboard will show:
Real-time threat level charts
DNS query logs with threat assessments
Source and destination IP addresses
Stop Monitoring: Click "Stop Fetching" to halt monitoring
Troubleshooting
Common Issues
Permission Denied for DNS Capture

Run the backend with administrator privileges
On Windows: Run PowerShell as Administrator
Backend Connection Issues

Ensure the backend is running on port 5000
Check if firewall is blocking the connection
API Key Errors

The application works without API keys
External threat checking will be disabled
Only local detection methods will be active
Build Errors

Ensure all dependencies are installed
Check Node.js and Python versions
Warnings
The Wireshark warnings about "manuf" are normal and don't affect functionality
DNS monitoring requires network access and may trigger security software
Development
Project Structure
DnsGuard-main/
├── app/                 # Next.js app directory
├── components/          # React components
├── backend/            # Python Flask backend
│   ├── app.py         # Main Flask application
│   ├── dns_analyzer.py # Threat analysis logic
│   └── requirements.txt # Python dependencies
├── public/             # Static assets
└── package.json        # Node.js dependencies
Building for Production
npm run build
npm start
Security Notes
This application captures DNS traffic for analysis
API keys should be kept secure and not committed to version control
The application runs locally and doesn't send data to external servers (except for threat intelligence APIs)
License
This project is for educational and security research purposes.
