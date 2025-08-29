# DNS Guard - Real-time Network Vulnerabilities Checker

A real-time DNS monitoring application that detects potential security threats by analyzing DNS queries and checking them against various threat intelligence services.

## Features

- **Real-time DNS Monitoring**: Captures and analyzes DNS queries in real-time
- **Threat Detection**: Uses multiple methods to detect potential threats:
  - Entropy analysis for suspicious domains
  - VirusTotal integration for malware detection
  - Google Safe Browsing for phishing/malware URLs
  - AbuseIPDB for malicious IP addresses
  - Local blocklist checking
- **Interactive Dashboard**: Real-time charts and logs display
- **Web Interface**: Modern React-based frontend with Tailwind CSS

## Prerequisites

- Node.js 18+ and npm
- Python 3.8+
- Administrator privileges (for DNS packet capture)

## Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd DnsGuard-main
```

### 2. Install Frontend Dependencies
```bash
npm install
```

### 3. Install Backend Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 4. Set up Environment Variables (Optional)
The application will work without API keys, but for full functionality:

```bash
cd backend
python setup_env.py
```

Then edit the `.env` file and add your API keys:
- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **Google Safe Browsing**: https://developers.google.com/safe-browsing
- **AbuseIPDB**: https://www.abuseipdb.com/api

## Running the Application

### 1. Start the Backend Server
```bash
cd backend
python app.py
```

The backend will start on `http://localhost:5000`

### 2. Start the Frontend Development Server
In a new terminal:
```bash
npm run dev
```

The frontend will start on `http://localhost:3000`

### 3. Access the Application
Open your browser and navigate to `http://localhost:3000`

## Usage

1. **Start Monitoring**: Click the "Start Fetching" button to begin DNS monitoring
2. **View Real-time Data**: The dashboard will show:
   - Real-time threat level charts
   - DNS query logs with threat assessments
   - Source and destination IP addresses
3. **Stop Monitoring**: Click "Stop Fetching" to halt monitoring

## Troubleshooting

### Common Issues

1. **Permission Denied for DNS Capture**
   - Run the backend with administrator privileges
   - On Windows: Run PowerShell as Administrator

2. **Backend Connection Issues**
   - Ensure the backend is running on port 5000
   - Check if firewall is blocking the connection

3. **API Key Errors**
   - The application works without API keys
   - External threat checking will be disabled
   - Only local detection methods will be active

4. **Build Errors**
   - Ensure all dependencies are installed
   - Check Node.js and Python versions

### Warnings
- The Wireshark warnings about "manuf" are normal and don't affect functionality
- DNS monitoring requires network access and may trigger security software

## Development

### Project Structure
```
DnsGuard-main/
├── app/                 # Next.js app directory
├── components/          # React components
├── backend/            # Python Flask backend
│   ├── app.py         # Main Flask application
│   ├── dns_analyzer.py # Threat analysis logic
│   └── requirements.txt # Python dependencies
├── public/             # Static assets
└── package.json        # Node.js dependencies
```

### Building for Production
```bash
npm run build
npm start
```

## Security Notes

- This application captures DNS traffic for analysis
- API keys should be kept secure and not committed to version control
- The application runs locally and doesn't send data to external servers (except for threat intelligence APIs)

## License

This project is for educational and security research purposes.
