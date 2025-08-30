# 🛡️ DNS Guard Pro - Advanced Network Security & Threat Intelligence Platform

A comprehensive cybersecurity platform that combines domain analysis, threat intelligence, and file analysis capabilities to protect against various cyber threats.

## ✨ Features

### 🎯 Threat Intelligence Dashboard
- **Real-time Security Insights**: Live threat analysis and monitoring
- **Threat Distribution**: High, Medium, and Low threat level categorization
- **Recent Threats**: Track latest detected threats with timestamps
- **Top Malicious Domains**: Identify most dangerous domains
- **Security Trends**: 24h, 7-day, and 30-day security analytics

### 🔍 Advanced Domain Analysis
- **Comprehensive DNS Analysis**: A, AAAA, MX, TXT, NS, CNAME records
- **SSL Certificate Analysis**: Certificate validity, issuer, expiration dates
- **Subdomain Enumeration**: Discover hidden subdomains
- **Port Scanning**: Check open ports and services
- **WHOIS Information**: Domain registration details
- **Security Scoring**: Automated threat level assessment

### 📁 Suspicious File Analysis
- **VirusTotal Integration**: Upload and analyze files for malware
- **Multi-Hash Analysis**: MD5, SHA1, SHA256 hash calculation
- **Threat Detection**: Real-time malware scanning results
- **File Information**: Size, type, and detailed analysis
- **Direct VirusTotal Links**: Access full analysis reports

### 🌐 Domain Security Features
- **Multi-API Integration**: VirusTotal, Google Safe Browsing, AbuseIPDB
- **Real-time Threat Detection**: Instant security assessment
- **Comprehensive Logging**: Detailed analysis history
- **Export Capabilities**: JSON and CSV report downloads

## 🚀 Tech Stack

### Frontend
- **Next.js 14**: React framework with App Router
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Modern styling
- **Responsive Design**: Mobile-first approach

### Backend
- **Flask**: Python web framework
- **DNS Analysis**: dnspython library
- **SSL Analysis**: cryptography library
- **WHOIS Lookup**: python-whois library
- **File Analysis**: VirusTotal API integration
- **CORS Support**: Cross-origin resource sharing

### APIs & Services
- **VirusTotal API**: File and domain threat analysis
- **Google Safe Browsing API**: URL threat detection
- **AbuseIPDB API**: IP reputation checking
- **DNS Services**: Comprehensive DNS record analysis

## 🏗️ Architecture

```
DNS Guard Pro
├── Frontend (Next.js)
│   ├── Threat Intelligence Dashboard
│   ├── Advanced Domain Analysis
│   ├── File Analysis Interface
│   └── Responsive UI Components
├── Backend (Flask)
│   ├── Domain Analysis Engine
│   ├── File Analysis Service
│   ├── Threat Intelligence API
│   └── Multi-API Integration
└── External APIs
    ├── VirusTotal
    ├── Google Safe Browsing
    └── AbuseIPDB
```

## 🛠️ Installation & Setup

### Prerequisites
- Node.js 18+ and npm
- Python 3.8+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/viz26/DNS-GUARD.git
cd DNS-GUARD
```

### 2. Frontend Setup
```bash
npm install
npm run dev
```

### 3. Backend Setup
```bash
cd backend
pip install -r requirements.txt
python app.py
```

### 4. Environment Variables

#### Frontend (.env.local)
```env
NEXT_PUBLIC_BACKEND_URL=http://localhost:8000
```

#### Backend Environment Variables
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

## 🌐 Deployment

### Vercel (Frontend)
1. Connect your GitHub repository to Vercel
2. Set environment variables in Vercel dashboard
3. Deploy automatically on push to main branch

### Render (Backend)
1. Create new Web Service on Render
2. Connect GitHub repository
3. Set build command: `pip install -r backend/requirements.txt`
4. Set start command: `cd backend && gunicorn app:app --bind 0.0.0.0:$PORT`
5. Add environment variables

## 📊 API Endpoints

### Domain Analysis
- `POST /analyze_domain` - Basic domain analysis
- `POST /analyze_domain_advanced` - Comprehensive domain analysis
- `GET /dns_records/<domain>` - DNS record lookup
- `GET /ssl_certificate/<domain>` - SSL certificate analysis
- `GET /subdomains/<domain>` - Subdomain enumeration
- `GET /port_scan/<domain>` - Port scanning
- `GET /whois/<domain>` - WHOIS information

### File Analysis
- `POST /analyze_file` - File upload and analysis

### Threat Intelligence
- `GET /threat_intelligence` - Threat intelligence dashboard data

### Logs & Reports
- `GET /logs` - Analysis logs
- `GET /summary` - Traffic summary
- `GET /download_json_logs` - Export logs as JSON
- `GET /download_csv_logs` - Export logs as CSV

## 🔧 Configuration

### API Keys Setup
1. **VirusTotal**: Get free API key from [virustotal.com](https://www.virustotal.com)
2. **Google Safe Browsing**: Enable API in Google Cloud Console
3. **AbuseIPDB**: Register at [abuseipdb.com](https://www.abuseipdb.com)

### File Size Limits
- **VirusTotal**: 32MB maximum file size for free API
- **Supported Formats**: All file types

## 📈 Usage Examples

### Domain Analysis
```bash
curl -X POST http://localhost:8000/analyze_domain_advanced \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### File Analysis
```bash
curl -X POST http://localhost:8000/analyze_file \
  -F "file=@suspicious_file.exe"
```

## 🛡️ Security Features

- **CORS Protection**: Cross-origin request handling
- **Input Validation**: Comprehensive input sanitization
- **Error Handling**: Graceful error management
- **Rate Limiting**: API usage protection
- **Secure File Upload**: File type and size validation

## 📱 User Interface

### Modern Dashboard
- **Real-time Updates**: Live threat intelligence
- **Interactive Charts**: Visual security metrics
- **Responsive Design**: Works on all devices
- **Dark/Light Theme**: User preference support

### Analysis Tools
- **Domain Scanner**: Comprehensive domain analysis
- **File Analyzer**: Malware detection interface
- **Threat Intelligence**: Security insights dashboard

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Developer

**Developed by Vidit Purohit**
- Cybersecurity Engineer & Full-Stack Developer
- Specialized in Network Security & Threat Intelligence

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review API documentation

## 🔄 Version History

### v2.0.0 (Current)
- ✅ Advanced Domain Analysis
- ✅ Threat Intelligence Dashboard
- ✅ File Analysis with VirusTotal
- ✅ Enhanced UI/UX
- ✅ Multi-API Integration
- ✅ Comprehensive Logging

### v1.0.0
- ✅ Basic DNS Analysis
- ✅ Simple Threat Detection
- ✅ Basic UI

---

**DNS Guard Pro** - Your comprehensive cybersecurity companion! 🛡️✨
