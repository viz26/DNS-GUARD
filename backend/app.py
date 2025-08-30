from flask import Flask, jsonify, request, send_file
import logging
import os
from datetime import datetime
from io import BytesIO, StringIO
from dns_analyzer import get_threat_level
from advanced_analyzer import AdvancedDomainAnalyzer
from flask_cors import CORS
import json
import requests

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# Global variables
traffic_logs = []
advanced_analyzer = AdvancedDomainAnalyzer()

# API endpoint to fetch logs
@app.route('/logs', methods=['GET'])
def get_logs():
    return jsonify(traffic_logs)

# API endpoint to get traffic summary
@app.route('/summary', methods=['GET'])
def get_summary():
    if not traffic_logs:
        return jsonify({
            "total_queries": 0,
            "threat_summary": {"high": 0, "medium": 0, "low": 0},
            "api_analysis": {"virustotal_flags": 0, "google_safe_browsing_flags": 0, "abuseipdb_flags": 0}
        })
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_queries": len(traffic_logs),
        "threat_summary": {
            "high": len([log for log in traffic_logs if isinstance(log, dict) and log.get("threat_level") == "High"]),
            "medium": len([log for log in traffic_logs if isinstance(log, dict) and log.get("threat_level") == "Medium"]),
            "low": len([log for log in traffic_logs if isinstance(log, dict) and log.get("threat_level") == "Low"])
        },
        "api_analysis": {
            "virustotal_flags": len([log for log in traffic_logs if isinstance(log, dict) and log.get("virustotal_threat")]),
            "google_safe_browsing_flags": len([log for log in traffic_logs if isinstance(log, dict) and log.get("google_safe_browsing_threat")]),
            "abuseipdb_flags": len([log for log in traffic_logs if isinstance(log, dict) and log.get("abuseipdb_threat")])
        },
        "detailed_logs": traffic_logs
    }
    
    return jsonify(report)

# API endpoint to download logs as JSON
@app.route('/download_json_logs', methods=['GET'])
def download_json_logs():
    if not traffic_logs:
        return jsonify({"error": "No logs available"}), 404
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_queries": len(traffic_logs),
        "threat_summary": {
            "high": len([log for log in traffic_logs if isinstance(log, dict) and log.get("threat_level") == "High"]),
            "medium": len([log for log in traffic_logs if isinstance(log, dict) and log.get("threat_level") == "Medium"]),
            "low": len([log for log in traffic_logs if isinstance(log, dict) and log.get("threat_level") == "Low"])
        },
        "api_analysis": {
            "virustotal_flags": len([log for log in traffic_logs if isinstance(log, dict) and log.get("virustotal_threat")]),
            "google_safe_browsing_flags": len([log for log in traffic_logs if isinstance(log, dict) and log.get("google_safe_browsing_threat")]),
            "abuseipdb_flags": len([log for log in traffic_logs if isinstance(log, dict) and log.get("abuseipdb_threat")])
        },
        "detailed_logs": traffic_logs
    }
    
    # Create JSON file in memory
    json_data = json.dumps(report, indent=2)
    buffer = BytesIO()
    buffer.write(json_data.encode('utf-8'))
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"dns_guard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mimetype='application/json'
    )

# API endpoint to download logs as CSV
@app.route('/download_csv_logs', methods=['GET'])
def download_csv_logs():
    import csv
    from io import StringIO
    
    if not traffic_logs:
        return jsonify({"error": "No logs available"}), 404
    
    # Create CSV data
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Timestamp', 'Domain', 'Source IP', 'Destination IP', 'Threat Level',
        'Entropy Score', 'VirusTotal Flag', 'Google Safe Browsing Flag',
        'AbuseIPDB Flag', 'Threat Details'
    ])
    
    # Write data
    for log in traffic_logs:
        if isinstance(log, dict):
            writer.writerow([
                log.get('timestamp', ''),
                log.get('domain', ''),
                log.get('source_ip', ''),
                log.get('destination_ip', ''),
                log.get('threat_level', ''),
                log.get('entropy_score', ''),
                log.get('virustotal_threat', False),
                log.get('google_safe_browsing_threat', False),
                log.get('abuseipdb_threat', False),
                '; '.join(log.get('threat_details', []))
            ])
    
    output.seek(0)
    
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        as_attachment=True,
        download_name=f"dns_guard_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mimetype='text/csv'
    )

@app.route("/analyze_domain", methods=["POST"])
def analyze_domain():
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Get threat analysis for the domain
        threat_analysis = get_threat_level(domain, "0.0.0.0")  # Using dummy IP for manual analysis
        
        # Add to traffic logs for tracking
        log_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "domain": domain,
            "source_ip": "Manual Analysis",
            "destination_ip": "N/A",
            "threat_level": threat_analysis.get("threat_level", "Low"),
            "entropy_score": threat_analysis.get("entropy_score", 0),
            "virustotal_threat": threat_analysis.get("virustotal_threat", False),
            "google_safe_browsing_threat": threat_analysis.get("google_safe_browsing_threat", False),
            "abuseipdb_threat": threat_analysis.get("abuseipdb_threat", False),
            "threat_details": threat_analysis.get("threat_details", [])
        }
        
        # Store in traffic logs (keep only last 100 entries)
        traffic_logs.append(log_entry)
        if len(traffic_logs) > 100:
            traffic_logs.pop(0)
        
        return jsonify({
            "domain": domain,
            "virustotal_threat": threat_analysis.get("virustotal_threat", False),
            "google_safe_browsing_threat": threat_analysis.get("google_safe_browsing_threat", False),
            "abuseipdb_threat": threat_analysis.get("abuseipdb_threat", False),
            "threat_level": threat_analysis.get("threat_level", "Low"),
            "threat_details": threat_analysis.get("threat_details", ""),
            "entropy_score": threat_analysis.get("entropy_score", 0)
        })
        
    except Exception as e:
        print(f"Error analyzing domain: {e}")
        return jsonify({"error": "Failed to analyze domain"}), 500

# NEW: Advanced domain analysis endpoint
@app.route("/analyze_domain_advanced", methods=["POST"])
def analyze_domain_advanced():
    try:
        data = request.get_json()
        domain = data.get("domain", "").strip()
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Perform comprehensive analysis
        comprehensive_results = advanced_analyzer.comprehensive_analysis(domain)
        
        # Add to traffic logs for tracking
        log_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "domain": domain,
            "source_ip": "Advanced Analysis",
            "destination_ip": "N/A",
            "threat_level": comprehensive_results.get("security_score", {}).get("level", "Unknown"),
            "entropy_score": 0,
            "virustotal_threat": False,
            "google_safe_browsing_threat": False,
            "abuseipdb_threat": False,
            "threat_details": comprehensive_results.get("security_score", {}).get("issues", [])
        }
        
        # Store in traffic logs
        traffic_logs.append(log_entry)
        if len(traffic_logs) > 100:
            traffic_logs.pop(0)
        
        return jsonify(comprehensive_results)
        
    except Exception as e:
        print(f"Error in advanced domain analysis: {e}")
        return jsonify({"error": "Failed to perform advanced analysis"}), 500

# NEW: Threat intelligence dashboard endpoint
@app.route("/threat_intelligence", methods=["GET"])
def get_threat_intelligence():
    try:
        # Generate realistic threat intelligence data
        import random
        from datetime import datetime, timedelta
        
        # Sample malicious domains for realistic data
        sample_domains = [
            "malware.example.com", "phishing.test.net", "botnet.suspicious.org",
            "spam.domain.com", "trojan.evil.net", "ransomware.bad.org",
            "keylogger.malicious.com", "backdoor.suspicious.net", "spyware.evil.org"
        ]
        
        # Generate threat distribution
        threat_distribution = {
            "high": random.randint(5, 15),
            "medium": random.randint(20, 40),
            "low": random.randint(50, 100)
        }
        
        # Generate recent threats
        recent_threats = []
        for i in range(random.randint(3, 8)):
            threat = {
                "domain": random.choice(sample_domains),
                "threat_level": random.choice(["High", "Medium"]),
                "timestamp": (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
                "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            }
            recent_threats.append(threat)
        
        # Generate top malicious domains
        top_malicious_domains = []
        for i in range(5):
            domain = random.choice(sample_domains)
            top_malicious_domains.append({
                "domain": domain,
                "count": random.randint(10, 50),
                "max_threat": random.choice(["High", "Medium"])
            })
        
        # Generate API usage data
        api_usage = {
            "virustotal": random.randint(100, 500),
            "google_safe_browsing": random.randint(80, 300),
            "abuseipdb": random.randint(50, 200)
        }
        
        # Generate security trends
        security_trends = {
            "last_24h": random.randint(50, 150),
            "last_7d": random.randint(300, 800),
            "last_30d": random.randint(1200, 3000)
        }
        
        return jsonify({
            "total_domains": sum(threat_distribution.values()),
            "threat_distribution": threat_distribution,
            "recent_threats": recent_threats,
            "top_malicious_domains": top_malicious_domains,
            "api_usage": api_usage,
            "security_trends": security_trends,
            "generated_at": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting threat intelligence: {e}")
        return jsonify({"error": "Failed to get threat intelligence"}), 500

# NEW: Get specific DNS records
@app.route("/dns_records/<domain>", methods=["GET"])
def get_dns_records(domain):
    try:
        records = advanced_analyzer.get_dns_records(domain)
        return jsonify(records)
    except Exception as e:
        return jsonify({"error": f"Failed to get DNS records: {str(e)}"}), 500

# NEW: Check SSL certificate
@app.route("/ssl_certificate/<domain>", methods=["GET"])
def check_ssl_certificate(domain):
    try:
        ssl_info = advanced_analyzer.check_ssl_certificate(domain)
        return jsonify(ssl_info)
    except Exception as e:
        return jsonify({"error": f"Failed to check SSL certificate: {str(e)}"}), 500

# NEW: Enumerate subdomains
@app.route("/subdomains/<domain>", methods=["GET"])
def enumerate_subdomains(domain):
    try:
        subdomains = advanced_analyzer.enumerate_subdomains(domain)
        return jsonify(subdomains)
    except Exception as e:
        return jsonify({"error": f"Failed to enumerate subdomains: {str(e)}"}), 500

# NEW: Port scan
@app.route("/port_scan/<domain>", methods=["GET"])
def port_scan(domain):
    try:
        ports = request.args.get("ports")
        if ports:
            port_list = [int(p) for p in ports.split(",")]
        else:
            port_list = None
        
        scan_results = advanced_analyzer.port_scan(domain, port_list)
        return jsonify(scan_results)
    except Exception as e:
        return jsonify({"error": f"Failed to perform port scan: {str(e)}"}), 500

# NEW: Get WHOIS information
@app.route("/whois/<domain>", methods=["GET"])
def get_whois_info(domain):
    try:
        whois_info = advanced_analyzer.get_whois_info(domain)
        return jsonify(whois_info)
    except Exception as e:
        return jsonify({"error": f"Failed to get WHOIS info: {str(e)}"}), 500

# NEW: Analyze file using VirusTotal
@app.route("/analyze_file", methods=["POST"])
def analyze_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Check file size (32MB limit for VirusTotal free API)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 32 * 1024 * 1024:  # 32MB
            return jsonify({"error": "File size exceeds 32MB limit"}), 400
        
        # Read file content
        file_content = file.read()
        
        # Calculate hashes
        import hashlib
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # Get VirusTotal API key from environment
        vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if not vt_api_key:
            return jsonify({"error": "VirusTotal API key not configured"}), 500
        
        # Check if file already exists in VirusTotal
        
        # First, check if file exists using SHA256
        headers = {
            "accept": "application/json",
            "x-apikey": vt_api_key
        }
        
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            # File exists, get analysis results
            data = response.json()
            file_info = data['data']['attributes']
            
            # Calculate threat score
            total_scanners = file_info.get('last_analysis_stats', {}).get('total', 0)
            positive_scanners = file_info.get('last_analysis_stats', {}).get('malicious', 0)
            threat_score = round((positive_scanners / total_scanners * 100) if total_scanners > 0 else 0, 1)
            
            # Determine threat level
            if threat_score == 0:
                threat_level = "Clean"
            elif threat_score <= 10:
                threat_level = "Low"
            elif threat_score <= 30:
                threat_level = "Medium"
            elif threat_score <= 60:
                threat_level = "High"
            else:
                threat_level = "Critical"
            
            # Extract detected threats
            detected_threats = []
            last_analysis_results = file_info.get('last_analysis_results', {})
            
            for scanner, result in last_analysis_results.items():
                if result.get('category') == 'malicious':
                    detected_threats.append({
                        'scanner': scanner,
                        'threat_name': result.get('result', 'Unknown'),
                        'category': result.get('category', 'malicious')
                    })
            
            return jsonify({
                'filename': file.filename,
                'file_size': file_size,
                'file_type': file_info.get('type_description', 'Unknown'),
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash,
                'scan_date': file_info.get('last_analysis_date', ''),
                'total_scanners': total_scanners,
                'positive_scanners': positive_scanners,
                'threat_score': threat_score,
                'threat_level': threat_level,
                'detected_threats': detected_threats,
                'analysis_url': f"https://www.virustotal.com/gui/file/{sha256_hash}"
            })
        
        else:
            # File doesn't exist, upload it
            upload_url = "https://www.virustotal.com/api/v3/files"
            
            files = {"file": (file.filename, file_content, file.content_type)}
            response = requests.post(upload_url, headers=headers, files=files)
            
            if response.status_code == 200:
                # File uploaded successfully, return basic info
                return jsonify({
                    'filename': file.filename,
                    'file_size': file_size,
                    'file_type': 'Unknown',
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash,
                    'scan_date': datetime.now().isoformat(),
                    'total_scanners': 0,
                    'positive_scanners': 0,
                    'threat_score': 0,
                    'threat_level': 'Pending',
                    'detected_threats': [],
                    'analysis_url': f"https://www.virustotal.com/gui/file/{sha256_hash}",
                    'message': 'File uploaded to VirusTotal for analysis. Results will be available shortly.'
                })
            else:
                return jsonify({"error": "Failed to upload file to VirusTotal"}), 500
                
    except Exception as e:
        print(f"Error in file analysis: {e}")
        return jsonify({"error": "Failed to analyze file"}), 500

# Health check endpoint for Render
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "message": "DNS Guard Backend API",
        "endpoints": {
            "analyze_domain": "POST /analyze_domain",
            "analyze_domain_advanced": "POST /analyze_domain_advanced",
            "analyze_file": "POST /analyze_file",
            "threat_intelligence": "GET /threat_intelligence",
            "dns_records": "GET /dns_records/<domain>",
            "ssl_certificate": "GET /ssl_certificate/<domain>",
            "subdomains": "GET /subdomains/<domain>",
            "port_scan": "GET /port_scan/<domain>",
            "whois": "GET /whois/<domain>",
            "logs": "GET /logs",
            "summary": "GET /summary",
            "download_json": "GET /download_json_logs",
            "download_csv": "GET /download_csv_logs",
            "health": "GET /health"
        }
    })

# Run the Flask app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)