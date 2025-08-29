from flask import Flask, jsonify, request, send_file
from scapy.all import sniff, DNS, IP
import threading
import logging
import os
from datetime import datetime
from io import BytesIO, StringIO
from dns_analyzer import get_threat_level
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(filename="logs/dns_guard.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Global variables
is_monitoring = False
traffic_logs = []

# Function to handle DNS packets
def dns_packet_handler(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if packet.haslayer(DNS) and packet[DNS].qd:
                dns_layer = packet[DNS]
                domain = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                
                # Skip local/private IPs and common domains to reduce noise
                if (src_ip.startswith(('127.', '192.168.', '10.', '172.')) or 
                    domain in ['localhost', 'local', 'home.arpa'] or
                    len(domain) < 3):
                    return
                
                # Check if we already processed this domain recently (within last 30 seconds)
                current_time = datetime.now()
                recent_logs = [log for log in traffic_logs[-10:] if isinstance(log, dict)]
                for recent_log in recent_logs:
                    if (recent_log.get('domain') == domain and 
                        recent_log.get('source_ip') == src_ip):
                        # Skip duplicate entries
                        return
                
                # Get threat analysis with optimized processing
                threat_analysis = get_threat_level(domain, src_ip)
                threat_level = threat_analysis["threat_level"]
                
                # Create detailed log entry
                log_entry = {
                    "timestamp": current_time.strftime("%H:%M:%S"),
                    "domain": domain,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "threat_level": threat_level,
                    "entropy_score": threat_analysis["entropy_score"],
                    "virustotal_threat": threat_analysis["virustotal_threat"],
                    "google_safe_browsing_threat": threat_analysis["google_safe_browsing_threat"],
                    "abuseipdb_threat": threat_analysis["abuseipdb_threat"],
                    "threat_details": threat_analysis["threat_details"]
                }
                
                # Store in traffic logs (keep only last 100 entries to prevent memory issues)
                traffic_logs.append(log_entry)
                if len(traffic_logs) > 100:
                    traffic_logs.pop(0)
                
                # Log to file
                logging.info(f"DNS Query: {domain} from {src_ip} - Threat Level: {threat_level}")
    except Exception as e:
        print(f"Error processing DNS packet: {e}")

# Function to start DNS monitoring
def start_monitoring():
    global is_monitoring
    if not is_monitoring:
        is_monitoring = True
        threading.Thread(target=sniff, kwargs={"filter": "udp port 53", "prn": dns_packet_handler}).start()

# Function to stop DNS monitoring
def stop_monitoring():
    global is_monitoring
    is_monitoring = False

# API endpoint to start monitoring
@app.route('/start', methods=['POST'])
def start():
    start_monitoring()
    return jsonify({"status": "started"})

# API endpoint to stop monitoring
@app.route('/stop', methods=['POST'])
def stop():
    stop_monitoring()
    return jsonify({"status": "stopped"})

# API endpoint to fetch logs
@app.route('/logs', methods=['GET'])
def logs():
    return jsonify(traffic_logs)

# API endpoint to download logs
@app.route('/download_logs', methods=['GET'])
def download_logs():
    log_file_path = 'logs/dns_guard.log'
    if os.path.exists(log_file_path):
        return send_file(log_file_path, as_attachment=True)
    else:
        return "Log file not found", 404

# API endpoint to download detailed logs as JSON
@app.route('/download_detailed_logs', methods=['GET'])
def download_detailed_logs():
    import json
    from io import BytesIO
    
    # Create detailed JSON report
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

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)