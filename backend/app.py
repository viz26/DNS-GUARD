from flask import Flask, jsonify, request, send_file
import logging
import os
from datetime import datetime
from io import BytesIO, StringIO
from dns_analyzer import get_threat_level
from flask_cors import CORS
import json

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# Global variables
traffic_logs = []

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
            "logs": "GET /logs",
            "summary": "GET /summary",
            "download_json": "GET /download_json_logs",
            "download_csv": "GET /download_csv_logs",
            "health": "GET /health"
        }
    })

# Run the Flask app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)