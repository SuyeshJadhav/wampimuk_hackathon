from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sys
import os
import json
import logging
from pathlib import Path
from io import BytesIO
from datetime import datetime

# Adjust Python path to import parent modules
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent
sys.path.append(str(project_root))

from file_analysis import extract_text_from_pdf, redact_text, generate_redacted_pdf
from risk_engine.tnc_analysis import TnCAnalyzer

app = Flask(__name__)
CORS(app)  # Enable CORS for renderer to fetch from localhost:5000

# Constants
INTERCEPT_LOG_PATH = project_root / 'mitmproxy_addon' / 'intercept_log.json'
UPLOAD_FOLDER = project_root / 'data' / 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Risk Engine Instance
tnc_analyzer = TnCAnalyzer()

# Configure logging
logging.basicConfig(level=logging.INFO)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    """Reads latest traffic logs from intercept_log.json"""
    try:
        if INTERCEPT_LOG_PATH.exists():
            with open(INTERCEPT_LOG_PATH, 'r') as f:
                logs = json.load(f)
            # Return last 50 logs
            return jsonify(logs[-50:][::-1])
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-pdf', methods=['POST'])
def scan_pdf():
    """
    Accepts PDF file upload.
    Returns extracted text + auto-detected sensitive findings.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        pdf_bytes = file.read()
        
        # 1. Extract Text
        result = extract_text_from_pdf(pdf_bytes)
        if result.get("error"):
            return jsonify(result), 400

        text = result["text"]
        
        # 2. Auto-detect findings (Basic regex for demo)
        import re
        findings = []
        patterns = {
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "SSN": r'\d{3}-\d{2}-\d{4}',
            "API Key": r'sk_[a-zA-Z0-9]+',
            "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
        
        for p_name, p_val in patterns.items():
            matches = list(set(re.findall(p_val, text)))
            for m in matches:
                findings.append({"type": p_name, "value": m})

        return jsonify({
            "text_preview": text[:500] + "...",
            "page_count": result["page_count"],
            "findings": findings,
            "metadata": result.get("metadata", {})
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze-tnc', methods=['POST'])
def analyze_tnc():
    """Analyzes text for risky clauses."""
    data = request.json
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "No text provided"}), 400

    try:
        result = tnc_analyzer.analyze_text(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logging.info("Starting Flask API on port 5000...")
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
