# mitmproxy_addon/config.py

# Proxy configuration
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

# Thresholds
ROOKIE_SCORE_THRESHOLD = 30  # days
DLP_ALERT_KEYWORDS = ["SSN", "API_KEY", "CONFIDENTIAL"]

# Feature toggles
ENABLE_DLP = True
ENABLE_TNC_ANALYSIS = True

# Risk Engine API URL
RISK_ENGINE_URL = "http://127.0.0.1:8000/evaluate"