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

# Noise filtering for mitmproxy addon
# Requests matching these rules are ignored before risk evaluation.
IGNORE_HOSTS = {
    "127.0.0.1",
    "localhost",
}
IGNORE_NETLOCS = {
    "127.0.0.1:8000",  # Risk engine itself
    "localhost:8000",
    "127.0.0.1:3000",  # Common dashboard dev ports
    "localhost:3000",
    "127.0.0.1:5173",
    "localhost:5173",
}
IGNORE_PATH_PREFIXES = (
    "/health",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/favicon.ico",
    "/sockjs-node",
    "/@vite",
)
IGNORE_FILE_EXTENSIONS = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
)

# Methods to inspect. Include GET if you also want to analyze query-based leakage.
ANALYZE_METHODS = {"GET", "POST", "PUT", "PATCH"}

# Allow client apps to explicitly bypass analysis for noisy calls.
# Example header from dashboard: X-AgencyGuard-Ignore: 1
IGNORE_HEADER = "x-agencyguard-ignore"
