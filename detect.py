from mitmproxy import http
import re

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

def request(flow: http.HTTPFlow):
    if flow.request.method == "POST":
        try:
            body = flow.request.get_text()
        except:
            return

        if SSN_RE.search(body):
            print("🚨 SSN DETECTED — Blocking request")

            flow.response = http.Response.make(
                403,
                b"Sensitive data detected. Request blocked.",
                {"Content-Type": "text/plain"}
            )
