# mitmproxy_addon/agency_guard_addon.py

from mitmproxy import http, ctx
import requests
import json

import utils 
import config

import uuid
import time

# Temporary store for approved requests
# { request_id: {"url": ..., "expires": timestamp} }
TEMP_APPROVALS = {}

def generate_interstitial_html(decision, score, domain, reason, allow_override, request_id):
    button_html = ""
    if allow_override:
        button_html = f"""
        <form method="GET" action="/agencyguard/proceed">
            <input type="hidden" name="id" value="{request_id}" />
            <button type="submit" style="padding:10px 20px;">
                Proceed Anyway
            </button>
        </form>
        """

    html = f"""
    <html>
    <head>
        <title>AgencyGuard Decision</title>
    </head>
    <body style="font-family: Arial; text-align:center; margin-top:100px;">
        <h1>{decision}</h1>
        <h2>Domain: {domain}</h2>
        <p>Risk Score: {score}</p>
        <p>Details: {reason}</p>
        <p>Please check the AgencyGuard Dashboard for full analysis.</p>
        {button_html}
    </body>
    </html>
    """

    return html.encode("utf-8")


class AgencyGuard:
    """
    Main mitmproxy addon for Agency Guard MVP.
    Intercepts HTTP(S) requests, sends to Risk Engine,
    enforces block/warn/allow decisions.
    """

    def request(self, flow: http.HTTPFlow):

        # -------------------------
        # 1️⃣ Handle Proceed Endpoint
        # -------------------------
        if flow.request.path.startswith("/agencyguard/proceed"):
            request_id = flow.request.query.get("id")

            if request_id and request_id in TEMP_APPROVALS:
                original_flow = TEMP_APPROVALS[request_id]["flow"]

                ctx.log.info(f"[USER APPROVED] Replaying request {request_id}")

                # Replay original request
                original_flow.request.headers["X-AgencyGuard-Approved"] = "true"
                ctx.master.commands.call("replay.client", [original_flow])

                flow.response = http.Response.make(
                    200,
                    b"<h2>Request Approved. Please wait...</h2>",
                    {"Content-Type": "text/html"}
                )
            else:
                flow.response = http.Response.make(
                    400,
                    b"<h2>Invalid approval request.</h2>",
                    {"Content-Type": "text/html"}
                )
            return

        # -------------------------
        # 2️⃣ Skip if already approved
        # -------------------------
        if flow.request.headers.get("X-AgencyGuard-Approved") == "true":
            return

        # -------------------------
        # 3️⃣ Normal Inspection
        # -------------------------
        """
        Called on every HTTP request
        """
        # print("Start analysis")
        try:
            url = flow.request.pretty_url
            method = flow.request.method
            headers = dict(flow.request.headers)
            body = flow.request.get_text(strict=False)
        except Exception as e:
            ctx.log.warn(f"Failed to read request: {e}")
            return

        domain = utils.extract_domain(url)
        normalized_url = utils.normalize_url(url)

        # Detect sensitive keywords in body (quick local scan)
        keywords_found = []
        if config.ENABLE_DLP and body:
            keywords_found = utils.detect_sensitive_keywords(body, config.DLP_ALERT_KEYWORDS)

        # Parse multipart files (metadata only)
        files_info = []
        content_type = headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            files_info = utils.parse_multipart_form(flow.request.raw_content, content_type)["files"]

        # Prepare payload to Risk Engine
        payload = {
            "domain": domain,
            "url": normalized_url,
            "method": method,
            "headers": headers,
            "body": body,
            "keywords_found": keywords_found,
            "files": files_info
        }
  
        try:
            response = requests.post(
            config.RISK_ENGINE_URL,
            json=payload,
            timeout=3,
            proxies={"http": None, "https": None}
            )   
            result = response.json()
            ctx.log.info(result)
        except Exception as e:
            ctx.log.warn(f"Failed to call Risk Engine: {e}")
            result = {"decision": "ALLOW", "score": 0, "details": {}}

        # Enforce decision
        decision = result.get("decision", "ALLOW")
        score = result.get("score", 0)
        details = result.get("details", {})

        # -------------------------
        # 4️⃣ Enforcement
        # -------------------------
        if decision == "BLOCK":
            flow.response = http.Response.make(
                403,
                generate_interstitial_html(
                    decision="BLOCK",
                    score=score,
                    domain=domain,
                    reason=details,
                    allow_override=False,
                    request_id=""
                ),
                {"Content-Type": "text/html"}
            )

        elif decision == "WARN":
            request_id = str(uuid.uuid4())

            # Store original flow
            TEMP_APPROVALS[request_id] = {
                "flow": flow.copy()
            }

            flow.response = http.Response.make(
                200,
                generate_interstitial_html(
                    decision="WARN",
                    score=score,
                    domain=domain,
                    reason=details,
                    allow_override=True,
                    request_id=request_id
                ),
                {"Content-Type": "text/html"}
            )

        else:
            ctx.log.info(f"[ALLOWED] {domain}")

addons = [AgencyGuard()]
