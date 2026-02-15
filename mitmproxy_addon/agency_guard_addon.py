# mitmproxy_addon/agency_guard_addon.py

from mitmproxy import http, ctx
import requests
import json

import utils
import config

class AgencyGuard:
    """
    Main mitmproxy addon for Agency Guard MVP.
    Intercepts HTTP(S) requests, sends to Risk Engine,
    enforces block/warn/allow decisions.
    """

    def request(self, flow: http.HTTPFlow):
        """
        Called on every HTTP request — DLP + Rookie Score analysis.
        """
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
        if decision == "BLOCK":
            ctx.log.info(f"[BLOCKED] {domain} | {method} {normalized_url}")
            flow.response = http.Response.make(
                403,
                b"<h1>Blocked by AgencyGuard</h1>",
                {"Content-Type": "text/html"}
            )
        elif decision == "WARN":
            ctx.log.info(f"[WARNING] {domain} | {method} {normalized_url}")
            # Optionally inject warning in response or log only
        else:
            ctx.log.info(f"[ALLOWED] {domain} | {method} {normalized_url}")


    def response(self, flow: http.HTTPFlow):
        """
        Called on every HTTP response.
        Detects T&C / Privacy Policy pages by analyzing the CONTENT
        of the response (not just the URL), then sends to Risk Engine
        for clause-level risk analysis.
        """
        if not config.ENABLE_TNC_ANALYSIS:
            return

        # Only analyze HTML responses
        content_type = flow.response.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return

        # Skip non-200 responses
        if flow.response.status_code != 200:
            return

        try:
            html_body = flow.response.get_text(strict=False) or ""
        except Exception:
            return

        # Don't process tiny or huge pages
        if len(html_body) < 500 or len(html_body) > 500_000:
            return

        url = flow.request.pretty_url
        domain = utils.extract_domain(url)

        # Strip HTML to plain text
        plain_text = utils.strip_html_to_text(html_body)

        # ── Content-based detection ──────────────────────────────────
        # Check if this page IS a T&C / privacy document based on
        # its actual content — works regardless of URL structure.
        if not utils.is_tnc_page(url, plain_text):
            return

        ctx.log.info(f"[TNC DETECTED] {domain} | {url}")

        # Send to Risk Engine for clause analysis
        payload = {
            "url": url,
            "domain": domain,
            "tnc_text": plain_text[:50_000],  # Cap at 50k chars
        }

        try:
            resp = requests.post(
                config.TNC_ENGINE_URL,
                json=payload,
                timeout=5,
                proxies={"http": None, "https": None}
            )
            result = resp.json()
            status = result.get("status", "UNKNOWN")
            score = result.get("tnc_score", 0)

            ctx.log.info(
                f"[TNC RESULT] {domain} | Status: {status} | Score: {score}"
            )

            # Log individual findings
            for finding in result.get("findings", []):
                ctx.log.info(
                    f"  ⚠ {finding['category']}: risk={finding['risk_level']}, "
                    f"count={finding['count']}"
                )

        except Exception as e:
            ctx.log.warn(f"Failed to send TnC analysis: {e}")


addons = [AgencyGuard()]
