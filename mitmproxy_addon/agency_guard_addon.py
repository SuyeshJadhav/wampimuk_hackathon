# mitmproxy_addon/agency_guard_addon.py

from mitmproxy import http, ctx
import requests
import json

from . import utils, config

class AgencyGuard:
    """
    Main mitmproxy addon for Agency Guard MVP.
    Intercepts HTTP(S) requests, sends to Risk Engine,
    enforces block/warn/allow decisions.
    """

    def request(self, flow: http.HTTPFlow):
        """
        Called on every HTTP request
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
            response = requests.post(config.RISK_ENGINE_URL, json=payload, timeout=3)
            result = response.json()
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

addons = [AgencyGuard()]
