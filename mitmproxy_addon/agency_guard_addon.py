# mitmproxy_addon/agency_guard_addon.py

from mitmproxy import http, ctx
import requests
from urllib.parse import urlparse

import utils
import config


class AgencyGuard:
    """
    Main mitmproxy addon for Agency Guard MVP.
    Intercepts HTTP(S) requests, sends to Risk Engine,
    enforces block/warn/allow decisions.
    """

    def _is_noise(self, flow: http.HTTPFlow, url: str, method: str, headers: dict) -> bool:
        """
        Return True when this request should be ignored by AgencyGuard.
        """
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = (parsed.path or "").lower()
        content_type = (headers.get("content-type") or "").lower()

        # Explicit opt-out for known noisy dashboard calls
        if (headers.get(config.IGNORE_HEADER) or "").strip() == "1":
            return True

        # Ignore local infra traffic (dashboard, API, risk engine, etc.)
        if hostname in config.IGNORE_HOSTS or netloc in config.IGNORE_NETLOCS:
            return True

        # Ignore static assets and framework/dev-server plumbing
        if any(path.startswith(prefix) for prefix in config.IGNORE_PATH_PREFIXES):
            return True
        if any(path.endswith(ext) for ext in config.IGNORE_FILE_EXTENSIONS):
            return True

        # Only inspect data-leaving request methods
        if method.upper() not in config.ANALYZE_METHODS:
            return True

        # Ignore non-textual bodies to reduce noise and CPU work
        text_types = (
            "application/x-www-form-urlencoded",
            "application/json",
            "text/",
            "multipart/form-data",
        )
        if not any(t in content_type for t in text_types):
            return True

        return False

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

        if self._is_noise(flow, url, method, headers):
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

addons = [AgencyGuard()]
