# mitmproxy_addon/agency_guard_addon.py

from mitmproxy import http, ctx
import requests
import os
import sys
from urllib.parse import unquote_plus

ADDON_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ADDON_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from . import utils, config
except ImportError:
    # mitmproxy loads addon scripts outside package context.
    if ADDON_DIR not in sys.path:
        sys.path.insert(0, ADDON_DIR)
    import utils  # type: ignore
    import config  # type: ignore

try:
    # Optional local fallback so POST+DLP can be enforced even if risk call fails.
    from risk_engine.dlp_scanner import DLPScanner  # type: ignore
except Exception:
    DLPScanner = None  # type: ignore

class AgencyGuard:
    """
    Main mitmproxy addon for Agency Guard MVP.
    Intercepts HTTP(S) requests, sends to Risk Engine,
    enforces block/warn/allow decisions.
    """

    def __init__(self):
        # Avoid proxy loops: don't inherit HTTP(S)_PROXY env vars for internal Risk Engine calls.
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.proxies = {"http": "", "https": ""}
        self.local_dlp = DLPScanner() if DLPScanner else None

    def load(self, loader):
        ctx.log.info(
            f"AgencyGuard loaded | risk_engine={config.RISK_ENGINE_URL} | "
            f"trust_env={self.http.trust_env} | local_dlp={'on' if self.local_dlp else 'off'}"
        )

    def request(self, flow: http.HTTPFlow):
        """
        Called on every HTTP request
        """
        try:
            url = flow.request.pretty_url
            method = flow.request.method
            headers = dict(flow.request.headers)
            body = flow.request.get_text(strict=False) or ""
            raw = flow.request.raw_content or b""
            content_type = headers.get("content-type", "").lower()

            # For write-like requests, prefer raw bytes decode for form payload reliability.
            if method.upper() in {"POST", "PUT", "PATCH"} and raw:
                if (
                    "application/x-www-form-urlencoded" in content_type
                    or "application/json" in content_type
                    or "text/plain" in content_type
                ):
                    body = raw.decode("utf-8", errors="ignore")
                elif not body:
                    body = raw.decode("utf-8", errors="ignore")
        except Exception as e:
            ctx.log.warn(f"Failed to read request: {e}")
            return

        domain = utils.extract_domain(url)
        normalized_url = utils.normalize_url(url)
        if "application/x-www-form-urlencoded" in content_type and body:
            body = unquote_plus(body)
        body_len = len(body.encode("utf-8")) if body else 0

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
        ctx.log.info(
            f"[REQ] {method} {normalized_url} | domain={domain} | body_bytes={body_len} | "
            f"keywords={len(keywords_found)} | files={len(files_info)}"
        )

        # Local hard block for POST with sensitive payload.
        if method.upper() == "POST" and body and self.local_dlp is not None:
            local = self.local_dlp.scan(body)
            local_findings = local.get("findings", [])
            if local_findings:
                score = 100
                decision = "BLOCK"
                flow.metadata["agencyguard_decision"] = decision
                flow.metadata["agencyguard_score"] = score
                flow.comment = f"AgencyGuard {decision} score={score} (local DLP)"
                ctx.log.info(
                    f"[BLOCKED-LOCAL-DLP] {domain} | {method} {normalized_url} | "
                    f"findings={len(local_findings)}"
                )
                flow.response = http.Response.make(
                    403,
                    b"<h1>Blocked by AgencyGuard (DLP)</h1>",
                    {
                        "Content-Type": "text/html",
                        "X-AgencyGuard-Decision": decision,
                        "X-AgencyGuard-Score": str(score),
                    },
                )
                return

        try:
            response = self.http.post(
                config.RISK_ENGINE_URL,
                json=payload,
                timeout=(1.0, 4.0),
                proxies={"http": "", "https": ""},
            )
            result = response.json()
        except Exception as e:
            ctx.log.warn(f"Failed to call Risk Engine ({config.RISK_ENGINE_URL}): {e!r}")
            result = {"decision": "ALLOW", "score": 0, "details": {}}

        # Enforce decision
        decision = result.get("decision", "ALLOW")
        score = result.get("score", 0)
        flow.metadata["agencyguard_decision"] = decision
        flow.metadata["agencyguard_score"] = score
        flow.comment = f"AgencyGuard {decision} score={score}"
        ctx.log.info(
            f"[RISK] decision={decision} score={score} | domain={domain} | method={method} | url={normalized_url}"
        )
        if decision == "BLOCK":
            ctx.log.info(f"[BLOCKED] {domain} | {method} {normalized_url}")
            flow.response = http.Response.make(
                403,
                b"<h1>Blocked by AgencyGuard</h1>",
                {
                    "Content-Type": "text/html",
                    "X-AgencyGuard-Decision": decision,
                    "X-AgencyGuard-Score": str(score),
                }
            )
        elif decision == "WARN":
            ctx.log.info(f"[WARNING] {domain} | {method} {normalized_url}")
            # Optionally inject warning in response or log only
        else:
            ctx.log.info(f"[ALLOWED] {domain} | {method} {normalized_url}")

    def response(self, flow: http.HTTPFlow):
        decision = flow.metadata.get("agencyguard_decision")
        score = flow.metadata.get("agencyguard_score")
        if not decision or flow.response is None:
            return
        flow.response.headers["X-AgencyGuard-Decision"] = str(decision)
        flow.response.headers["X-AgencyGuard-Score"] = str(score)

addons = [AgencyGuard()]
