from mitmproxy import http, ctx
import json
import os
from datetime import datetime

LOG_FILE = "intercept_log.json"

def log_event(data):
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

    with open(LOG_FILE, "r+") as f:
        existing = json.load(f)
        existing.append(data)
        f.seek(0)
        json.dump(existing, f, indent=2)


class SurfaceInspector:

    def request(self, flow: http.HTTPFlow):

        try:
            body_text = flow.request.get_text(strict=False)
        except:
            body_text = None

        content_type = flow.request.headers.get("content-type", "")

        log_data = {
            "timestamp": str(datetime.utcnow()),

            # Domain / Network
            "domain": flow.request.host,
            "port": flow.request.port,
            "scheme": flow.request.scheme,
            "full_url": flow.request.pretty_url,
            "client_ip": flow.client_conn.address[0] if flow.client_conn.address else None,
            "server_ip": flow.server_conn.ip_address if flow.server_conn else None,

            # HTTP
            "method": flow.request.method,
            "http_version": flow.request.http_version,
            "headers": dict(flow.request.headers),
            "query_params": dict(flow.request.query),
            "cookies": dict(flow.request.cookies),

            # Body
            "content_type": content_type,
            "content_length": flow.request.headers.get("content-length"),
            "body_preview": body_text[:1000] if body_text else None,

            # Raw size
            "raw_body_size_bytes": len(flow.request.raw_content)
            if flow.request.raw_content else 0,
        }

        # Detect multipart uploads
        if "multipart/form-data" in content_type:
            log_data["multipart_detected"] = True

        # Detect JSON payload
        if "application/json" in content_type:
            try:
                log_data["json_body"] = json.loads(body_text)
            except:
                log_data["json_body"] = "invalid_json"

        # Detect form submission
        if "application/x-www-form-urlencoded" in content_type:
            log_data["form_data"] = dict(flow.request.urlencoded_form)

        log_event(log_data)

        ctx.log.info(f"[INSPECT] {flow.request.method} {flow.request.pretty_url}")


addons = [SurfaceInspector()]
