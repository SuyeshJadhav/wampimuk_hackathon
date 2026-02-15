from mitmproxy import http

def request(flow: http.HTTPFlow):
    if flow.request.method != "POST":
        return

    ctype = flow.request.headers.get("content-type", "").lower()

    # Only inspect text-like payloads
    if "application/json" in ctype or \
       "application/x-www-form-urlencoded" in ctype or \
       "text/" in ctype:

        body = flow.request.get_text(strict=False) or ""

        print("\n===== DECRYPTED TEXT BODY =====")
        print(body)
        print("================================\n")
