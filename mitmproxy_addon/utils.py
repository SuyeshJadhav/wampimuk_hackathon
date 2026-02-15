# mitmproxy_addon/utils.py

import re
from urllib.parse import urlparse

def extract_domain(url: str) -> str:
    """
    Extracts domain from a given URL.
    Example: https://sub.example.com/path -> example.com
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])  # example.com
    return hostname

def normalize_url(url: str) -> str:
    """
    Normalize URL by stripping scheme and trailing slashes
    """
    parsed = urlparse(url)
    return f"{parsed.netloc}{parsed.path}".rstrip("/")

def parse_multipart_form(body: bytes, content_type: str) -> dict:
    """
    Placeholder for multipart/form-data parsing
    Returns:
        {
            "fields": {...},
            "files": [
                {"filename": "...", "content_type": "...", "size": ...},
                ...
            ]
        }
    """
    # TODO: implement actual multipart parser or use existing library
    return {"fields": {}, "files": []}

def detect_sensitive_keywords(text: str, keywords: list) -> list:
    """
    Simple detection of sensitive keywords in text
    """
    found = []
    for kw in keywords:
        if re.search(kw, text, re.IGNORECASE):
            found.append(kw)
    return found
