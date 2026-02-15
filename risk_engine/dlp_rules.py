"""
DLP Regex Rules

Add / modify regex safely here.
All regex is compiled once for performance.
"""

import re


DLP_PATTERNS = {

    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),

    "CREDIT_CARD": re.compile(
        r"\b(?:\d[ -]*?){13,16}\b"
    ),

    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),

    "PHONE": re.compile(
        r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
    ),

    "API_KEY": re.compile(
        r"\b(?:api[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9-_]{16,}['\"]",
        re.IGNORECASE,
    ),

    "PASSWORD": re.compile(
        r"\bpassword['\"]?\s*[:=]\s*['\"].+?['\"]",
        re.IGNORECASE,
    ),

    "PRIVATE_KEY": re.compile(
        r"-----BEGIN PRIVATE KEY-----"
    ),

    "BANK_ACCOUNT": re.compile(
        r"\b\d{9,18}\b"
    ),

}