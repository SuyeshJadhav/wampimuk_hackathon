"""
DLP Regex Rules

Add / modify regex safely here.
All regex is compiled once for performance.
"""

import re


DLP_PATTERNS = {

    "SSN": re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\d{3}\s\d{2}\s\d{4}|\d{9})\b"),

    "CREDIT_CARD": re.compile(
        r"\b(?:\d{3}-\d{2}-\d{4}|\d{3}\s\d{2}\s\d{4}|\d{9})\b"
    ),

    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),

    "PHONE": re.compile(
        r"\b(?:\d{3}-\d{2}-\d{4}|\d{3}\s\d{2}\s\d{4}|\d{9})\b"
    ),

    # "API_KEY": re.compile(
    #     r"\b[A-Za-z0-9]{32,64}\b",
    #     re.IGNORECASE,
    # ),

    "PASSWORD": re.compile(
        r"\bpassword['\"]?\s*[:=]\s*['\"].+?['\"]",
        re.IGNORECASE,
    ),

    "PRIVATE_KEY": re.compile(
        r"-----BEGIN PRIVATE KEY-----"
    ),

    "SWIFT_CODES": re.compile(
        r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b"
    ),
    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"
    ),

}