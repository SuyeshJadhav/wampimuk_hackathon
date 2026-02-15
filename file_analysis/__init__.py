"""
file_analysis — Local-first PDF extraction & redaction for Agency Guard.

Public API:
    extract_text_from_pdf(file_buffer: bytes) -> dict
    scan_text(text: str) -> list[dict]              # Auto-detect via DLP regex
    redact_text(text: str, findings=None) -> str     # Auto or manual redaction
    generate_redacted_pdf(file_buffer: bytes, findings=None) -> dict
"""

from file_analysis.pdf_text_scan import extract_text_from_pdf
from file_analysis.redaction import generate_redacted_pdf, redact_text, scan_text

__all__ = [
    "extract_text_from_pdf",
    "scan_text",
    "redact_text",
    "generate_redacted_pdf",
]
