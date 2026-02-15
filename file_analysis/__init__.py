"""
file_analysis — Local-first PDF extraction & redaction for Agency Guard.

Public API:
    extract_text_from_pdf(file_buffer: bytes) -> dict
    redact_text(text: str, findings: list[str]) -> str
    generate_redacted_pdf(file_buffer: bytes, findings: list[str]) -> dict
"""

from file_analysis.pdf_text_scan import extract_text_from_pdf
from file_analysis.redaction import generate_redacted_pdf, redact_text

__all__ = [
    "extract_text_from_pdf",
    "redact_text",
    "generate_redacted_pdf",
]
