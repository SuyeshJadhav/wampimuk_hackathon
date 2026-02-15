"""
pdf_text_scan.py — Local-first PDF text extraction for the Agency Guard DLP pipeline.

Usage from the mitmproxy layer:
    When a multipart file upload is intercepted:

        from file_analysis import extract_text_from_pdf

        # `flow` is a mitmproxy http.HTTPFlow object
        raw_bytes = flow.request.raw_content          # full request body
        # For multipart, parse the PDF part out first (e.g. via email.parser or
        # mitmproxy's multipart utilities), then pass the raw PDF bytes:
        result = extract_text_from_pdf(pdf_bytes)

        if result.get("error"):
            # Handle corrupted / password-protected file
            ...
        else:
            clean_text = result["text"]
            # Forward `clean_text` to the Risk Engine /evaluate endpoint for DLP scanning

No external APIs are used — all processing happens locally via pdfplumber.
"""

from __future__ import annotations

import io
import logging
from typing import Any

import pdfplumber

logger = logging.getLogger(__name__)


def extract_text_from_pdf(file_buffer: bytes) -> dict[str, Any]:
    """
    Extract all readable text from a PDF byte stream.

    Parameters
    ----------
    file_buffer : bytes
        Raw bytes of the PDF file (as captured from an HTTP upload body).

    Returns
    -------
    dict
        On success::

            {
                "text": "<concatenated page text>",
                "page_count": int,
                "metadata": { ... },   # PDF info dict (title, author, etc.)
            }

        On failure::

            {
                "text": "",
                "page_count": 0,
                "error": "corrupt_pdf" | "password_protected" | "extraction_failed",
                "detail": "<human-readable message>"
            }
    """

    if not file_buffer:
        return _error_response("corrupt_pdf", "Received an empty file buffer.")

    try:
        pdf_stream = io.BytesIO(file_buffer)

        with pdfplumber.open(pdf_stream) as pdf:
            pages_text: list[str] = []

            for page_num, page in enumerate(pdf.pages, start=1):
                try:
                    page_text = page.extract_text() or ""
                    pages_text.append(page_text)
                except Exception as page_err:
                    logger.warning(
                        "Could not extract text from page %d: %s", page_num, page_err
                    )
                    pages_text.append("")

            full_text = "\n".join(pages_text).strip()

            # Pull whatever metadata the PDF exposes
            metadata = pdf.metadata or {}

            return {
                "text": full_text,
                "page_count": len(pdf.pages),
                "metadata": {
                    "title": metadata.get("Title", ""),
                    "author": metadata.get("Author", ""),
                    "creator": metadata.get("Creator", ""),
                    "producer": metadata.get("Producer", ""),
                },
            }

    except Exception as exc:
        error_msg = str(exc).lower()

        # pdfplumber / pdfminer raise specific messages for encrypted PDFs
        if "password" in error_msg or "encrypted" in error_msg:
            logger.info("Password-protected PDF detected.")
            return _error_response(
                "password_protected",
                "The PDF is encrypted or password-protected. "
                "Provide the password or upload an unprotected copy.",
            )

        logger.error("PDF extraction failed: %s", exc, exc_info=True)
        return _error_response(
            "corrupt_pdf",
            f"Could not parse the PDF. It may be corrupted or use an unsupported format. ({exc})",
        )


# ── helpers ──────────────────────────────────────────────────────────────────

def _error_response(error_code: str, detail: str) -> dict[str, Any]:
    """Return a standardised error dict."""
    return {
        "text": "",
        "page_count": 0,
        "error": error_code,
        "detail": detail,
    }
