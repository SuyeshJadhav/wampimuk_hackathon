"""
redaction.py — Local-first text & visual PDF redaction for the Agency Guard DLP pipeline.

Usage from a FastAPI evaluate endpoint:
    from file_analysis import extract_text_from_pdf, redact_text, generate_redacted_pdf

    # 1. Extract text
    result     = extract_text_from_pdf(pdf_bytes)
    raw_text   = result["text"]

    # 2. Run your DLP / Risk-Engine scanner to produce findings
    findings   = risk_engine.scan(raw_text)   # e.g. ["123-45-6789", "sk-abc123"]

    # 3. Redact the text (for logging / downstream consumption)
    safe_text  = redact_text(raw_text, findings)

    # 4. (Advanced) Generate a visually redacted PDF
    safe_pdf   = generate_redacted_pdf(pdf_bytes, findings)

No external APIs are used — all processing happens locally via pdfplumber + ReportLab.
"""

from __future__ import annotations

import io
import logging
import re
from typing import Any

import pdfplumber
from reportlab.lib.units import inch  # noqa: F401 – kept for convenience
from reportlab.pdfgen import canvas as rl_canvas

logger = logging.getLogger(__name__)

# Placeholder that replaces every sensitive match
REDACTION_PLACEHOLDER = "[REDACTED]"


# ═══════════════════════════════════════════════════════════════════════════════
#  1.  TEXT REDACTION  (string → string)
# ═══════════════════════════════════════════════════════════════════════════════

def redact_text(
    text: str,
    findings: list[str],
    *,
    placeholder: str = REDACTION_PLACEHOLDER,
    case_sensitive: bool = False,
) -> str:
    """
    Replace every occurrence of each finding in *text* with *placeholder*.

    Parameters
    ----------
    text : str
        The raw text extracted from a document.
    findings : list[str]
        Sensitive strings discovered by the Risk Engine / DLP scanner
        (e.g. SSNs, API keys, email addresses).
    placeholder : str, optional
        Replacement token (default ``[REDACTED]``).
    case_sensitive : bool, optional
        If ``False`` (default), matching is case-insensitive.

    Returns
    -------
    str
        The sanitised text with all findings replaced.
    """
    if not text or not findings:
        return text

    sanitised = text

    for finding in findings:
        if not finding:
            continue

        # Escape the finding so it is treated as a literal, not a regex
        pattern = re.escape(finding)
        flags = 0 if case_sensitive else re.IGNORECASE
        sanitised = re.sub(pattern, placeholder, sanitised, flags=flags)

    return sanitised


# ═══════════════════════════════════════════════════════════════════════════════
#  2.  VISUAL PDF REDACTION  (bytes → bytes)   — Advanced / Skeleton
# ═══════════════════════════════════════════════════════════════════════════════

def generate_redacted_pdf(
    file_buffer: bytes,
    findings: list[str],
    *,
    placeholder: str = REDACTION_PLACEHOLDER,
) -> dict[str, Any]:
    """
    Produce a new PDF with sensitive strings covered by opaque black rectangles.

    **This is a best-effort skeleton.**  It works well for simple, single-column
    PDFs where pdfplumber can reliably report character-level bounding boxes.
    Production hardening (multi-column layouts, rotated text, embedded images
    containing text, etc.) is marked with TODO comments.

    The redaction is *irreversible* — the original text is not present in the
    output PDF; a black rectangle is drawn over the matching region on a blank
    page that is overlaid with only the redacted content.

    Parameters
    ----------
    file_buffer : bytes
        Raw bytes of the original PDF.
    findings : list[str]
        Sensitive strings to redact.

    Returns
    -------
    dict
        On success::

            {
                "redacted_pdf": bytes,   # The new PDF file content
                "pages_processed": int,
                "redactions_applied": int,
            }

        On failure::

            {
                "redacted_pdf": b"",
                "error": str,
                "detail": str,
            }
    """

    if not file_buffer or not findings:
        return {
            "redacted_pdf": file_buffer or b"",
            "pages_processed": 0,
            "redactions_applied": 0,
        }

    try:
        pdf_stream = io.BytesIO(file_buffer)
        output_buffer = io.BytesIO()

        total_redactions = 0

        with pdfplumber.open(pdf_stream) as pdf:
            # Determine page size from the first page (fallback to Letter)
            first_page = pdf.pages[0] if pdf.pages else None
            if first_page:
                page_width = float(first_page.width)
                page_height = float(first_page.height)
            else:
                page_width, page_height = 612.0, 792.0  # Letter

            c = rl_canvas.Canvas(output_buffer, pagesize=(page_width, page_height))

            for page_num, page in enumerate(pdf.pages, start=1):
                pw = float(page.width)
                ph = float(page.height)
                c.setPageSize((pw, ph))

                # ── Step A: Extract ALL text with character-level bounding boxes ──
                chars = page.chars  # list of dicts with x0, y0, x1, y1, text keys

                # Rebuild the full page text from chars
                page_text = "".join(ch.get("text", "") for ch in chars)

                # ── Step B: Find matches in the page text ──────────────────────
                regions_to_redact: list[tuple[float, float, float, float]] = []

                for finding in findings:
                    if not finding:
                        continue
                    start = 0
                    lower_page = page_text.lower()
                    lower_finding = finding.lower()

                    while True:
                        idx = lower_page.find(lower_finding, start)
                        if idx == -1:
                            break
                        end_idx = idx + len(finding)

                        # Gather bounding boxes of matched characters
                        matched_chars = chars[idx:end_idx]
                        if matched_chars:
                            x0 = min(float(ch["x0"]) for ch in matched_chars)
                            x1 = max(float(ch["x1"]) for ch in matched_chars)
                            # pdfplumber y-axis: top=0.  ReportLab y-axis: bottom=0.
                            top = min(float(ch["top"]) for ch in matched_chars)
                            bottom = max(float(ch["bottom"]) for ch in matched_chars)

                            # Convert pdfplumber coords → ReportLab coords
                            rl_y0 = ph - bottom
                            rl_y1 = ph - top
                            regions_to_redact.append((x0, rl_y0, x1, rl_y1))
                            total_redactions += 1

                        start = end_idx

                # ── Step C: Redraw text, replacing redacted regions with boxes ──
                #
                # Strategy (irreversible):
                #   1. Draw the full page text char-by-char
                #   2. Draw opaque BLACK rectangles over every redacted region
                #   3. The original text underneath is NOT preserved — we only
                #      write non-redacted chars to the canvas.
                #
                # TODO: Handle embedded images, vector graphics, annotations.
                # TODO: Preserve fonts / sizes (currently uses Helvetica fallback).

                c.setFont("Helvetica", 10)

                # Draw only non-redacted characters
                redacted_indices: set[int] = set()
                for finding in findings:
                    if not finding:
                        continue
                    start = 0
                    while True:
                        idx = lower_page.find(finding.lower(), start)
                        if idx == -1:
                            break
                        for i in range(idx, idx + len(finding)):
                            redacted_indices.add(i)
                        start = idx + len(finding)

                for i, ch in enumerate(chars):
                    if i in redacted_indices:
                        continue  # skip — will be covered by black box
                    x = float(ch["x0"])
                    y = ph - float(ch["bottom"])
                    try:
                        c.drawString(x, y, ch.get("text", ""))
                    except Exception:
                        pass  # non-renderable glyph

                # Draw black rectangles over redacted regions
                c.setFillColorRGB(0, 0, 0)
                for (x0, y0, x1, y1) in regions_to_redact:
                    padding = 1  # slight padding around text
                    c.rect(
                        x0 - padding,
                        y0 - padding,
                        (x1 - x0) + 2 * padding,
                        (y1 - y0) + 2 * padding,
                        fill=True,
                        stroke=False,
                    )

                c.showPage()  # finalise current page

            c.save()

        return {
            "redacted_pdf": output_buffer.getvalue(),
            "pages_processed": len(pdf.pages) if 'pdf' in dir() else 0,
            "redactions_applied": total_redactions,
        }

    except Exception as exc:
        logger.error("Visual PDF redaction failed: %s", exc, exc_info=True)
        return {
            "redacted_pdf": b"",
            "error": "redaction_failed",
            "detail": str(exc),
        }
