"""
redaction.py — Local-first text & visual PDF redaction for the Agency Guard DLP pipeline.

Automatic mode (RECOMMENDED):
    from file_analysis import extract_text_from_pdf, redact_text, generate_redacted_pdf

    # 1. Extract text
    result     = extract_text_from_pdf(pdf_bytes)
    raw_text   = result["text"]

    # 2. Redact — DLP regex patterns are applied AUTOMATICALLY
    safe_text  = redact_text(raw_text)

    # 3. Generate a visually redacted PDF — also automatic
    safe_pdf   = generate_redacted_pdf(pdf_bytes)

Manual mode (pass explicit strings to redact):
    safe_text  = redact_text(raw_text, findings=["123-45-6789", "sk-abc123"])
    safe_pdf   = generate_redacted_pdf(pdf_bytes, findings=["123-45-6789"])

No external APIs are used — all processing happens locally via pdfplumber + ReportLab.
"""

from __future__ import annotations

import io
import logging
import re
import sys
import os
from typing import Any, Optional

import pdfplumber
from reportlab.lib.units import inch  # noqa: F401 – kept for convenience
from reportlab.pdfgen import canvas as rl_canvas

# ── Import DLP regex patterns from the risk_engine ──────────────────────────
# Add the project root to sys.path so we can import risk_engine as a package
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from risk_engine.dlp_rules import DLP_PATTERNS

logger = logging.getLogger(__name__)

# Placeholder that replaces every sensitive match
REDACTION_PLACEHOLDER = "[REDACTED]"


# ═══════════════════════════════════════════════════════════════════════════════
#  0.  DLP REGEX SCANNER  (text → list of matched strings)
# ═══════════════════════════════════════════════════════════════════════════════

def scan_text(text: str) -> list[dict[str, Any]]:
    """
    Scan text using ALL precompiled DLP regex patterns from ``dlp_rules.py``.

    Returns
    -------
    list[dict]
        Each dict contains::

            {
                "type": "SSN" | "CREDIT_CARD" | ...,
                "match": "<the actual matched string>",
                "start": int,   # start index in text
                "end": int,     # end index in text
            }

        Sorted by start position.  Duplicates are kept so callers can count.
    """
    if not text:
        return []

    results: list[dict[str, Any]] = []

    for data_type, pattern in DLP_PATTERNS.items():
        for m in pattern.finditer(text):
            results.append({
                "type": data_type,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
            })

    # Sort by position so redaction order is deterministic
    results.sort(key=lambda r: r["start"])
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  1.  TEXT REDACTION  (string → string)
# ═══════════════════════════════════════════════════════════════════════════════

def redact_text(
    text: str,
    findings: Optional[list[str]] = None,
    *,
    placeholder: str = REDACTION_PLACEHOLDER,
) -> str:
    """
    Replace every occurrence of sensitive data in *text* with *placeholder*.

    **Auto mode** (``findings`` is ``None``):
        Uses the DLP regex patterns from ``risk_engine/dlp_rules.py`` to
        dynamically detect SSNs, credit cards, emails, API keys, etc.

    **Manual mode** (``findings`` is a list of strings):
        Treats each string as a literal and replaces all occurrences.

    Parameters
    ----------
    text : str
        The raw text extracted from a document.
    findings : list[str] or None, optional
        If provided, literal strings to redact.
        If ``None`` (default), DLP regex patterns are used automatically.
    placeholder : str, optional
        Replacement token (default ``[REDACTED]``).

    Returns
    -------
    str
        The sanitised text with all findings replaced.
    """
    if not text:
        return text

    # ── AUTO MODE: Use DLP regex patterns ────────────────────────────────
    if findings is None:
        sanitised = text
        for data_type, pattern in DLP_PATTERNS.items():
            sanitised = pattern.sub(placeholder, sanitised)
        return sanitised

    # ── MANUAL MODE: Literal string replacement (backwards compat) ───────
    sanitised = text
    for finding in findings:
        if not finding:
            continue
        escaped = re.escape(finding)
        sanitised = re.sub(escaped, placeholder, sanitised, flags=re.IGNORECASE)

    return sanitised


# ═══════════════════════════════════════════════════════════════════════════════
#  2.  VISUAL PDF REDACTION  (bytes → bytes)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_redacted_pdf(
    file_buffer: bytes,
    findings: Optional[list[str]] = None,
    *,
    placeholder: str = REDACTION_PLACEHOLDER,
) -> dict[str, Any]:
    """
    Produce a new PDF with sensitive data covered by opaque black rectangles.

    **Auto mode** (``findings`` is ``None``):
        Uses DLP regex patterns to automatically detect sensitive regions.

    **Manual mode** (``findings`` is a list of strings):
        Redacts the exact literal strings provided.

    The redaction is *irreversible* — the original text is not present in the
    output PDF; a black rectangle is drawn over the matching region.

    Parameters
    ----------
    file_buffer : bytes
        Raw bytes of the original PDF.
    findings : list[str] or None, optional
        Literal strings to redact. If ``None``, DLP regex is used automatically.

    Returns
    -------
    dict
        On success::

            {
                "redacted_pdf": bytes,
                "pages_processed": int,
                "redactions_applied": int,
                "findings_summary": [{"type": str, "count": int}, ...],
            }

        On failure::

            {
                "redacted_pdf": b"",
                "error": str,
                "detail": str,
            }
    """

    if not file_buffer:
        return {
            "redacted_pdf": b"",
            "pages_processed": 0,
            "redactions_applied": 0,
        }

    try:
        pdf_stream = io.BytesIO(file_buffer)
        output_buffer = io.BytesIO()

        total_redactions = 0
        type_counts: dict[str, int] = {}
        pages_count = 0

        with pdfplumber.open(pdf_stream) as pdf:
            # Determine page size from the first page (fallback to Letter)
            first_page = pdf.pages[0] if pdf.pages else None
            if first_page:
                page_width = float(first_page.width)
                page_height = float(first_page.height)
            else:
                page_width, page_height = 612.0, 792.0  # Letter

            c = rl_canvas.Canvas(output_buffer, pagesize=(page_width, page_height))
            pages_count = len(pdf.pages)

            for page_num, page in enumerate(pdf.pages, start=1):
                pw = float(page.width)
                ph = float(page.height)
                c.setPageSize((pw, ph))

                # ── Step A: Extract characters with bounding boxes ───────
                chars = page.chars
                page_text = "".join(ch.get("text", "") for ch in chars)

                # ── Step B: Find sensitive regions ───────────────────────
                regions_to_redact: list[tuple[float, float, float, float]] = []
                redacted_indices: set[int] = set()

                if findings is None:
                    # AUTO MODE — use DLP regex patterns
                    for data_type, pattern in DLP_PATTERNS.items():
                        for m in pattern.finditer(page_text):
                            idx = m.start()
                            end_idx = m.end()
                            matched_chars = chars[idx:end_idx]

                            if matched_chars:
                                x0 = min(float(ch["x0"]) for ch in matched_chars)
                                x1 = max(float(ch["x1"]) for ch in matched_chars)
                                top = min(float(ch["top"]) for ch in matched_chars)
                                bottom = max(float(ch["bottom"]) for ch in matched_chars)

                                rl_y0 = ph - bottom
                                rl_y1 = ph - top
                                regions_to_redact.append((x0, rl_y0, x1, rl_y1))
                                total_redactions += 1

                                type_counts[data_type] = type_counts.get(data_type, 0) + 1

                            for i in range(idx, end_idx):
                                redacted_indices.add(i)
                else:
                    # MANUAL MODE — literal string matching
                    lower_page = page_text.lower()
                    for finding in findings:
                        if not finding:
                            continue
                        start = 0
                        lower_finding = finding.lower()

                        while True:
                            idx = lower_page.find(lower_finding, start)
                            if idx == -1:
                                break
                            end_idx = idx + len(finding)
                            matched_chars = chars[idx:end_idx]

                            if matched_chars:
                                x0 = min(float(ch["x0"]) for ch in matched_chars)
                                x1 = max(float(ch["x1"]) for ch in matched_chars)
                                top = min(float(ch["top"]) for ch in matched_chars)
                                bottom = max(float(ch["bottom"]) for ch in matched_chars)

                                rl_y0 = ph - bottom
                                rl_y1 = ph - top
                                regions_to_redact.append((x0, rl_y0, x1, rl_y1))
                                total_redactions += 1

                            for i in range(idx, end_idx):
                                redacted_indices.add(i)

                            start = end_idx

                # ── Step C: Redraw — only non-redacted characters ────────
                c.setFont("Helvetica", 10)

                for i, ch in enumerate(chars):
                    if i in redacted_indices:
                        continue
                    x = float(ch["x0"])
                    y = ph - float(ch["bottom"])
                    try:
                        c.drawString(x, y, ch.get("text", ""))
                    except Exception:
                        pass  # non-renderable glyph

                # Draw black rectangles over redacted regions
                c.setFillColorRGB(0, 0, 0)
                for (x0, y0, x1, y1) in regions_to_redact:
                    padding = 1
                    c.rect(
                        x0 - padding,
                        y0 - padding,
                        (x1 - x0) + 2 * padding,
                        (y1 - y0) + 2 * padding,
                        fill=True,
                        stroke=False,
                    )

                c.showPage()

            c.save()

        # Build findings summary for the response
        findings_summary = [
            {"type": t, "count": n} for t, n in type_counts.items()
        ]

        return {
            "redacted_pdf": output_buffer.getvalue(),
            "pages_processed": pages_count,
            "redactions_applied": total_redactions,
            "findings_summary": findings_summary,
        }

    except Exception as exc:
        logger.error("Visual PDF redaction failed: %s", exc, exc_info=True)
        return {
            "redacted_pdf": b"",
            "error": "redaction_failed",
            "detail": str(exc),
        }
