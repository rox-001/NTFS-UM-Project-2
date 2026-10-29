"""
dlp_scanner.py - Content Inspection & True DLP Regex Engine
Inspects file content for sensitive data leaks:
- Cryptographic Private Keys
- Cloud Access Tokens & API Credentials (AWS, GCP, GitHub)
- Payment Card Numbers with Luhn Checksum Algorithm Validation
- PII (Social Security Numbers, Aadhaar Numbers)
"""

from __future__ import annotations

import os
import re

# Max bytes to inspect for DLP regex to ensure zero latency overhead
_MAX_DLP_INSPECT_BYTES = 512 * 1024  # 512 KB

# ── Compiled Regular Expressions ─────────────────────────────────────────────
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
    re.IGNORECASE
)
_RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_GCP_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_RE_GITHUB_TOKEN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b")

# Credit Card Candidate Pattern (13 to 19 digits with optional spaces or dashes)
_RE_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# PII Patterns
_RE_US_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_RE_AADHAAR = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")


def _luhn_checksum_valid(number_str: str) -> bool:
    """Verify Luhn (Mod 10) algorithm to filter out random 16-digit non-card numbers."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Check leading digit for standard card issuers: 3 (Amex), 4 (Visa), 5 (MasterCard), 6 (Discover)
    if digits[0] not in (3, 4, 5, 6):
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum % 10) == 0


def _mask_secret(val: str) -> str:
    """Mask secret for safe security report display."""
    if len(val) <= 8:
        return "********"
    return val[:4] + "*" * (len(val) - 8) + val[-4:]


def scan_file_content(filepath: str) -> dict:
    """
    Scan the file content for sensitive DLP patterns.

    Returns:
        {
            "is_violation": bool,
            "matches": list[dict],      # [{"type": str, "count": int, "sample": str}]
            "risk_bonus": int,          # 0 to 20
            "summary": str,
        }
    """
    if not filepath or not os.path.isfile(filepath):
        return {"is_violation": False, "matches": [], "risk_bonus": 0, "summary": ""}

    # Check file size before reading
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            return {"is_violation": False, "matches": [], "risk_bonus": 0, "summary": ""}
    except OSError:
        return {"is_violation": False, "matches": [], "risk_bonus": 0, "summary": ""}

    # Read up to 512 KB
    content = ""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(_MAX_DLP_INSPECT_BYTES)
    except Exception:
        return {"is_violation": False, "matches": [], "risk_bonus": 0, "summary": ""}

    if not content:
        return {"is_violation": False, "matches": [], "risk_bonus": 0, "summary": ""}

    matches = []
    risk_bonus = 0

    # 1. Cryptographic Private Keys
    pk_hits = _RE_PRIVATE_KEY.findall(content)
    if pk_hits:
        matches.append({"type": "Private Key", "count": len(pk_hits), "sample": "-----BEGIN PRIVATE KEY-----"})
        risk_bonus += 20

    # 2. Cloud Credentials
    aws_hits = _RE_AWS_KEY.findall(content)
    if aws_hits:
        matches.append({"type": "AWS Access Key", "count": len(aws_hits), "sample": _mask_secret(aws_hits[0])})
        risk_bonus += 20

    gcp_hits = _RE_GCP_KEY.findall(content)
    if gcp_hits:
        matches.append({"type": "Google Cloud API Key", "count": len(gcp_hits), "sample": _mask_secret(gcp_hits[0])})
        risk_bonus += 15

    gh_hits = _RE_GITHUB_TOKEN.findall(content)
    if gh_hits:
        matches.append({"type": "GitHub Token", "count": len(gh_hits), "sample": "ghp_****************"})
        risk_bonus += 15

    # 3. Payment Card Data (with Luhn validation)
    card_candidates = _RE_CREDIT_CARD.findall(content)
    valid_cards = []
    for cand in card_candidates:
        clean_num = re.sub(r"\D", "", cand)
        if _luhn_checksum_valid(clean_num):
            valid_cards.append(_mask_secret(clean_num))
            if len(valid_cards) >= 3:
                break

    if valid_cards:
        matches.append({"type": "Payment Card Number", "count": len(valid_cards), "sample": valid_cards[0]})
        risk_bonus += 20

    # 4. PII Data
    ssn_hits = _RE_US_SSN.findall(content)
    if ssn_hits:
        matches.append({"type": "Social Security Number (SSN)", "count": len(ssn_hits), "sample": "***-**-" + ssn_hits[0][-4:]})
        risk_bonus += 15

    aadhaar_hits = _RE_AADHAAR.findall(content)
    if aadhaar_hits:
        matches.append({"type": "Aadhaar Identity Number", "count": len(aadhaar_hits), "sample": "**** **** " + aadhaar_hits[0].strip()[-4:]})
        risk_bonus += 15

    # Cap risk bonus at 20
    risk_bonus = min(20, risk_bonus)
    is_violation = len(matches) > 0

    summary = ", ".join([f"{m['count']}x {m['type']}" for m in matches]) if matches else ""

    return {
        "is_violation": is_violation,
        "matches": matches,
        "risk_bonus": risk_bonus,
        "summary": summary,
    }
