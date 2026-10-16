"""Rule-based detectors for prompt injection, PII and secrets.

Each detector takes text and returns a list of Finding objects.
Rules are intentionally simple and readable: this is a baseline you can
measure and improve (e.g. by adding an ML classifier later).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    category: str  # "injection" | "pii" | "secret"
    rule: str      # short rule name, e.g. "ignore_previous"
    match: str     # the text that matched (truncated for logs)


INJECTION_RULES: dict[str, re.Pattern] = {
    "ignore_previous": re.compile(
        r"\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)\b",
        re.I,
    ),
    "reveal_system_prompt": re.compile(
        r"\b(reveal|show|print|repeat|leak)\b.{0,30}\b(system\s+prompt|hidden\s+instructions|initial\s+instructions)\b",
        re.I,
    ),
    "role_override": re.compile(
        r"\byou\s+are\s+now\b.{0,40}\b(dan|unrestricted|jailbroken|developer\s+mode)\b",
        re.I,
    ),
    "disable_safety": re.compile(
        r"\b(disable|bypass|turn\s+off|ignore)\b.{0,20}\b(safety|guardrails|filters|restrictions)\b",
        re.I,
    ),
}

PII_RULES: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

SECRET_RULES: dict[str, re.Pattern] = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _run(category: str, rules: dict[str, re.Pattern], text: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, pattern in rules.items():
        for m in pattern.finditer(text):
            findings.append(Finding(category, name, m.group(0)[:40]))
    return findings


# Zero-width and soft-hyphen characters attackers insert to split keywords.
_INVISIBLE = re.compile(r"[­​-‏⁠-⁤﻿]")


def normalize(text: str) -> str:
    """Fold look-alike characters (NFKC) and drop invisible ones."""
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


def detect_injection(text: str) -> list[Finding]:
    return _run("injection", INJECTION_RULES, normalize(text))


def detect_pii(text: str) -> list[Finding]:
    findings = []
    for f in _run("pii", PII_RULES, text):
        if f.rule == "credit_card":
            digits = re.sub(r"\D", "", f.match)
            if not (13 <= len(digits) <= 16 and _luhn_ok(digits)):
                continue  # random digit run, not a card number
        findings.append(f)
    return findings


def detect_secrets(text: str) -> list[Finding]:
    return _run("secret", SECRET_RULES, text)


def scan(text: str) -> list[Finding]:
    """Run every detector on the text."""
    return detect_injection(text) + detect_pii(text) + detect_secrets(text)


def redact(text: str) -> str:
    """Replace PII and secrets with placeholders. Injection text is left as-is."""
    for name, pattern in {**SECRET_RULES, **PII_RULES}.items():
        if name == "credit_card":
            text = pattern.sub(
                lambda m: "[REDACTED:credit_card]"
                if _luhn_ok(re.sub(r"\D", "", m.group(0))) and 13 <= len(re.sub(r"\D", "", m.group(0))) <= 16
                else m.group(0),
                text,
            )
        else:
            text = pattern.sub(f"[REDACTED:{name}]", text)
    return text
