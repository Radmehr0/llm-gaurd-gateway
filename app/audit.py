"""Append-only JSONL audit log.

Only rule names and categories are logged, never the matched values,
so the audit log itself can't become a leak of sensitive data.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .detectors import Finding


class AuditLog:
    def __init__(self, path: str | Path = "audit.jsonl"):
        self.path = Path(path)

    def record(self, direction: str, action: str, findings: list[Finding]) -> dict:
        entry = {
            "ts": time.time(),
            "direction": direction,  # "request" | "response"
            "action": action,        # "allowed" | "redacted" | "blocked"
            "findings": [{"category": f.category, "rule": f.rule} for f in findings],
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line]
