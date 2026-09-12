"""Structured audit logging.

Mirroring production traffic on a government backbone carries custody
obligations, and those obligations do not end when the packets are discarded.
An agency has to be able to answer, after the fact, who assessed which capture
and when — both to demonstrate the analyzer was used lawfully and to
reconstruct what an analyst knew at the time a decision was made.

The log is JSON Lines: one self-contained object per line, append-only, trivially
shippable to a SIEM without a parser. What it deliberately does not contain is
any part of the traffic itself. Findings are recorded by rule ID and subject, not
by detail text, so the audit trail cannot become a second copy of the
intelligence it is meant to account for.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime, timezone
from typing import Any

_lock = threading.Lock()

DEFAULT_LOG = "cipherguard-audit.jsonl"


class AuditLog:
    def __init__(self, path: str | None = DEFAULT_LOG, actor: str = "cli"):
        self.path = path
        self.actor = actor
        self.host = socket.gethostname()

    def _write(self, record: dict[str, Any]) -> None:
        if not self.path:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": self.host,
            "actor": self.actor,
            "pid": os.getpid(),
            **record,
        }
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        # Append under a lock and with a single write call: concurrent analysts
        # on one sensor must not interleave partial lines and corrupt the trail.
        with _lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def assessment(self, assessment, capture_path: str, source: str = "cli") -> None:
        """Record that an assessment happened, without recording its content."""
        self._write(
            {
                "event": "assessment",
                "source": source,
                "capture": os.path.basename(capture_path),
                "capture_sha256": _digest(capture_path),
                "score": assessment.score(),
                "grade": assessment.grade(),
                "counts": assessment.counts(),
                "sessions": len(assessment.sessions),
                "esp_flows": len(assessment.flows),
                # rule IDs and subjects only — never finding detail, which
                # would duplicate the intelligence into the audit trail
                "findings": sorted(
                    {f"{f.rule_id}:{f.subject}" for f in assessment.findings}
                ),
                "report_digest": assessment.digest(),
            }
        )

    def export(self, kind: str, capture: str, destination: str | None) -> None:
        self._write(
            {
                "event": "export",
                "kind": kind,
                "capture": os.path.basename(capture),
                "destination": os.path.basename(destination) if destination else None,
            }
        )

    def denied(self, reason: str, detail: str = "") -> None:
        self._write({"event": "denied", "reason": reason, "detail": detail[:200]})


def _digest(path: str) -> str | None:
    """SHA-256 of the capture, so a later reader can prove which bytes were
    assessed. A finding is only meaningful against a known input."""
    import hashlib

    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(1 << 20):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
