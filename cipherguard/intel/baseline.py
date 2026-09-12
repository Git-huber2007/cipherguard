"""Temporal baseline: continuous assurance rather than point-in-time scanning.

The literature splits into two camps, and both miss the same thing. Static
configuration verification proves a policy correct on paper but never sees the
wire. Encrypted-traffic classification reads flow statistics but ignores what
was negotiated. Neither observes a peer pair *over time*, so neither can detect
the failure that matters most operationally:

    a link that used to negotiate AES-256 / Group 19 and now negotiates
    3DES / Group 2 with the same peer.

That is the signature of downgrade injection, of a botched firmware rollback, or
of a failover onto a legacy standby gateway. Every one of those is invisible to
a single capture, because a single capture has nothing to compare against — the
weak suite looks like it was always the policy. It is equally invisible to
configuration review, which sees the intended config rather than what the peers
actually settled on.

The store is deliberately small and boring: SQLite, one row per peer pair per
observation, with the best strength ever seen retained as the baseline. No
payload, no addresses beyond the peer pair already present in the capture.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from ..core.models import Assessment, IkeSession
from ..core.strength import score_proposal

DEFAULT_DB = "cipherguard-baseline.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_key        TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    capture         TEXT NOT NULL,
    ike_version     TEXT,
    vendor_family   TEXT,
    classical_bits  INTEGER NOT NULL,
    quantum_bits    INTEGER NOT NULL,
    dh_group        INTEGER,
    transforms      TEXT NOT NULL,
    score           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_peer ON observations(peer_key, observed_at);

CREATE TABLE IF NOT EXISTS baselines (
    peer_key            TEXT PRIMARY KEY,
    best_classical_bits INTEGER NOT NULL,
    best_quantum_bits   INTEGER NOT NULL,
    best_transforms     TEXT NOT NULL,
    best_seen_at        TEXT NOT NULL,
    first_seen_at       TEXT NOT NULL,
    observations        INTEGER NOT NULL DEFAULT 1
);
"""


@dataclass
class Drift:
    peer_key: str
    kind: str            # "downgrade" | "improvement" | "new"
    previous_bits: int
    current_bits: int
    previous_transforms: list[str]
    current_transforms: list[str]
    baseline_seen_at: str

    @property
    def delta(self) -> int:
        return self.current_bits - self.previous_bits

    def to_dict(self) -> dict:
        return {
            "peer_key": self.peer_key,
            "kind": self.kind,
            "previous_bits": self.previous_bits,
            "current_bits": self.current_bits,
            "delta": self.delta,
            "previous_transforms": self.previous_transforms,
            "current_transforms": self.current_transforms,
            "baseline_seen_at": self.baseline_seen_at,
        }


def peer_key(sess: IkeSession) -> str:
    """Direction-independent identity for a gateway pair.

    Sorted so that an initiator/responder role swap on re-negotiation does not
    read as a different link and silently reset its baseline.
    """
    return "|".join(sorted([sess.peer_a, sess.peer_b]))


class BaselineStore:
    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "BaselineStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- recording ---------------------------------------------------------

    def record(
        self,
        assessment: Assessment,
        min_observations: int = 2,
        max_new_peers: int = 64,
    ) -> list[Drift]:
        """Record every session and return the drift detected against baseline.

        Three constraints, all of them because this store is written from
        attacker-reachable traffic and its output gates a CI exit code:

        `confirmed_only` — only proposals a responder actually agreed to are
        recorded. An unanswered IKE_SA_INIT proves somebody sent a packet, and
        anyone on a mirrored segment can send one. Without this, a single
        spoofed datagram permanently sets a peer pair's baseline: set it high
        and a real downgrade never fires, set it low across many pairs and the
        resulting alert flood trains operators to ignore exit code 3.

        `min_observations` — a baseline is promoted only after the same or
        better strength has been seen more than once, so one anomalous exchange
        cannot define the reference point.

        `max_new_peers` — a cap on how many previously unseen peer pairs one
        capture may introduce, since peer keys are derived from IP addresses
        and spoofing them is free.
        """
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        drifts: list[Drift] = []
        new_peers = 0

        for sess in assessment.sessions:
            prop = sess.negotiated("IKE", confirmed_only=True)
            if not prop:
                # An offer that was never agreed to, or a failed negotiation.
                # Recording it as fact would be wrong in both cases.
                continue
            strength = score_proposal(prop.transforms)
            transforms = sorted(t.label() for t in prop.transforms)
            key = peer_key(sess)
            dh = next((t.value_id for t in prop.by_type(4)), None)

            self.conn.execute(
                "INSERT INTO observations (peer_key, observed_at, capture, "
                "ike_version, vendor_family, classical_bits, quantum_bits, "
                "dh_group, transforms, score) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key, now, assessment.capture, sess.version, sess.vendor_family(),
                 strength.classical_bits, strength.quantum_bits, dh,
                 json.dumps(transforms), assessment.score()),
            )

            row = self.conn.execute(
                "SELECT * FROM baselines WHERE peer_key = ?", (key,)
            ).fetchone()

            if row is None:
                new_peers += 1
                if new_peers > max_new_peers:
                    # Beyond this, the capture is introducing peers faster than
                    # any real deployment changes, which is what address
                    # spoofing looks like. Observations are still recorded; only
                    # baseline creation is withheld.
                    continue
                self.conn.execute(
                    "INSERT INTO baselines (peer_key, best_classical_bits, "
                    "best_quantum_bits, best_transforms, best_seen_at, first_seen_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (key, strength.classical_bits, strength.quantum_bits,
                     json.dumps(transforms), now, now),
                )
                drifts.append(
                    Drift(key, "new", strength.classical_bits, strength.classical_bits,
                          transforms, transforms, now)
                )
                continue

            self.conn.execute(
                "UPDATE baselines SET observations = observations + 1 WHERE peer_key = ?",
                (key,),
            )
            best = row["best_classical_bits"]
            previous = json.loads(row["best_transforms"])

            if strength.classical_bits < best:
                drifts.append(
                    Drift(key, "downgrade", best, strength.classical_bits,
                          previous, transforms, row["best_seen_at"])
                )
            elif strength.classical_bits > best:
                # Promote only once the stronger suite has been seen enough
                # times to be a configuration rather than an anomaly.
                seen_at_least = self.conn.execute(
                    "SELECT COUNT(*) FROM observations WHERE peer_key = ? "
                    "AND classical_bits >= ?",
                    (key, strength.classical_bits),
                ).fetchone()[0]
                if seen_at_least < min_observations:
                    continue
                drifts.append(
                    Drift(key, "improvement", best, strength.classical_bits,
                          previous, transforms, row["best_seen_at"])
                )
                self.conn.execute(
                    "UPDATE baselines SET best_classical_bits = ?, best_quantum_bits = ?, "
                    "best_transforms = ?, best_seen_at = ? WHERE peer_key = ?",
                    (strength.classical_bits, strength.quantum_bits,
                     json.dumps(transforms), now, key),
                )

        self.conn.commit()
        return drifts

    # -- querying ----------------------------------------------------------

    def history(self, key: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT observed_at, capture, classical_bits, quantum_bits, dh_group, "
            "transforms FROM observations WHERE peer_key = ? "
            "ORDER BY observed_at DESC, id DESC LIMIT ?",
            (key, limit),
        ).fetchall()
        return [
            {**dict(r), "transforms": json.loads(r["transforms"])} for r in rows
        ]

    def fleet(self) -> list[dict]:
        """One row per link, weakest current state first — the triage queue."""
        rows = self.conn.execute(
            """
            SELECT b.peer_key, b.best_classical_bits, b.best_quantum_bits,
                   b.first_seen_at, b.observations,
                   o.classical_bits AS current_bits, o.quantum_bits AS current_quantum,
                   o.observed_at AS last_seen, o.transforms AS current_transforms,
                   o.vendor_family, o.ike_version
            FROM baselines b
            JOIN observations o ON o.id = (
                SELECT id FROM observations WHERE peer_key = b.peer_key
                ORDER BY observed_at DESC, id DESC LIMIT 1
            )
            ORDER BY o.classical_bits ASC, b.peer_key ASC
            """
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["current_transforms"] = json.loads(d["current_transforms"])
            d["degraded"] = d["current_bits"] < d["best_classical_bits"]
            out.append(d)
        return out

    def summary(self) -> dict:
        fleet = self.fleet()
        if not fleet:
            return {"links": 0}
        quantum_safe = sum(1 for f in fleet if f["current_quantum"] >= 128)
        return {
            "links": len(fleet),
            "observations": sum(f["observations"] for f in fleet),
            "degraded": sum(1 for f in fleet if f["degraded"]),
            "below_112_bits": sum(1 for f in fleet if f["current_bits"] < 112),
            "quantum_safe": quantum_safe,
            "quantum_exposed": len(fleet) - quantum_safe,
            "weakest_bits": min(f["current_bits"] for f in fleet),
        }
