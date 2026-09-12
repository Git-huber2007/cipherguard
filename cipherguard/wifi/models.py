"""Data models for Wi-Fi auditing and security posture assessment."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SecurityFinding:
    severity: str  # "critical", "high", "medium", "low", "info"
    rule_id: str
    title: str
    subject: str
    detail: str
    remediation: str
    reference: str = ""
    inferred: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WifiNetwork:
    ssid: str
    bssid: str
    signal_percent: int
    rssi_dbm: int
    channel: int
    band: str  # "2.4 GHz", "5 GHz", "6 GHz", or "Unknown"
    radio_type: str  # "802.11ax", "802.11ac", "802.11n", etc.
    authentication: str  # "WPA3-Personal", "WPA2-Personal", "Open", etc.
    encryption: str  # "CCMP", "GCMP", "TKIP", "None"
    security_grade: str  # "A+", "A", "B", "D", "F"
    connected: bool = False
    is_rogue: bool = False
    rogue_reason: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WifiInterfaceInfo:
    name: str
    description: str
    mac_address: str
    state: str
    ssid: str
    bssid: str
    band: str
    channel: int
    radio_type: str
    authentication: str
    cipher: str
    signal_percent: int
    rssi_dbm: int
    rx_rate_mbps: float = 0.0
    tx_rate_mbps: float = 0.0
    dns_servers: list[str] = field(default_factory=list)
    gateway_ip: str = ""
    ipv4_address: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WifiAssessment:
    interface: WifiInterfaceInfo | None
    networks_in_range: list[WifiNetwork] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[SecurityFinding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    summary: str = ""
    dns_posture: dict[str, Any] = field(default_factory=dict)
    quantum_risk: str = "Standard Classical (ECC/RSA Handshake at Risk to CRQC)"
    rogue_aps: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if not self.counts:
            c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in self.findings:
                c[f.severity] = c.get(f.severity, 0) + 1
            self.counts = c

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface.to_dict() if self.interface else None,
            "networks_in_range": [n.to_dict() for n in self.networks_in_range],
            "score": self.score,
            "grade": self.grade,
            "started": self.started,
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts,
            "summary": self.summary,
            "dns_posture": self.dns_posture,
            "quantum_risk": self.quantum_risk,
            "rogue_aps": self.rogue_aps,
        }
