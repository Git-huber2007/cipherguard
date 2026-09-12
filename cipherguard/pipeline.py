"""Analysis pipeline: capture file in, scored assessment out.

Single pass over the capture. Each packet is offered to the IKE dissector and
the ESP tracker; neither holds more than flow-level metadata, so memory is
bounded by the number of distinct SAs rather than by capture size.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from .audit.engine import evaluate
from .core.models import Assessment, IkeMessage
from .dissector import ike as ike_mod
from .dissector.esp import EspTracker
from .dissector.pcap import read_packets
from .ml.classifier import SuiteClassifier

DEFAULT_MODEL_DIR = "models"


def analyze(
    capture: str,
    model_dir: str = DEFAULT_MODEL_DIR,
    min_esp_packets: int = 8,
    max_packets: int | None = None,
    disabled_rules: set[str] | None = None,
) -> Assessment:
    if not os.path.exists(capture):
        raise FileNotFoundError(capture)

    started = time.time()
    messages: list[IkeMessage] = []
    tracker = EspTracker()

    total = ike_seen = esp_seen = other = 0
    first_ts = last_ts = None

    for pkt in read_packets(capture):
        total += 1
        if max_packets and total > max_packets:
            break
        if first_ts is None:
            first_ts = pkt.timestamp
        last_ts = pkt.timestamp

        if ike_mod.is_ike_port(pkt):
            msg = ike_mod.parse_message(pkt)
            if msg is not None:
                messages.append(msg)
                ike_seen += 1
                continue
        if tracker.consume(pkt):
            esp_seen += 1
        else:
            other += 1

    sessions = ike_mod.group_sessions(messages)
    flows = tracker.results(min_packets=min_esp_packets)
    _attribute_volume(sessions, flows)

    model_loaded = False
    model_metrics: dict = {}
    if SuiteClassifier.is_trained(model_dir):
        model = SuiteClassifier.load(model_dir)
        model.annotate(flows)
        model_loaded = True
        model_metrics = model.metrics

    assessment = Assessment(
        capture=os.path.basename(capture),
        started=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sessions=sessions,
        flows=flows,
        stats={
            "packets_read": total,
            "ike_messages": ike_seen,
            "esp_packets": esp_seen,
            "other_packets": other,
            "ike_sessions": len(sessions),
            "esp_flows_tracked": len(tracker.all_flows()),
            "esp_flows_assessed": len(flows),
            "capture_seconds": round((last_ts or 0) - (first_ts or 0), 3),
            "analysis_seconds": round(time.time() - started, 3),
            "model_loaded": model_loaded,
            "model_metrics": model_metrics,
            "parse_errors": sum(len(m.parse_errors) for m in messages),
        },
    )

    return evaluate(assessment, disabled=disabled_rules)


def _attribute_volume(sessions, flows) -> None:
    """Attach each ESP flow's byte volume to the IKE session for its peer pair.

    The association is by address pair rather than by SPI: the child SA's SPI is
    negotiated inside the encrypted IKE_AUTH exchange, so a passive observer can
    never link an ESP SPI to its parent IKE SA cryptographically. Matching on
    peers is the only correlation available, and it is stated here rather than
    hidden because it is an approximation — two tunnels between the same pair of
    gateways will be pooled together.
    """
    for sess in sessions:
        peers = {sess.peer_a, sess.peer_b}
        total = 0
        duration = 0.0
        for flow in flows:
            if {flow.src, flow.dst} & peers:
                total += sum(flow.payload_lengths)
                duration = max(duration, flow.duration)
        sess.observed_bytes = total
        sess.observed_seconds = duration


def throughput_estimate(assessment: Assessment) -> dict:
    """Sustained analysis rate, reported honestly as packets per second measured
    on this host rather than as a claimed line rate."""
    stats = assessment.stats
    elapsed = max(stats.get("analysis_seconds", 0), 1e-6)
    pps = stats.get("packets_read", 0) / elapsed
    return {
        "packets_per_second": round(pps, 1),
        "analysis_seconds": stats.get("analysis_seconds"),
        "note": (
            "Measured single-threaded in the pure-Python reference reader. The "
            "C++/DPDK ingestion path is a separate component; this figure is the "
            "portable path's real rate, not a line-rate claim."
        ),
    }
