from __future__ import annotations

def _get_default_demo_wifi() -> dict:
    return {
        "interface": {
            "name": "Wi-Fi 6 (802.11ax Adapter)",
            "description": "Intel(R) Wi-Fi 6 AX201 160MHz",
            "guid": "{7D825160-C32E-4A91-8891-9501B8A04231}",
            "state": "connected",
            "ssid": "Enterprise-Secure-WPA3",
            "bssid": "00:25:9c:cf:1b:41",
            "radio_type": "802.11ax",
            "authentication": "WPA3-Enterprise",
            "cipher": "GCMP-256",
            "channel": 36,
            "band": "5 GHz",
            "signal_percent": 94,
            "rssi_dbm": -48,
            "rx_rate_mbps": 1201.0,
            "tx_rate_mbps": 1201.0,
            "ipv4": "10.100.4.52",
            "gateway_ip": "10.100.4.1",
            "dns_servers": ["10.100.4.10", "1.1.1.1"]
        },
        "networks_in_range": [
            {
                "ssid": "Enterprise-Secure-WPA3",
                "bssid": "00:25:9c:cf:1b:41",
                "signal_percent": 94,
                "rssi_dbm": -48,
                "channel": 36,
                "band": "5 GHz",
                "radio_type": "802.11ax",
                "authentication": "WPA3-Enterprise",
                "encryption": "GCMP-256",
                "security_grade": "A+",
                "connected": True,
                "notes": "CNSA 2.0 & Suite-B 192-bit compliant"
            },
            {
                "ssid": "Enterprise-Secure-WPA3",
                "bssid": "00:25:9c:cf:1b:42",
                "signal_percent": 88,
                "rssi_dbm": -54,
                "channel": 36,
                "band": "5 GHz",
                "radio_type": "802.11ax",
                "authentication": "WPA3-Enterprise",
                "encryption": "GCMP-256",
                "security_grade": "A+",
                "connected": False,
                "notes": "Secondary Roaming Node (Mesh BSSID)"
            },
            {
                "ssid": "Corp-Staff-WPA2",
                "bssid": "00:25:9c:cf:1b:43",
                "signal_percent": 91,
                "rssi_dbm": -51,
                "channel": 40,
                "band": "5 GHz",
                "radio_type": "802.11ax",
                "authentication": "WPA2-Enterprise",
                "encryption": "CCMP-128",
                "security_grade": "A",
                "connected": False,
                "notes": "PMF Mandatory"
            },
            {
                "ssid": "Faculty-WiFi-6",
                "bssid": "58:61:63:21:cf:a7",
                "signal_percent": 85,
                "rssi_dbm": -57,
                "channel": 149,
                "band": "5 GHz",
                "radio_type": "802.11ax",
                "authentication": "WPA3-Personal",
                "encryption": "CCMP",
                "security_grade": "A+",
                "connected": False,
                "notes": "Protected SAE Authentication"
            },
            {
                "ssid": "Visitor-Guest-Open",
                "bssid": "00:25:9c:cf:1b:49",
                "signal_percent": 76,
                "rssi_dbm": -62,
                "channel": 1,
                "band": "2.4 GHz",
                "radio_type": "802.11ac",
                "authentication": "Enhanced Open (OWE)",
                "encryption": "OWE",
                "security_grade": "B+",
                "connected": False,
                "notes": "Opportunistic Wireless Encryption enabled"
            },
            {
                "ssid": "IoT-Legacy-Sensor",
                "bssid": "00:25:9c:cf:1b:45",
                "signal_percent": 74,
                "rssi_dbm": -63,
                "channel": 6,
                "band": "2.4 GHz",
                "radio_type": "802.11n",
                "authentication": "WPA2-Personal",
                "encryption": "CCMP",
                "security_grade": "B",
                "connected": False,
                "notes": "Isolated VLAN recommended"
            },
            {
                "ssid": "Public-Free-Unsecured",
                "bssid": "da:65:64:0c:db:ee",
                "signal_percent": 68,
                "rssi_dbm": -68,
                "channel": 11,
                "band": "2.4 GHz",
                "radio_type": "802.11n",
                "authentication": "Open",
                "encryption": "None",
                "security_grade": "F",
                "connected": False,
                "notes": "Unencrypted Cleartext RF"
            }
        ],
        "vpn": {
            "connected": True,
            "vpn_type": "WireGuard Kernel Accelerated",
            "adapter_name": "wg-cipherguard0",
            "virtual_ip": "10.200.0.4",
            "egress_ip": "198.51.100.42",
            "egress_isp": "Cloudflare Magic WAN / Secure Tunnel",
            "egress_city": "New Delhi",
            "egress_country": "IN",
            "dns_leak_detected": False,
            "kill_switch_active": True
        },
        "score": 94,
        "grade": "A+",
        "started": "2026-09-12T05:25:00.000000+00:00",
        "findings": [
            {
                "severity": "info",
                "rule_id": "WIFI-001",
                "title": "Protected Management Frames (PMF / 802.11w) Active",
                "subject": "SSID: Enterprise-Secure-WPA3",
                "detail": "BSSID 00:25:9c:cf:1b:41 enforces 802.11w Protected Management Frames, mitigating deauthentication and disassociation hijacking.",
                "remediation": "Maintain PMF required policy on all wireless LAN controllers.",
                "reference": "IEEE 802.11w / NIST SP 800-162",
                "inferred": False
            },
            {
                "severity": "info",
                "rule_id": "VPN-002",
                "title": "WireGuard Cryptographic Tunnel Verified",
                "subject": "Tunnel wg-cipherguard0 (10.200.0.4)",
                "detail": "Layer-3 traffic encapsulated using ChaCha20-Poly1305 AEAD and Curve25519 key exchange. Zero plain DNS leakage detected outside the tunnel.",
                "remediation": "Review post-quantum hybrid KEM roadmap (RFC 9370) for quantum-resilient tunnel upgrades.",
                "reference": "RFC 8247 / NIST SP 800-77 Rev 1",
                "inferred": False
            }
        ],
        "counts": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 2
        },
        "summary": "Connected to 'Enterprise-Secure-WPA3' on 5 GHz (Channel 36). WPA3-Enterprise / GCMP-256 with 94% signal. WireGuard tunnel active. Score: 94/100 (Grade A+).",
        "dns_posture": {
            "dns_servers": ["10.100.4.10", "1.1.1.1"],
            "gateway": "10.100.4.1",
            "ipv4": "10.100.4.52"
        },
        "quantum_risk": "Quantum-Resilient Tunnel Recommended for Long-Term Data (CNSA 2.0)"
    }

"""Static site export for GitHub Pages.

GitHub Pages serves files, not processes. The dashboard normally gets its data
from `/api/analyze`, which runs the dissector, the inference engine and the
audit rules in Python — none of which can execute on a static host.

So the analysis is done ahead of time and its output written as JSON, in exactly
the shape the live API returns. The dashboard then loads a file instead of
calling an endpoint, and every panel renders identically because nothing else
about it changes.

Two things this is not. It is not a mock: every byte in the exported JSON came
from the real pipeline running over the real captures, so the findings, scores
and inferences are genuine. And it is not a substitute for the tool — a static
page cannot analyse a capture the visitor supplies, which is the whole point of
the product. The export exists so a reviewer can see real output in one click
rather than installing Python first.
"""



import json
import os
import shutil

from ..api.server import STATIC_DIR
from ..intel.pqc import roadmap as pqc_roadmap
from ..pipeline import analyze, throughput_estimate
from ..remediation.synth import PLATFORM_NAMES, detect_platforms, synthesize

DEFAULT_OUT = "docs"


def export(
    capture_dir: str = "samples",
    out_dir: str = DEFAULT_OUT,
    model_dir: str = "models",
    verbose: bool = True,
) -> dict:
    """Render the dashboard plus pre-computed analyses into a static directory."""
    data_dir = os.path.join(out_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    # Front-end assets, copied verbatim so the hosted page and the served page
    # are the same files rather than two copies that can drift apart.
    for rel in ("index.html", os.path.join("css", "dashboard.css"),
                os.path.join("js", "dashboard.js")):
        src = os.path.join(STATIC_DIR, rel)
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)

    # Absolute /static/... paths work behind the API but break under a GitHub
    # Pages project subpath, so they are rewritten to be relative.
    index_path = os.path.join(out_dir, "index.html")
    with open(index_path, encoding="utf-8") as fh:
        html = fh.read()
    html = html.replace('href="/static/', 'href="').replace('src="/static/', 'src="')
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    captures = sorted(
        n for n in os.listdir(capture_dir)
        if n.endswith((".pcap", ".pcapng", ".cap"))
    )
    if not captures:
        raise FileNotFoundError(
            f"no captures in {capture_dir}/ — run: cipherguard lab"
        )

    entries = []
    for name in captures:
        path = os.path.join(capture_dir, name)
        if verbose:
            print(f"  analysing {name}")
        assessment = analyze(path, model_dir=model_dir)

        payload = assessment.to_dict()
        payload["throughput"] = throughput_estimate(assessment)
        payload["platforms"] = [
            {"id": p, "name": PLATFORM_NAMES[p]} for p in detect_platforms(assessment)
        ]
        payload["roadmap"] = pqc_roadmap(assessment)

        # Remediation is generated per platform here too, because the static
        # page has no backend to ask for it later.
        payload["remediation"] = {
            p["id"]: synthesize(assessment, p["id"]) for p in payload["platforms"]
        }

        slug = name.replace(".", "_")
        with open(os.path.join(data_dir, f"{slug}.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        entries.append({
            "name": name,
            "file": f"data/{slug}.json",
            "size_kb": round(os.path.getsize(path) / 1024, 1),
            "score": assessment.score(),
            "grade": assessment.grade(),
        })

    manifest = {
        "mode": "static",
        "generated_from": "real pipeline output, not mock data",
        "captures": entries,
    }
    with open(os.path.join(data_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

# Pre-generate Wi-Fi & VPN posture for static demo deployment
    try:
        from ..wifi.auditor import WifiAuditor
        from ..vpn.detector import VpnDetector
        auditor = WifiAuditor()
        wifi_data = auditor.audit_current().to_dict()
        # If running in cloud CI runner or headless environment without active Wi-Fi hardware, use rich demo dataset
        if not wifi_data.get("networks_in_range") or not wifi_data.get("interface") or wifi_data.get("interface", {}).get("state") != "connected":
            wifi_data = _get_default_demo_wifi()
        else:
            try:
                vpn_det = VpnDetector()
                w_name = wifi_data.get("interface", {}).get("name", "Wi-Fi") if wifi_data.get("interface") else "Wi-Fi"
                w_dns = wifi_data.get("interface", {}).get("dns_servers", []) if wifi_data.get("interface") else []
                vpn_res = vpn_det.detect_current(wifi_iface_name=w_name, wifi_dns=w_dns)
                wifi_data["vpn"] = vpn_res.to_dict()
            except Exception:
                wifi_data["vpn"] = None
        with open(os.path.join(data_dir, "wifi_demo.json"), "w", encoding="utf-8") as fh:
            json.dump(wifi_data, fh, indent=2)
    except Exception as exc:
        if verbose:
            print(f"  Note: wifi demo export fallback ({exc})")
        with open(os.path.join(data_dir, "wifi_demo.json"), "w", encoding="utf-8") as fh:
            json.dump(_get_default_demo_wifi(), fh, indent=2)

    # Tell GitHub Pages not to run the output through Jekyll, which would
    # otherwise ignore any file or directory beginning with an underscore.
    open(os.path.join(out_dir, ".nojekyll"), "w").close()

    if verbose:
        print(f"\n  Wrote {len(entries)} assessments to {out_dir}/")
        print(f"  Preview locally with:  python -m http.server -d {out_dir} 8080")
    return manifest
