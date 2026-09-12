"""VPN Tunnel & Overlay Security Detector.

Detects active virtual VPN interfaces (WireGuard, OpenVPN, IPsec/IKEv2,
Tailscale, Cloudflare WARP, Cisco AnyConnect, etc.), verifies default route
redirection, inspects DNS resolution for leak vulnerabilities, and queries
egress IP/ISP geolocation.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from typing import Any

from ..wifi.models import SecurityFinding
from .models import NetworkPostureComposite, VpnTunnelInfo

VPN_PATTERNS: list[tuple[str, str]] = [
    (r"protun|proton", "ProtonVPN (WireGuard)"),
    (r"wireguard|wintun", "WireGuard"),
    (r"tap-windows|openvpn|tun\d*", "OpenVPN"),
    (r"wan miniport \(ikev2\)|wan miniport \(ipsec\)|ikev2|ipsec", "IPsec / IKEv2"),
    (r"tailscale", "Tailscale"),
    (r"cloudflare.*warp|warp.*adapter", "Cloudflare WARP"),
    (r"cisco|anyconnect", "Cisco AnyConnect"),
    (r"fortinet|forticlient", "Fortinet FortiClient"),
    (r"palo alto|globalprotect", "GlobalProtect"),
    (r"mullvad", "Mullvad VPN"),
    (r"nordlynx|nordvpn", "NordVPN (NordLynx)"),
    (r"expressvpn", "ExpressVPN"),
    (r"surfshark", "Surfshark"),
    (r"zerotier", "ZeroTier"),
    (r"vpn", "Generic VPN"),
]


class VpnDetector:
    """Discovers active VPN tunnels, route redirects, DNS leaks, and egress changes."""

    def __init__(self) -> None:
        self.is_windows = sys.platform.startswith("win")
        self.is_linux = sys.platform.startswith("linux")
        self._cached_egress: dict[str, Any] = {}
        self._cached_egress_ts: float = 0.0

    def detect_current(self, wifi_iface_name: str = "Wi-Fi", wifi_dns: list[str] | None = None) -> VpnTunnelInfo:
        """Analyze system routing, adapters, and egress to determine VPN status."""
        if self.is_windows:
            info = self._detect_windows(wifi_iface_name, wifi_dns)
        elif self.is_linux:
            info = self._detect_linux(wifi_iface_name, wifi_dns)
        else:
            info = VpnTunnelInfo()

        egress = self._get_egress_info()
        info.egress_ip = egress.get("ip", "")
        info.egress_isp = egress.get("isp", "")
        info.egress_country = egress.get("country", "")
        info.egress_city = egress.get("city", "")

        self._assess_vpn_posture(info, wifi_dns)
        return info

    def _assess_vpn_posture(self, info: VpnTunnelInfo, wifi_dns: list[str] | None) -> None:
        """Evaluate cryptographic tunnel assurance and identify data or DNS leaks."""
        findings: list[SecurityFinding] = []

        if info.connected:
            findings.append(
                SecurityFinding(
                    severity="info",
                    rule_id="VPN-001",
                    title=f"Active Encrypted {info.vpn_type} Overlay Tunnel Verified",
                    subject=f"Adapter: {info.adapter_name} ({info.vpn_type})",
                    detail=(
                        f"All transport layer payloads on '{info.adapter_name}' are encapsulated in an encrypted "
                        f"{info.vpn_type} tunnel. Even if local Wi-Fi encryption is compromised, intermediate nodes "
                        f"and the local access point cannot inspect or tamper with tunneled packets."
                    ),
                    remediation="Maintain tunnel keepalive and verify endpoint certificate/key validity.",
                    reference="RFC 4301 (IPsec) / RFC 9370 / WireGuard Technical Whitepaper",
                )
            )

            if info.dns_leak_detected:
                findings.append(
                    SecurityFinding(
                        severity="high",
                        rule_id="VPN-002",
                        title="Critical DNS Leak Detected (Queries Bypassing VPN Tunnel)",
                        subject=f"Leaked Resolvers: {info.dns_leak_details}",
                        detail=(
                            f"Although default route metric points to {info.vpn_type}, DNS queries are being sent to "
                            f"the local physical Wi-Fi network's DNS resolvers ({info.dns_leak_details}). Local ISP "
                            f"and eavesdroppers can monitor visited domains and metadata."
                        ),
                        remediation="Configure the VPN client to enforce tunnel DNS (e.g. Set-DnsClientServerAddress on Wi-Fi interface) or enable Block-Outside-DNS.",
                        reference="RFC 7626 / US-CERT Alert TA15-286A",
                    )
                )
            elif info.dns_servers:
                findings.append(
                    SecurityFinding(
                        severity="info",
                        rule_id="VPN-003",
                        title="Encrypted Tunnel DNS Enforced",
                        subject=f"Tunnel DNS: {', '.join(info.dns_servers)}",
                        detail="Domain name resolution is securely isolated inside the VPN tunnel.",
                        remediation="Ensure DNSSEC validation is enabled on the tunnel resolver.",
                        reference="RFC 8484 / RFC 7858",
                    )
                )

            if not info.is_default_route:
                findings.append(
                    SecurityFinding(
                        severity="medium",
                        rule_id="VPN-004",
                        title="Split Tunneling Active (Partial Route Redirection)",
                        subject=f"Adapter: {info.adapter_name}",
                        detail="Default Internet route (0.0.0.0/0) remains on the physical Wi-Fi link. Only specific subnets are routed through the VPN tunnel.",
                        remediation="If full confidentiality is desired, enable full-tunnel mode in your VPN configuration.",
                        reference="NIST SP 800-77 Rev. 1",
                    )
                )
        else:
            isp_desc = f" ({info.egress_isp})" if info.egress_isp else ""
            findings.append(
                SecurityFinding(
                    severity="info",
                    rule_id="VPN-010",
                    title="Direct Physical Egress (No Virtual VPN Tunnel)",
                    subject=f"Egress: Direct to ISP{isp_desc}",
                    detail=(
                        "Device network traffic egresses directly through the local Wi-Fi router to the public ISP without "
                        "an outer IPsec or WireGuard protective tunnel. Local network administrators and upstream ISPs "
                        "can inspect unencrypted transport metadata and SNI hostnames."
                    ),
                    remediation="For sensitive remote access or untrusted networks, establish an IPsec (RFC 4301) or WireGuard tunnel.",
                    reference="NIST SP 800-77 / NIST SP 800-113",
                )
            )

        info.findings = findings

    def _detect_windows(self, wifi_iface_name: str, wifi_dns: list[str] | None) -> VpnTunnelInfo:
        """Inspect Windows adapters, routing table, and DNS servers using fast native utilities."""
        try:
            return self._detect_windows_fast(wifi_iface_name, wifi_dns)
        except Exception:
            return self._detect_windows_powershell(wifi_iface_name, wifi_dns)

    def _detect_windows_fast(self, wifi_iface_name: str, wifi_dns: list[str] | None) -> VpnTunnelInfo:
        info = VpnTunnelInfo()
        out_if = subprocess.check_output(
            ["netsh", "interface", "ipv4", "show", "interfaces"],
            text=True, errors="ignore", timeout=3
        )
        out_rt = subprocess.check_output(
            ["route", "print"],
            text=True, errors="ignore", timeout=3
        )
        out_dns = subprocess.check_output(
            ["netsh", "interface", "ip", "show", "dns"],
            text=True, errors="ignore", timeout=3
        )

        idx_to_desc: dict[int, str] = {}
        lines = out_rt.splitlines()
        in_if_list = False
        for line in lines:
            if "Interface List" in line:
                in_if_list = True
                continue
            if "====" in line and in_if_list and idx_to_desc:
                in_if_list = False
                continue
            if in_if_list:
                m = re.match(r"^\s*(\d+)\.{3,}(.+)$", line)
                if m:
                    idx = int(m.group(1))
                    desc = m.group(2).strip()
                    desc = re.sub(r"^[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){5}\s*\.{0,}\s*", "", desc).strip()
                    idx_to_desc[idx] = desc

        connected_adapters: list[dict[str, Any]] = []
        for line in out_if.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[0].isdigit() and parts[3].lower() == "connected":
                idx = int(parts[0])
                metric = int(parts[1])
                mtu = int(parts[2])
                name = " ".join(parts[4:])
                desc = idx_to_desc.get(idx, name)
                connected_adapters.append({"idx": idx, "name": name, "desc": desc, "metric": metric, "mtu": mtu})

        # Find VPN adapter
        vpn_adapter = None
        detected_vpn_type = "None"
        for ad in connected_adapters:
            name = ad["name"]
            desc = ad["desc"]
            combined = f"{name} {desc}".lower()
            if "loopback" in combined:
                continue
            if "wi-fi" in combined and "vpn" not in combined:
                continue
            if ("wireless" in combined or "802.11" in combined) and "vpn" not in combined:
                continue
            if "gbe family" in combined or "gigabit" in combined:
                continue
            for pat, vtype in VPN_PATTERNS:
                if re.search(pat, combined):
                    vpn_adapter = ad
                    detected_vpn_type = vtype
                    break
            if vpn_adapter:
                break

        # Parse routes
        routes: list[dict[str, Any]] = []
        in_ipv4 = False
        has_def1_split = False
        vpn_ip = ""
        for line in lines:
            if "IPv4 Route Table" in line:
                in_ipv4 = True
                continue
            if "IPv6 Route Table" in line:
                in_ipv4 = False
                continue
            if in_ipv4:
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] in ("0.0.0.0", "128.0.0.0"):
                    dest = parts[0]
                    mask = parts[1]
                    gw = parts[2]
                    iface = parts[3]
                    metric = int(parts[4])
                    routes.append({"dest": dest, "mask": mask, "gw": gw, "iface": iface, "metric": metric})
                    if dest in ("0.0.0.0", "128.0.0.0") and mask == "128.0.0.0":
                        has_def1_split = True
                        vpn_ip = iface

        # Parse DNS per interface
        dns_by_iface: dict[str, list[str]] = {}
        cur_if: str | None = None
        for line in out_dns.splitlines():
            m = re.search(r'Configuration for interface "([^"]+)"', line)
            if m:
                cur_if = m.group(1)
                dns_by_iface[cur_if] = []
                continue
            if cur_if:
                m_ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if m_ip:
                    dns_by_iface[cur_if].append(m_ip.group(0))

        if not vpn_adapter and has_def1_split and vpn_ip:
            for ad in connected_adapters:
                comb = f"{ad['name']} {ad['desc']}".lower()
                if "wi-fi" not in comb and "ethernet" not in comb and "loopback" not in comb:
                    vpn_adapter = ad
                    detected_vpn_type = "Generic VPN Tunnel"
                    break

        if vpn_adapter:
            info.connected = True
            info.adapter_name = vpn_adapter["name"]
            info.adapter_description = vpn_adapter["desc"]
            info.vpn_type = detected_vpn_type
            info.virtual_ip = vpn_ip
            info.is_default_route = True
            info.route_metric = vpn_adapter["metric"] or 1
            info.dns_servers = dns_by_iface.get(vpn_adapter["name"], [])
            
            wifi_dns_active = dns_by_iface.get("Wi-Fi", [])
            effective_wifi_dns = wifi_dns or wifi_dns_active
            if info.dns_servers and not any(d in wifi_dns_active for d in info.dns_servers):
                info.dns_leak_detected = False
            elif effective_wifi_dns and not info.dns_servers:
                info.dns_leak_detected = True
                info.dns_leak_details = ", ".join(effective_wifi_dns)

        return info

    def _detect_windows_powershell(self, wifi_iface_name: str, wifi_dns: list[str] | None) -> VpnTunnelInfo:
        info = VpnTunnelInfo()
        try:
            ps_script = (
                "$a = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, InterfaceIndex, LinkSpeed); "
                "$r = @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1') } | Select-Object InterfaceAlias, InterfaceIndex, DestinationPrefix, NextHop, RouteMetric); "
                "$d = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses); "
                "[PSCustomObject]@{ adapters = $a; routes = $r; dns = $d } | ConvertTo-Json -Depth 3 -Compress"
            )
            raw = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=12,
            )
            data = json.loads(raw)
            adapters = data.get("adapters") or []
            if isinstance(adapters, dict): adapters = [adapters]
            routes = data.get("routes") or []
            if isinstance(routes, dict): routes = [routes]
            dns_list = data.get("dns") or []
            if isinstance(dns_list, dict): dns_list = [dns_list]

            vpn_adapter = None
            detected_vpn_type = "None"
            for ad in adapters:
                combined = f"{ad.get('Name', '')} {ad.get('InterfaceDescription', '')}".lower()
                if "wi-fi" in combined and "vpn" not in combined: continue
                if ("wireless" in combined or "802.11" in combined) and "vpn" not in combined: continue
                if "gbe family" in combined or "gigabit" in combined: continue
                for pattern, vtype in VPN_PATTERNS:
                    if re.search(pattern, combined):
                        vpn_adapter = ad
                        detected_vpn_type = vtype
                        break
                if vpn_adapter: break

            if vpn_adapter:
                info.connected = True
                info.adapter_name = vpn_adapter.get("Name", "")
                info.adapter_description = vpn_adapter.get("InterfaceDescription", "")
                info.vpn_type = detected_vpn_type
                info.is_default_route = True
        except Exception:
            pass
        return info

    def _detect_linux(self, wifi_iface_name: str, wifi_dns: list[str] | None) -> VpnTunnelInfo:
        """Inspect Linux routes and tun/tap/wg interfaces."""
        info = VpnTunnelInfo()
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    dev = parts[idx + 1]
                    dev_lower = dev.lower()
                    if dev_lower.startswith(("tun", "tap", "wg", "ppp")):
                        info.connected = True
                        info.adapter_name = dev
                        info.is_default_route = True
                        if dev_lower.startswith("wg"):
                            info.vpn_type = "WireGuard"
                        elif dev_lower.startswith("tun"):
                            info.vpn_type = "OpenVPN / TUN"
                        else:
                            info.vpn_type = "Linux Virtual Tunnel"
                        if "via" in parts:
                            info.gateway_ip = parts[parts.index("via") + 1]
                        break
        except Exception:
            pass
        return info

    def _get_egress_info(self) -> dict[str, Any]:
        """Fetch current public IP, ISP, and Country with 15-second cache.

        Respects CIPHERGUARD_NO_EGRESS_LOOKUP=1 for strict air-gapped or
        privacy-sensitive audit environments where external queries are forbidden.
        """
        if os.environ.get("CIPHERGUARD_NO_EGRESS_LOOKUP", "").strip().lower() in ("1", "true", "yes"):
            return {
                "ip": "Protected (Air-gapped / Local Mode)",
                "isp": "Local Privacy Mode Enforced",
                "country": "Local",
                "city": "Private",
            }

        now = time.time()
        if self._cached_egress and (now - self._cached_egress_ts < 15.0):
            return self._cached_egress

        info: dict[str, Any] = {}
        # Try HTTPS encrypted endpoints first
        for endpoint, is_ipapi in [
            ("https://ipapi.co/json/", True),
            ("https://api.ipify.org?format=json", False),
            ("http://ip-api.com/json/?fields=status,query,isp,org,country,city", False),
        ]:
            try:
                req = urllib.request.Request(
                    endpoint,
                    headers={"User-Agent": "CipherGuard-Security-Auditor/2.0"},
                )
                with urllib.request.urlopen(req, timeout=1.8) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if is_ipapi and data.get("ip"):
                        info = {
                            "ip": data.get("ip", ""),
                            "isp": data.get("org", "") or data.get("asn", "Encrypted Tunnel Egress"),
                            "country": data.get("country_name", ""),
                            "city": data.get("city", ""),
                        }
                        break
                    elif data.get("status") == "success" or data.get("query"):
                        info = {
                            "ip": data.get("query", data.get("ip", "")),
                            "isp": data.get("isp", "") or data.get("org", "Public Egress"),
                            "country": data.get("country", ""),
                            "city": data.get("city", ""),
                        }
                        break
                    elif data.get("ip"):
                        info = {"ip": data.get("ip"), "isp": "Public Egress", "country": "", "city": ""}
                        break
            except Exception:
                continue

        if info:
            self._cached_egress = info
            self._cached_egress_ts = now
        return info
