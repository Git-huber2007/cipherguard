"""Tests for the live Wi-Fi auditing and wireless posture module."""

from cipherguard.wifi.auditor import WifiAuditor
from cipherguard.wifi.models import SecurityFinding, WifiAssessment, WifiInterfaceInfo, WifiNetwork


def test_wifi_models_serialization():
    f = SecurityFinding(
        severity="high",
        rule_id="WIFI-001",
        title="Test Finding",
        subject="Test AP",
        detail="Test detail",
        remediation="Test fix",
    )
    assert f.to_dict()["rule_id"] == "WIFI-001"

    net = WifiNetwork(
        ssid="TestSSID",
        bssid="00:11:22:33:44:55",
        signal_percent=90,
        rssi_dbm=-45,
        channel=36,
        band="5 GHz",
        radio_type="802.11ac",
        authentication="WPA3-Personal",
        encryption="CCMP",
        security_grade="A+",
    )
    d = net.to_dict()
    assert d["ssid"] == "TestSSID"
    assert d["security_grade"] == "A+"

    iface = WifiInterfaceInfo(
        name="Wi-Fi",
        description="Wireless NIC",
        mac_address="50:fe:0c:5d:83:54",
        state="connected",
        ssid="TestSSID",
        bssid="00:11:22:33:44:55",
        band="5 GHz",
        channel=36,
        radio_type="802.11ac",
        authentication="WPA2-Personal",
        cipher="CCMP",
        signal_percent=85,
        rssi_dbm=-50,
    )
    assessment = WifiAssessment(interface=iface, networks_in_range=[net], score=85, grade="B")
    ad = assessment.to_dict()
    assert ad["score"] == 85
    assert ad["grade"] == "B"
    assert ad["interface"]["ssid"] == "TestSSID"
    assert len(ad["networks_in_range"]) == 1


def test_wifi_auditor_grading():
    auditor = WifiAuditor()
    assert auditor._grade_network("Open", "None") == "F"
    assert auditor._grade_network("WEP", "WEP") == "F"
    assert auditor._grade_network("WPA-Personal", "TKIP") == "D"
    assert auditor._grade_network("WPA2-Personal", "CCMP") == "B"
    assert auditor._grade_network("WPA3-Personal", "CCMP") == "A+"


def test_wifi_auditor_live_or_fallback():
    auditor = WifiAuditor()
    assessment = auditor.audit_current()
    assert isinstance(assessment, WifiAssessment)
    assert isinstance(assessment.score, int)
    assert 0 <= assessment.score <= 100
    assert assessment.grade in ("A+", "A", "B", "C", "D", "F", "—")
    assert isinstance(assessment.findings, list)


def test_is_private_ip():
    from cipherguard.wifi.auditor import _is_private_ip
    assert _is_private_ip("192.168.1.1") is True
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("172.16.0.1") is True
    assert _is_private_ip("172.31.255.254") is True
    assert _is_private_ip("172.32.0.1") is False
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("1.1.1.1") is False
    assert _is_private_ip("invalid-ip") is False


def test_live_capture_linktype_attribute():
    import sys
    from cipherguard.capture.live import LiveCapture
    from cipherguard.dissector.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

    cap = LiveCapture("test-iface")
    if sys.platform.startswith("win"):
        assert cap.linktype == LINKTYPE_RAW
    else:
        assert cap.linktype == LINKTYPE_ETHERNET


def test_connected_bssid_isolation():
    auditor = WifiAuditor()
    raw_output = """
SSID 1 : Campus-Mesh
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP 
    BSSID 1                 : 11:22:33:44:55:01
         Signal             : 90%
         Radio type         : 802.11ax
         Channel            : 36 
         Band               : 5 GHz
    BSSID 2                 : 11:22:33:44:55:02
         Signal             : 80%
         Radio type         : 802.11ax
         Channel            : 44 
         Band               : 5 GHz
    BSSID 3                 : 11:22:33:44:55:03
         Signal             : 70%
         Radio type         : 802.11ax
         Channel            : 149 
         Band               : 5 GHz
"""
    import unittest.mock as mock
    WifiAuditor._bss_cache.clear()
    with mock.patch("subprocess.check_output", return_value=raw_output):
        # Target only BSSID 2
        nets = auditor._get_windows_networks(
            connected_ssid="Campus-Mesh",
            connected_bssid="11:22:33:44:55:02",
            force_scan=False,
        )
        connected_nets = [n for n in nets if n.connected]
        assert len(connected_nets) == 1
        assert connected_nets[0].bssid == "11:22:33:44:55:02"
        # The other 2 BSSIDs should be false
        other_nets = [n for n in nets if not n.connected]
        assert len(other_nets) == 2
    WifiAuditor._bss_cache.clear()


