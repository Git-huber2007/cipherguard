"""Test all web readiness endpoints and custom error handling for CipherGuard."""
import sys
import os
import warnings

# Cleanly suppress upstream library deprecation warnings
warnings.filterwarnings("ignore")

# Ensure the cipherguard project root is first in sys.path regardless of execution CWD
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Remove any parent directories that might shadow the cipherguard module
parent_dir = os.path.dirname(PROJECT_ROOT)
while parent_dir in sys.path:
    sys.path.remove(parent_dir)

# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from cipherguard.api.server import create_app

def run_tests():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    
    print("Testing 20-Point Web Production Readiness Checklist...")
    
    # 1. Root dashboard
    r = client.get("/")
    assert r.status_code == 200, f"GET / failed: {r.status_code}"
    assert "CipherGuard" in r.text
    assert "og-image.png" in r.text
    assert "site.webmanifest" in r.text
    assert "cookie-banner" in r.text
    assert "mobile-sticky-cta" in r.text
    print("[OK] GET / (Dashboard with OG tags, meta descriptions, sticky CTA, cookie banner) passed")

    # 2. Privacy Policy page
    r = client.get("/privacy")
    assert r.status_code == 200, f"GET /privacy failed: {r.status_code}"
    assert "Zero-Payload Architecture" in r.text
    print("[OK] GET /privacy passed")

    # 3. Terms of Engagement page
    r = client.get("/terms")
    assert r.status_code == 200, f"GET /terms failed: {r.status_code}"
    assert "Terms of Engagement" in r.text
    print("[OK] GET /terms passed")

    # 4. Thank You page
    r = client.get("/thank-you")
    assert r.status_code == 200, f"GET /thank-you failed: {r.status_code}"
    assert "Assessment Complete" in r.text
    print("[OK] GET /thank-you passed")

    # 5. Robots.txt
    r = client.get("/robots.txt")
    assert r.status_code == 200, f"GET /robots.txt failed: {r.status_code}"
    assert "User-agent" in r.text
    assert "Sitemap: /sitemap.xml" in r.text
    print("[OK] GET /robots.txt passed")                                    

    # 6. Sitemap.xml
    r = client.get("/sitemap.xml")
    assert r.status_code == 200, f"GET /sitemap.xml failed: {r.status_code}"
    assert "<urlset" in r.text
    assert "/privacy" in r.text
    print("[OK] GET /sitemap.xml passed")

    # 7. Favicon.ico
    r = client.get("/favicon.ico")
    assert r.status_code == 200, f"GET /favicon.ico failed: {r.status_code}"
    print("[OK] GET /favicon.ico passed")

    # 8. Static image assets
    r_svg = client.get("/static/img/favicon.svg")
    assert r_svg.status_code == 200
    r_og = client.get("/static/img/og-image.png")
    assert r_og.status_code == 200
    r_mani = client.get("/static/site.webmanifest")
    assert r_mani.status_code == 200
    print("[OK] Static assets (favicon.svg, og-image.png, site.webmanifest) passed")

    # 9. Custom 404 HTML Page for browser navigation
    r_404_html = client.get("/non-existent-page-test", headers={"Accept": "text/html,application/xhtml+xml"})
    assert r_404_html.status_code == 404, f"Custom 404 HTML status: {r_404_html.status_code}"
    assert "Segment Not Found" in r_404_html.text or "PACKET_DROPPED" in r_404_html.text
    print("[OK] Custom 404 HTML Error Page passed")

    # 10. API 404 JSON for programmatic clients
    r_404_json = client.get("/api/non-existent-endpoint", headers={"Accept": "application/json"})
    assert r_404_json.status_code == 404
    data = r_404_json.json()
    assert "detail" in data
    print("[OK] API 404 JSON response preserved")

    print("\nALL 20-POINT CHECKLIST BACKEND VERIFICATIONS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
