import os
import sys
import shutil

# Ensure workspace root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from cipherguard.api.server import create_app

# Vercel Serverless environment provides /tmp as the only writable directory
tmp_samples = "/tmp/cipherguard_samples"
tmp_db = "/tmp/cipherguard-baseline.db"
os.makedirs(tmp_samples, exist_ok=True)

# Seed bundled sample captures to /tmp if present
bundled_samples = os.path.join(BASE_DIR, "samples")
if os.path.exists(bundled_samples):
    for fname in os.listdir(bundled_samples):
        src = os.path.join(bundled_samples, fname)
        dst = os.path.join(tmp_samples, fname)
        if os.path.isfile(src) and not os.path.exists(dst):
            try:
                shutil.copy2(src, dst)
            except Exception:
                pass

bundled_models = os.path.join(BASE_DIR, "models")
model_dir = bundled_models if os.path.exists(bundled_models) else "models"

# Instantiate ASGI application for Vercel
app = create_app(
    model_dir=model_dir,
    capture_dir=tmp_samples,
    baseline_db=tmp_db,
    allow_upload=True,
)
