import os
import sys
import shutil
import traceback

# Add multiple candidate root paths to sys.path so cipherguard is always importable
this_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(this_dir)
cwd = os.getcwd()

for candidate in [cwd, parent_dir, this_dir]:
    if candidate and candidate not in sys.path and os.path.exists(candidate):
        sys.path.insert(0, candidate)

try:
    from cipherguard.api.server import create_app
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    BASE_DIR = parent_dir if os.path.exists(os.path.join(parent_dir, "cipherguard")) else cwd
    bundled_samples = os.path.join(BASE_DIR, "samples")
    bundled_models = os.path.join(BASE_DIR, "models")
    tmp_samples = "/tmp/cipherguard_samples"
    tmp_db = "/tmp/cipherguard-baseline.db"

    os.makedirs(tmp_samples, exist_ok=True)

    app = create_app(
        model_dir=bundled_models if os.path.exists(bundled_models) else "models",
        capture_dir=tmp_samples,
        baseline_db=tmp_db,
        allow_upload=True,
    )

    # Lazy seeder: copy sample pcaps to /tmp on startup or first request rather than blocking import
    @app.on_event("startup")
    def seed_samples():
        if os.path.exists(bundled_samples):
            for fname in os.listdir(bundled_samples):
                src = os.path.join(bundled_samples, fname)
                dst = os.path.join(tmp_samples, fname)
                if os.path.isfile(src) and not os.path.exists(dst):
                    try:
                        shutil.copy2(src, dst)
                    except Exception:
                        pass

except Exception as e:
    # Diagnostic fallback app: if an unhandled startup exception occurs,
    # return the exact traceback rather than crashing Lambda with FUNCTION_INVOCATION_FAILED
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="CipherGuard - Startup Diagnostic")
    err_tb = traceback.format_exc()

    @app.get("/{full_path:path}")
    def diagnostic_fallback(full_path: str = ""):
        return HTMLResponse(
            f"<html><body><h2>CipherGuard Startup Error</h2>"
            f"<p>An error occurred during serverless function initialization:</p>"
            f"<pre style='background:#f4f4f4;padding:12px;border:1px solid #ccc;'>{err_tb}</pre>"
            f"<p>Python Path: {sys.path}</p>"
            f"<p>Working Directory: {os.getcwd()}</p>"
            f"</body></html>",
            status_code=500,
        )
