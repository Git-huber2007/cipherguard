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

from __future__ import annotations

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

    # Tell GitHub Pages not to run the output through Jekyll, which would
    # otherwise ignore any file or directory beginning with an underscore.
    open(os.path.join(out_dir, ".nojekyll"), "w").close()

    if verbose:
        print(f"\n  Wrote {len(entries)} assessments to {out_dir}/")
        print(f"  Preview locally with:  python -m http.server -d {out_dir} 8080")
    return manifest
