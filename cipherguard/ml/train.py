"""Train the ESP suite classifier against the reference testbed corpus."""

from __future__ import annotations

import argparse
import time

from . import features as F
from .classifier import SuiteClassifier
from .synth import build_corpus

DEFAULT_MODEL_DIR = "models"


def holdout_eval(model: SuiteClassifier, seed: int = 909, per_suite: int = 40) -> dict:
    """Evaluate through the complete inference path on flows the model never saw.

    The metrics computed inside `fit` score the raw ensemble on feature vectors.
    That is not what ships: predictions in production also pass the RFC 4303
    plausibility mask, and they are consumed at framing-class granularity. So the
    numbers that matter are measured here, on freshly generated flows, through
    `predict_one` exactly as the pipeline calls it.
    """
    from ..audit.policy import framing_class_of

    flows, labels = build_corpus(samples_per_suite=per_suite, seed=seed)
    exact = grouped = 0
    confusion: dict[str, dict[str, int]] = {}

    for flow, truth in zip(flows, labels):
        pred = model.predict_one(flow)
        exact += pred.label == truth
        true_cls, _ = framing_class_of(truth)
        pred_cls, _ = framing_class_of(pred.label)
        grouped += true_cls == pred_cls
        confusion.setdefault(true_cls or "?", {})
        confusion[true_cls or "?"][pred_cls or "?"] = (
            confusion[true_cls or "?"].get(pred_cls or "?", 0) + 1
        )

    n = len(flows)
    return {
        "n": n,
        "exact_suite_accuracy": round(exact / n, 4),
        "framing_class_accuracy": round(grouped / n, 4),
        "class_confusion": confusion,
    }


def train(
    samples_per_suite: int = 90,
    epochs: int = 60,
    seed: int = 42,
    out: str = DEFAULT_MODEL_DIR,
    verbose: bool = True,
) -> dict:
    if verbose:
        print(f"Building reference corpus ({samples_per_suite} flows per suite)")
    flows, labels = build_corpus(samples_per_suite=samples_per_suite, seed=seed)

    t0 = time.time()
    X = F.extract_batch(flows)
    if verbose:
        print(f"Extracted {X.shape[0]}x{X.shape[1]} features in {time.time() - t0:.1f}s")

    model = SuiteClassifier()
    metrics = model.fit(X, labels, epochs=epochs, seed=seed, verbose=verbose)

    if verbose:
        print("Evaluating the full inference path on held-out flows")
    metrics["holdout"] = holdout_eval(model, seed=seed + 867)
    model.metrics = metrics
    model.save(out)

    if verbose:
        h = metrics["holdout"]
        print(f"\n  Random Forest, raw ensemble input   {metrics['rf_accuracy']:.1%}")
        print(f"  1D-CNN, raw ensemble input          {metrics['cnn_accuracy']:.1%}")
        print(f"  Ensemble, no plausibility mask      {metrics['ensemble_accuracy']:.1%}")
        print(f"\n  Held out, exact suite               {h['exact_suite_accuracy']:.1%}")
        print(f"  Held out, framing class             {h['framing_class_accuracy']:.1%}")
        print(
            "\n  Exact-suite accuracy is capped well below 100% by design: suites\n"
            "  sharing IV, ICV and block size are not separable from passive\n"
            "  observation at all. Framing class is the number that governs the\n"
            "  audit verdict, and it is what the findings are phrased against."
        )
        print(f"\nSaved to {out}/")
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the ESP inference model")
    ap.add_argument("--samples", type=int, default=90, help="flows per suite")
    ap.add_argument("--epochs", type=int, default=60, help="CNN training epochs")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=DEFAULT_MODEL_DIR)
    args = ap.parse_args()
    train(args.samples, args.epochs, args.seed, args.out)


if __name__ == "__main__":
    main()
