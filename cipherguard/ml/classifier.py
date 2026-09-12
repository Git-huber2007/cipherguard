"""ESP cipher-suite inference engine.

Two models with different failure modes, combined by soft voting:

  Random Forest   reads the scalar and modulo features as thresholds. Excellent
                  at the structural signal (block size, ICV length), essentially
                  a learned version of the RFC 4303 framing arithmetic.
  1D-CNN          reads the 64-point distribution profile as a signal and picks
                  up shape — where the residue peak sits and how sharp it is —
                  which generalises better to padding regimes not in training.

The ensemble reports a calibrated probability, and callers are expected to check
it. Suites that share IV length, ICV length and block size are not separable from
framing alone; ``ambiguity_group`` names those cases so the audit engine can
report "AES-CTR or AES-GCM" instead of guessing one and stating it as fact.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from ..core.constants import ESP_SUITES
from ..core.models import EspFlow
from . import features as F
from .cnn import EspCNN

# Suites whose ESP framing is byte-for-byte identical. Any prediction inside a
# group is really a prediction of the group; the members differ only by weak
# timing signal and must not be reported as certain.
AMBIGUITY_GROUPS = [
    {"AES-CTR-128 / HMAC-SHA2-256-128", "AES-GCM-128 (ICV 16)",
     "AES-GCM-256 (ICV 16)", "ChaCha20-Poly1305"},
    {"3DES-CBC / HMAC-MD5-96", "DES-CBC / HMAC-SHA1-96"},
]


def ambiguity_group(label: str) -> set[str]:
    for group in AMBIGUITY_GROUPS:
        if label in group:
            return group
    return {label}


SCHEMA_VERSION = 2


class ModelSchemaError(RuntimeError):
    """A stored model does not match the current feature schema."""


class ModelIntegrityError(RuntimeError):
    """A stored model's contents do not match its signed manifest."""


def _sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def feature_hash() -> str:
    """Fingerprint of the feature contract a model was fitted against."""
    import hashlib

    payload = "|".join(F.FEATURE_NAMES) + f"|signal={F.SIGNAL_LEN}"
    return hashlib.sha256(payload.encode()).hexdigest()


MIN_CIPHERTEXT_ENTROPY = 6.8  # below this, the payload is not cipher output
MAX_PLAINTEXT_ENTROPY = 7.2   # above this, the payload is not plaintext


@dataclass
class Prediction:
    label: str
    confidence: float
    ranked: list[tuple[str, float]]
    group: list[str]
    group_confidence: float
    excluded: list[tuple[str, str]] | None = None  # (suite, why it was ruled out)

    @property
    def ambiguous(self) -> bool:
        return len(self.group) > 1 and self.group_confidence - self.confidence > 0.12


def plausibility(
    flow: EspFlow, labels: list[str] | None = None
) -> tuple[np.ndarray, list[tuple[str, str]], list[str]]:
    """Hard structural constraints from RFC 4303, applied over the learned models.

    Two suites can be statistically confusable while being physically impossible
    to confuse. AES-GCM and ESP-NULL are the sharp case: their ciphertext lengths
    differ by a constant 12 bytes, so every length-residue feature is identical
    and the CNN — which sees only the distribution profile — cannot tell them
    apart at all. The distinction is entropy, and entropy is not negotiable:
    output of a working cipher is indistinguishable from random.

    So rather than hoping the ensemble weights land right, the framing rules are
    applied as a mask:

      * every ESP ciphertext length must satisfy len = (IV + ICV) mod blocksize,
        which is arithmetic, not a heuristic
      * ciphertext must clear the entropy floor; integrity-only payloads must not
      * observed lengths must leave room for the suite's own IV and ICV

    A suite failing these is set to zero probability regardless of what the
    models say. This is also what makes a finding defensible to an auditor: the
    exclusions are stated reasons, not model internals.
    """
    # The caller's label ordering is authoritative. The classifier stores labels
    # sorted, while ESP_SUITES is in catalogue order; masking one with the other
    # silently applies each suite's constraint to a different suite.
    labels = labels if labels is not None else sorted(ESP_SUITES.keys())
    mask = np.ones(len(labels))
    excluded: list[tuple[str, str]] = []
    notes: list[str] = []

    lengths = np.asarray(flow.payload_lengths, dtype=np.int64)
    if lengths.size == 0:
        return mask, excluded, notes

    entropy = (
        sum(flow.entropy_samples) / len(flow.entropy_samples)
        if len(flow.entropy_samples) >= 12
        else None
    )

    # Observed granularity: the GCD of the gaps between distinct ciphertext
    # lengths, which recovers the true padding boundary directly.
    #
    # The residue test alone is one-directional and therefore not sufficient. A
    # flow padded to 16 bytes satisfies len = 12 (mod 16), which *implies*
    # len = 4 (mod 8), so an AES-CBC tunnel passes the 3DES test for free and the
    # two collapse together. Granularity breaks the implication: padding to 16
    # leaves gaps that are multiples of 16, padding to 8 produces gaps of 8. The
    # two constraints together pin the block size in both directions.
    distinct = np.unique(lengths)
    granularity = 0
    for gap in np.diff(distinct):
        granularity = math.gcd(granularity, int(gap))
    granularity_usable = distinct.size >= 8 and granularity > 0
    if not granularity_usable:
        # The strongest tie-breaker switches off exactly where inference is
        # weakest — a low-volume or heavily TFC-padded flow with too few
        # distinct lengths. Degrading quietly there would be the worst place
        # to do it, so the caller is told.
        notes.append(
            f"Only {distinct.size} distinct ciphertext lengths observed, so the "
            "padding-boundary test could not run and suites differing only by "
            "block size cannot be separated. Treat this attribution as weaker "
            "than its confidence suggests."
        )

    for i, name in enumerate(labels):
        spec = ESP_SUITES.get(name)
        if spec is None:
            continue
        modulus = max(spec["block"], 4)
        expected = (spec["iv"] + spec["icv"]) % modulus
        agree = float((lengths % modulus == expected).mean())

        if granularity_usable and granularity != modulus:
            mask[i] = 0.0
            excluded.append(
                (name, f"length granularity is {granularity}B, so the padding "
                       f"boundary is not this suite's {modulus}B")
            )
            continue

        if agree < 0.90:
            mask[i] = 0.0
            excluded.append(
                (name, f"framing mismatch: {agree:.0%} of lengths match the "
                       f"required len mod {modulus} == {expected}")
            )
            continue

        overhead = spec["iv"] + spec["icv"]
        if lengths.min() < overhead + 4:
            mask[i] = 0.0
            excluded.append(
                (name, f"shortest packet ({lengths.min()}B) cannot hold this "
                       f"suite's {overhead}B IV+ICV overhead")
            )
            continue

        if entropy is not None:
            encrypts = not name.startswith("NULL")
            if encrypts and entropy < MIN_CIPHERTEXT_ENTROPY:
                mask[i] = 0.0
                excluded.append(
                    (name, f"payload entropy {entropy:.2f} is below the "
                           f"ciphertext floor of {MIN_CIPHERTEXT_ENTROPY}")
                )
            elif not encrypts and entropy > MAX_PLAINTEXT_ENTROPY:
                mask[i] = 0.0
                excluded.append(
                    (name, f"payload entropy {entropy:.2f} exceeds the plaintext "
                           f"ceiling of {MAX_PLAINTEXT_ENTROPY}; payload is encrypted")
                )

    if mask.sum() == 0:  # nothing survived: fall back to the models alone
        notes.append(
            "No catalogued suite satisfies the observed framing. The SA may use a "
            "transform outside the catalogue, TFC padding, or nested encapsulation."
        )
        mask = np.ones(len(labels))
    else:
        survivors = [labels[i] for i in range(len(labels)) if mask[i] > 0]
        notes.append(
            f"{len(survivors)} of {len(labels)} suites are structurally consistent "
            "with the observed framing."
        )
    return mask, excluded, notes


class SuiteClassifier:
    """Random Forest + 1D-CNN soft-voting ensemble."""

    def __init__(self, rf_weight: float = 0.55):
        self.labels: list[str] = list(ESP_SUITES.keys())
        self.rf: RandomForestClassifier | None = None
        self.cnn: EspCNN | None = None
        self.rf_weight = rf_weight
        self.metrics: dict = {}

    # -- training -----------------------------------------------------------

    def fit(
        self,
        X: np.ndarray,
        labels: list[str],
        epochs: int = 60,
        seed: int = 42,
        verbose: bool = False,
    ) -> dict:
        self.labels = sorted(set(labels))
        index = {name: i for i, name in enumerate(self.labels)}
        y = np.array([index[l] for l in labels])

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.25, random_state=seed, stratify=y
        )

        self.rf = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=1,
            n_jobs=-1,
            random_state=seed,
            class_weight="balanced_subsample",
        )
        self.rf.fit(X_tr, y_tr)

        self.cnn = EspCNN(len(self.labels), signal_len=F.SIGNAL_LEN, seed=seed)
        if verbose:
            print("Training 1D-CNN")
        self.cnn.fit(
            X_tr[:, : F.SIGNAL_LEN], y_tr, epochs=epochs, seed=seed, verbose=verbose
        )

        rf_acc = float((self.rf.predict(X_te) == y_te).mean())
        cnn_acc = float((self.cnn.predict(X_te[:, : F.SIGNAL_LEN]) == y_te).mean())
        ens = self._blend(X_te)
        ens_acc = float((ens.argmax(axis=1) == y_te).mean())

        # accuracy once framing-identical suites are merged: the ceiling that
        # actually matters operationally, since the audit rules key off framing
        group_index = {}
        for i, name in enumerate(self.labels):
            key = tuple(sorted(ambiguity_group(name)))
            group_index[i] = key
        grouped = float(
            np.mean(
                [
                    group_index[p] == group_index[t]
                    for p, t in zip(ens.argmax(axis=1), y_te)
                ]
            )
        )

        self.metrics = {
            "n_train": int(len(y_tr)),
            "n_test": int(len(y_te)),
            "classes": self.labels,
            "rf_accuracy": round(rf_acc, 4),
            "cnn_accuracy": round(cnn_acc, 4),
            "ensemble_accuracy": round(ens_acc, 4),
            "grouped_accuracy": round(grouped, 4),
            "confusion": self._confusion(ens.argmax(axis=1), y_te).tolist(),
        }
        return self.metrics

    def _confusion(self, pred: np.ndarray, true: np.ndarray) -> np.ndarray:
        n = len(self.labels)
        m = np.zeros((n, n), dtype=int)
        for p, t in zip(pred, true):
            m[t, p] += 1
        return m

    # -- inference ----------------------------------------------------------

    def _blend(self, X: np.ndarray) -> np.ndarray:
        assert self.rf is not None and self.cnn is not None
        rf_p = self.rf.predict_proba(X)
        cnn_p = self.cnn.predict_proba(X[:, : F.SIGNAL_LEN])
        # RandomForest may have seen fewer classes than the label space
        if rf_p.shape[1] != len(self.labels):
            full = np.zeros((rf_p.shape[0], len(self.labels)))
            for col, cls in enumerate(self.rf.classes_):
                full[:, int(cls)] = rf_p[:, col]
            rf_p = full
        return self.rf_weight * rf_p + (1 - self.rf_weight) * cnn_p

    def predict_one(self, flow: EspFlow) -> Prediction:
        vec = F.extract(flow).reshape(1, -1)
        probs = self._blend(vec)[0]

        mask, excluded, _notes = plausibility(flow, self.labels)
        if len(mask) == len(probs):
            masked = probs * mask
            if masked.sum() > 0:
                probs = masked / masked.sum()

        order = np.argsort(probs)[::-1]
        ranked = [(self.labels[i], float(probs[i])) for i in order]
        top = ranked[0]
        group = sorted(ambiguity_group(top[0]))
        gconf = float(sum(probs[self.labels.index(g)] for g in group if g in self.labels))
        return Prediction(
            label=top[0],
            confidence=float(top[1]),
            ranked=ranked,
            group=group,
            group_confidence=gconf,
            excluded=excluded,
        )

    def annotate(self, flows: list[EspFlow]) -> list[Prediction]:
        preds = []
        for flow in flows:
            pred = self.predict_one(flow)
            flow.predicted_suite = pred.label
            flow.confidence = pred.confidence
            flow.ranked = pred.ranked
            preds.append(pred)
        return preds

    # -- persistence --------------------------------------------------------

    def save(self, directory: str) -> None:
        import hashlib
        import platform
        import sys
        from datetime import datetime, timezone

        import joblib
        import sklearn

        os.makedirs(directory, exist_ok=True)
        assert self.rf is not None and self.cnn is not None
        joblib.dump(self.rf, os.path.join(directory, "rf.joblib"))
        self.cnn.save(os.path.join(directory, "cnn.npz"))

        # rf.joblib is a pickle, so loading it is code execution. The manifest
        # is written to a separate file so that tampering with the model
        # requires tampering with the manifest too, and an operator can hold
        # the manifest somewhere the analyzer's model directory is not.
        manifest = {
            "algorithm": "sha256",
            "files": {
                name: _sha256_file(os.path.join(directory, name))
                for name in ("rf.joblib", "cnn.npz")
            },
        }
        with open(os.path.join(directory, "MANIFEST.sha256"), "w") as fh:
            json.dump(manifest, fh, indent=2)

        with open(os.path.join(directory, "meta.json"), "w") as fh:
            json.dump(
                {
                    "schema_version": SCHEMA_VERSION,
                    "feature_hash": feature_hash(),
                    "labels": self.labels,
                    "rf_weight": self.rf_weight,
                    "metrics": self.metrics,
                    "features": F.FEATURE_NAMES,
                    # Provenance, so an operator can answer "what is this model
                    # and where did it come from" from the artefact itself.
                    "provenance": {
                        "trained_at": datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                        "python": sys.version.split()[0],
                        "sklearn": sklearn.__version__,
                        "platform": platform.platform(),
                        "corpus": "synthetic RFC 4303 framing model",
                    },
                },
                fh,
                indent=2,
            )

    @staticmethod
    def verify(directory: str, require_manifest: bool = True) -> dict:
        """Check model files against their manifest before anything is loaded.

        `joblib.load` unpickles, so anyone who can write to the model directory
        gets code execution inside the analyzer — on a sensor that is often the
        most privileged process on the host. The feature-schema check does not
        help here: it reads meta.json from the same directory an attacker would
        already control.

        This is not a signature and does not pretend to be one. It detects
        tampering by anything that cannot also rewrite the manifest, and it
        gives an operator a hash to pin in configuration management. Real
        signing needs a key the sensor does not hold.
        """
        manifest_path = os.path.join(directory, "MANIFEST.sha256")
        if not os.path.exists(manifest_path):
            if require_manifest:
                raise ModelIntegrityError(
                    f"{directory}/MANIFEST.sha256 is missing. Loading rf.joblib "
                    "unpickles arbitrary objects, so an unverified model "
                    "directory is a code-execution path. Retrain with: "
                    "cipherguard train"
                )
            return {"verified": False, "reason": "no manifest"}

        with open(manifest_path) as fh:
            manifest = json.load(fh)

        for name, expected in manifest.get("files", {}).items():
            path = os.path.join(directory, name)
            if not os.path.exists(path):
                raise ModelIntegrityError(f"{name} listed in the manifest is missing")
            actual = _sha256_file(path)
            if actual != expected:
                raise ModelIntegrityError(
                    f"{name} does not match the manifest "
                    f"(expected {expected[:16]}, got {actual[:16]}). "
                    "The model directory has been modified since training."
                )
        return {"verified": True, "files": manifest["files"]}

    @classmethod
    def load(cls, directory: str, require_manifest: bool = True) -> "SuiteClassifier":
        import joblib

        # Verify before importing anything from the directory, because the
        # verification is worthless if it runs after the pickle.
        cls.verify(directory, require_manifest=require_manifest)

        with open(os.path.join(directory, "meta.json")) as fh:
            meta = json.load(fh)

        # A feature-schema change is the dangerous failure here: the arrays
        # still have compatible shapes, the model still loads, and every
        # prediction is quietly computed from columns that no longer mean what
        # the model was fitted on. Nothing raises, and the output looks
        # plausible. Refuse to load instead.
        stored = meta.get("feature_hash")
        if stored is not None and stored != feature_hash():
            raise ModelSchemaError(
                f"model in {directory}/ was trained against a different feature "
                f"schema (model {stored[:12]}, current {feature_hash()[:12]}). "
                "Predictions would be computed from mismatched columns. "
                "Retrain with: cipherguard train"
            )
        if meta.get("schema_version") != SCHEMA_VERSION:
            raise ModelSchemaError(
                f"model schema version {meta.get('schema_version')} does not "
                f"match {SCHEMA_VERSION}. Retrain with: cipherguard train"
            )

        model = cls(rf_weight=meta.get("rf_weight", 0.55))
        model.labels = meta["labels"]
        model.metrics = meta.get("metrics", {})
        model.provenance = meta.get("provenance", {})
        model.rf = joblib.load(os.path.join(directory, "rf.joblib"))
        model.cnn = EspCNN.load(os.path.join(directory, "cnn.npz"))
        return model

    @staticmethod
    def is_trained(directory: str) -> bool:
        return all(
            os.path.exists(os.path.join(directory, f))
            for f in ("rf.joblib", "cnn.npz", "meta.json")
        )
