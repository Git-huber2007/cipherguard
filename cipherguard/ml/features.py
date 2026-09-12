"""Side-channel feature extraction for encrypted ESP flows.

The dominant signal is structural, not statistical. RFC 4303 requires the ESP
ciphertext to carry an explicit IV, a payload padded up to the cipher block size
(and to a 4-byte boundary at minimum), a two-byte trailer, and a trailing ICV.
So for a suite with block size ``b``, IV length ``iv`` and ICV length ``icv``,
every ciphertext length satisfies

    len (mod b) == (iv + icv) (mod b)

which is a fixed residue the analyzer can read straight off the wire. Block size
separates 3DES/DES (8) from AES-CBC (16) from the counter and AEAD modes (4),
and the residue within a block size separates ICV lengths — that is how
HMAC-SHA1-96 (12) is told apart from HMAC-SHA2-256-128 (16).

Timing and entropy are secondary: they help only where two suites share an
identical length signature (AES-CTR vs AES-GCM, DES vs 3DES), and the model is
expected to confuse those pairs. Nothing here decrypts anything.
"""

from __future__ import annotations

import math
from typing import Iterable

import numpy as np

from ..core.models import EspFlow

LENGTH_BINS = 36
MAX_LENGTH = 1600
SIGNAL_LEN = 64  # 16 (mod-16) + 8 (mod-8) + 4 (mod-4) + 36 (length histogram)

FEATURE_NAMES: list[str] = (
    [f"mod16_{i}" for i in range(16)]
    + [f"mod8_{i}" for i in range(8)]
    + [f"mod4_{i}" for i in range(4)]
    + [f"lenhist_{i}" for i in range(LENGTH_BINS)]
    + [
        "len_mean",
        "len_std",
        "len_min",
        "len_max",
        "len_p25",
        "len_p50",
        "len_p75",
        "len_p90",
        "len_unique_ratio",
        "len_range",
        "len_gcd",
        "len_delta_gcd",
        "small_pkt_ratio",
        "mtu_pkt_ratio",
        "entropy_mean",
        "entropy_std",
        "entropy_min",
        "iat_mean",
        "iat_std",
        "iat_p50",
        "iat_cv",
        "burstiness",
        "packet_rate",
        "log_packets",
    ]
)


def _gcd_of(values: Iterable[int]) -> int:
    g = 0
    for v in values:
        g = math.gcd(g, int(v))
        if g == 1:
            return 1
    return g


def _hist(values: np.ndarray, bins: int, lo: float, hi: float) -> np.ndarray:
    if values.size == 0:
        return np.zeros(bins, dtype=np.float64)
    counts, _ = np.histogram(np.clip(values, lo, hi), bins=bins, range=(lo, hi))
    total = counts.sum()
    return counts / total if total else counts.astype(np.float64)


def _modulo_profile(lengths: np.ndarray, modulus: int) -> np.ndarray:
    """Normalised histogram of ciphertext length residues."""
    if lengths.size == 0:
        return np.zeros(modulus, dtype=np.float64)
    residues = np.bincount(lengths % modulus, minlength=modulus).astype(np.float64)
    return residues / residues.sum()


def extract(flow: EspFlow) -> np.ndarray:
    """Return the flat feature vector for one flow, ordered as FEATURE_NAMES."""
    lengths = np.asarray(flow.payload_lengths, dtype=np.int64)
    iats = np.asarray(flow.inter_arrivals, dtype=np.float64)
    ents = np.asarray(flow.entropy_samples, dtype=np.float64)

    if lengths.size == 0:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float64)

    parts: list[np.ndarray] = [
        _modulo_profile(lengths, 16),
        _modulo_profile(lengths, 8),
        _modulo_profile(lengths, 4),
        _hist(lengths.astype(np.float64), LENGTH_BINS, 0, MAX_LENGTH),
    ]

    uniq = np.unique(lengths)
    deltas = np.abs(np.diff(uniq)) if uniq.size > 1 else np.array([0])

    scalar = [
        float(lengths.mean()),
        float(lengths.std()),
        float(lengths.min()),
        float(lengths.max()),
        float(np.percentile(lengths, 25)),
        float(np.percentile(lengths, 50)),
        float(np.percentile(lengths, 75)),
        float(np.percentile(lengths, 90)),
        float(uniq.size / lengths.size),
        float(lengths.max() - lengths.min()),
        float(_gcd_of(uniq.tolist())),
        float(_gcd_of(deltas.tolist())),
        float((lengths < 128).mean()),
        float((lengths > 1300).mean()),
    ]

    if ents.size:
        scalar += [float(ents.mean()), float(ents.std()), float(ents.min())]
    else:
        scalar += [0.0, 0.0, 0.0]

    if iats.size:
        mean_iat = float(iats.mean())
        std_iat = float(iats.std())
        scalar += [
            mean_iat,
            std_iat,
            float(np.percentile(iats, 50)),
            float(std_iat / mean_iat) if mean_iat > 1e-9 else 0.0,
            float((iats < mean_iat * 0.25).mean()),
        ]
    else:
        scalar += [0.0, 0.0, 0.0, 0.0, 0.0]

    duration = max(flow.duration, 1e-6)
    scalar += [float(flow.packets / duration), float(math.log1p(flow.packets))]

    vec = np.concatenate(parts + [np.asarray(scalar, dtype=np.float64)])
    return np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)


def signal(vector: np.ndarray) -> np.ndarray:
    """The first SIGNAL_LEN features form a contiguous distribution profile that
    the 1D-CNN consumes as a single-channel signal."""
    return vector[:SIGNAL_LEN]


def extract_batch(flows: list[EspFlow]) -> np.ndarray:
    if not flows:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float64)
    return np.vstack([extract(f) for f in flows])
