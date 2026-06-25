#!/usr/bin/env python3
"""
Offline model evaluation — Precision / Recall / F1 for the anomaly detectors.

Scores the anomaly detectors on a LABELLED holdout and writes the metrics to the
`model_performance` table, which the dashboard's Model Performance card displays
(System & ML Models -> ML Models tab).

Two models are evaluated on the SAME feature matrix for a fair comparison:
  * River HalfSpaceTrees — the production incremental detector (what runs on the Pi).
  * scikit-learn IsolationForest — the secondary comparator. It runs OFFLINE here on a
    dev/CI machine only, so the Raspberry Pi runtime-RAM constraint that kept it out of
    the live engine does not apply to this evaluation.

Datasets: point --dataset at a labelled CSV (e.g. IoT-23 / BOT-IoT exports) with the
feature columns below plus a `label` column (0 = benign, 1 = attack). With no dataset a
small SYNTHETIC sample is generated so the pipeline runs end-to-end; that run is tagged
"synthetic-sample" so it is never mistaken for the headline benchmark.

Expected dataset columns (missing ones default to 0):
  duration, bytes_sent, bytes_received, packets_sent, packets_received, label

Usage:
  python scripts/evaluate_models.py [--dataset path.csv] [--db data/database/iotsentinel.db]
                                    [--limit N]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from ml.feature_extractor import FeatureExtractor  # noqa: E402


def _synthetic_dataset(n: int = 1500, anomaly_rate: float = 0.12, seed: int = 42) -> pd.DataFrame:
    """A small benign+attack mix so the pipeline runs without the large public datasets.
    Benign: short, low-byte flows. Attacks: exfil-like (huge bytes) and scan-like (many
    tiny flows) — separable enough to give meaningful, non-trivial P/R/F1."""
    rng = np.random.default_rng(seed)
    n_anom = int(n * anomaly_rate)
    n_norm = n - n_anom

    norm = pd.DataFrame({
        "duration": rng.gamma(2.0, 1.5, n_norm),
        "bytes_sent": rng.gamma(2.0, 700, n_norm),
        "bytes_received": rng.gamma(2.0, 1100, n_norm),
        "packets_sent": rng.poisson(8, n_norm),
        "packets_received": rng.poisson(10, n_norm),
        "label": 0,
    })
    half = n_anom // 2
    exfil = pd.DataFrame({  # large sustained outbound transfers (orders of magnitude bigger)
        "duration": rng.gamma(4.0, 12.0, half),
        "bytes_sent": rng.gamma(4.0, 300000, half),
        "bytes_received": rng.gamma(2.0, 1500, half),
        "packets_sent": rng.poisson(1200, half),
        "packets_received": rng.poisson(60, half),
        "label": 1,
    })
    scan = pd.DataFrame({  # many near-empty one-shot connections
        "duration": rng.uniform(0.0, 0.02, n_anom - half),
        "bytes_sent": rng.uniform(0.0, 8, n_anom - half),
        "bytes_received": np.zeros(n_anom - half),
        "packets_sent": np.ones(n_anom - half),
        "packets_received": np.zeros(n_anom - half),
        "label": 1,
    })
    df = pd.concat([norm, exfil, scan], ignore_index=True)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _feature_matrix(df: pd.DataFrame):
    """Reuse the production FeatureExtractor so the evaluation matches live scoring."""
    X, names = FeatureExtractor().extract_features(df.drop(columns=["label"], errors="ignore"))
    X = np.nan_to_num(np.asarray(X, dtype=float), nan=0.0, posinf=0.0, neginf=0.0)
    return X, names


def _prf(y_true, y_pred):
    from sklearn.metrics import precision_recall_fscore_support
    p, r, f, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0)
    return float(p), float(r), float(f)


def evaluate_halfspacetrees(X, names, y, seed: int = 42):
    """Holdout evaluation of River HalfSpaceTrees: learn over the stream (unsupervised,
    no labels), then score every record with the trained model and threshold at the
    (1 - contamination) quantile so the positive rate matches the true anomaly rate.
    Learn-then-score mirrors IsolationForest's fit-then-predict for a fair comparison."""
    from river import anomaly
    dicts = [{n: float(v) for n, v in zip(names, row)} for row in X]
    hst = anomaly.HalfSpaceTrees(n_trees=10, height=8,
                                 window_size=max(50, len(dicts) // 4), seed=seed)
    for x in dicts:
        hst.learn_one(x)
    scores = np.asarray([hst.score_one(x) for x in dicts], dtype=float)
    rate = max(float(np.mean(y)), 1e-3)
    thr = np.quantile(scores, 1.0 - rate)
    pred = (scores > thr).astype(int)
    return _prf(y, pred)


def evaluate_isolation_forest(X, y, seed: int = 42):
    """Offline comparator (dev/CI only — not run on the Pi)."""
    from sklearn.ensemble import IsolationForest
    rate = min(max(float(np.mean(y)), 1e-3), 0.5)
    clf = IsolationForest(contamination=rate, random_state=seed, n_estimators=150)
    raw = clf.fit_predict(X)            # -1 = anomaly, 1 = normal
    pred = (raw == -1).astype(int)
    return _prf(y, pred)


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate IoTSentinel anomaly models (P/R/F1).")
    ap.add_argument("--dataset", help="Labelled CSV (needs a 'label' column: 0 benign, 1 attack)")
    ap.add_argument("--db", default=str(REPO / "data" / "database" / "iotsentinel.db"),
                    help="SQLite DB to write model_performance into")
    ap.add_argument("--limit", type=int, default=0, help="Cap rows (0 = all)")
    args = ap.parse_args()

    if args.dataset and Path(args.dataset).exists():
        df = pd.read_csv(args.dataset)
        source = Path(args.dataset).stem
        if "label" not in df.columns:
            print("ERROR: dataset has no 'label' column (0 benign, 1 attack).", file=sys.stderr)
            return 2
    else:
        if args.dataset:
            print(f"WARN: dataset {args.dataset} not found — using synthetic sample.", file=sys.stderr)
        df = _synthetic_dataset()
        source = "synthetic-sample"

    if args.limit and len(df) > args.limit:
        df = df.head(args.limit)

    y = df["label"].astype(int).to_numpy()
    X, names = _feature_matrix(df)
    print(f"Evaluating on {len(df)} rows ({int(y.sum())} attacks, {len(names)} features) "
          f"from '{source}'")

    results = {
        f"HalfSpaceTrees ({source})": evaluate_halfspacetrees(X, names, y),
        f"IsolationForest ({source})": evaluate_isolation_forest(X, y),
    }

    # Persist for the dashboard card.
    try:
        from database.db_manager import DatabaseManager
        db = DatabaseManager(args.db)
        # The table is created by config/init_database.py on a provisioned install; ensure
        # it exists so the eval also works against a fresh/standalone DB.
        db.conn.execute("""
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                model_type TEXT,
                precision REAL,
                recall REAL,
                f1_score REAL
            )
        """)
        db.conn.commit()
        for model_type, (p, r, f) in results.items():
            db.add_model_performance_metric(model_type=model_type, precision=p, recall=r, f1_score=f)
        print(f"Stored {len(results)} model_performance rows in {args.db}")
    except Exception as exc:  # storage is best-effort; metrics still printed
        print(f"WARN: could not store metrics: {exc}", file=sys.stderr)

    print("\n  model                              precision  recall    f1")
    for model_type, (p, r, f) in results.items():
        print(f"  {model_type:34s} {p:8.3f}  {r:7.3f}  {f:6.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
