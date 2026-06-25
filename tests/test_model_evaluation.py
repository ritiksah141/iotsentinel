#!/usr/bin/env python3
"""Tests for scripts/evaluate_models.py — the offline Precision/Recall/F1 evaluation of
the anomaly detectors (River HalfSpaceTrees + an Isolation Forest comparator). The
Isolation Forest runs OFFLINE here only, so the Pi runtime-RAM constraint that excluded
it from the live engine does not apply.

Run: pytest tests/test_model_evaluation.py -v
"""
import importlib.util
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Load the script module (it lives in scripts/, not an importable package).
_spec = importlib.util.spec_from_file_location("evaluate_models", ROOT / "scripts" / "evaluate_models.py")
em = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(em)


def test_synthetic_dataset_is_labelled():
    df = em._synthetic_dataset(n=400)
    assert "label" in df.columns
    assert set(df["label"].unique()) == {0, 1}
    assert 0 < df["label"].mean() < 0.5  # a minority of attacks


def test_feature_matrix_shape_matches_rows():
    df = em._synthetic_dataset(n=300)
    X, names = em._feature_matrix(df)
    assert X.shape[0] == len(df)
    assert X.shape[1] == len(names) and len(names) > 0
    assert np.isfinite(X).all()  # no NaN/inf leaks into the models


def test_halfspacetrees_returns_valid_prf():
    df = em._synthetic_dataset(n=600)
    X, names = em._feature_matrix(df)
    y = df["label"].to_numpy()
    p, r, f = em.evaluate_halfspacetrees(X, names, y)
    for v in (p, r, f):
        assert 0.0 <= v <= 1.0


def test_isolation_forest_comparator_returns_valid_prf():
    df = em._synthetic_dataset(n=600)
    X, _ = em._feature_matrix(df)
    y = df["label"].to_numpy()
    p, r, f = em.evaluate_isolation_forest(X, y)
    for v in (p, r, f):
        assert 0.0 <= v <= 1.0
    # On the separable synthetic mix the comparator should beat random guessing.
    assert f > 0.2


def test_metrics_round_trip_through_db(db):
    """The dashboard card reads model_performance; verify the store/retrieve the eval uses."""
    db.add_model_performance_metric("HalfSpaceTrees (test)", 0.81, 0.74, 0.77)
    rows = db.get_model_performance_metrics(days=3650)
    assert any(r["model_type"] == "HalfSpaceTrees (test)" and abs(r["f1_score"] - 0.77) < 1e-6
               for r in rows)


def test_ml_metrics_card_is_wired():
    """The ML Models tab must surface the model metrics, and a callback must render them
    from model_performance."""
    app_src = (ROOT / "dashboard" / "app.py").read_text()
    admin_src = (ROOT / "dashboard" / "callbacks" / "callbacks_admin.py").read_text()
    assert "ml-metrics-card-body" in app_src
    assert "render_ml_metrics_card" in admin_src
    assert "get_model_performance_metrics" in admin_src
