"""Detection and robustness metrics."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef, precision_score, recall_score, roc_auc_score


def safe_auroc(y_true: np.ndarray, scores: np.ndarray) -> float:
    return float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) > 1 else float("nan")


def safe_auprc(y_true: np.ndarray, scores: np.ndarray) -> float:
    return float(average_precision_score(y_true, scores)) if len(np.unique(y_true)) > 1 else float("nan")


def false_alarms_per_hour(y_true: np.ndarray, y_pred: np.ndarray, window_seconds: float) -> float:
    benign = y_true == 0
    hours = benign.sum() * window_seconds / 3600.0
    return float(((y_pred == 1) & benign).sum() / hours) if hours > 0 else float("nan")


def event_recall_and_ttd(y_pred: np.ndarray, times_s: np.ndarray, intervals: list[tuple[float, float]]) -> tuple[float, list[float]]:
    if not intervals:
        return float("nan"), []
    detected, ttds = 0, []
    for start, end in intervals:
        mask = (times_s >= start) & (times_s < end)
        alarm_times = times_s[mask & (y_pred == 1)]
        if len(alarm_times):
            detected += 1
            ttds.append(float(alarm_times.min() - start))
    return float(detected / len(intervals)), ttds


def window_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)) if len(np.unique(y_true)) > 1 else float("nan"),
    }


def evaluate_run(y_true: np.ndarray, scores: np.ndarray, y_pred: np.ndarray, times_s: np.ndarray, intervals: list[tuple[float, float]], window_seconds: float) -> dict[str, float]:
    er, ttds = event_recall_and_ttd(y_pred, times_s, intervals)
    out = {
        "auroc": safe_auroc(y_true, scores),
        "auprc": safe_auprc(y_true, scores),
        "false_alarms_per_hour": false_alarms_per_hour(y_true, y_pred, window_seconds),
        "event_recall": er,
        "median_ttd_s": float(np.median(ttds)) if ttds else float("nan"),
        "mean_ttd_s": float(np.mean(ttds)) if ttds else float("nan"),
        "n_detected_events": int(len(ttds)),
        "n_attack_events": int(len(intervals)),
    }
    out.update(window_metrics(y_true, y_pred))
    return out
