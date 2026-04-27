"""Robustness aggregation and profile summaries."""

from __future__ import annotations

import numpy as np
import pandas as pd


def aggregate_metrics(metrics: pd.DataFrame) -> pd.DataFrame:
    group_cols = ["detector", "phase", "perturbation_family", "severity", "attack_duration", "attack_intensity"]
    numeric_cols = [
        c for c in metrics.columns
        if c not in group_cols + ["run_id", "run_dir", "threshold", "perturbation", "perturbation_profile"]
        and pd.api.types.is_numeric_dtype(metrics[c])
    ]
    out = metrics.groupby(group_cols, dropna=False)[numeric_cols].agg(["mean", "std", "count"])
    out.columns = ["_".join(c).strip("_") for c in out.columns.to_flat_index()]
    return out.reset_index()


def robustness_summary(agg: pd.DataFrame, metric: str, higher_is_better: bool = True, eps: float = 1e-9) -> pd.DataFrame:
    """Summarize available severity points.

    The current dataset contains selected severity points, not a dense grid.
    The resulting summaries should therefore be interpreted as discrete
    robustness profiles over the available severities.
    """
    rows = []
    keys = ["detector", "perturbation_family", "attack_duration", "attack_intensity"]
    for group, g in agg.groupby(keys, dropna=False):
        vals = g.sort_values("severity")[metric].dropna().astype(float).values
        if len(vals) == 0:
            continue
        row = dict(zip(keys, group if isinstance(group, tuple) else (group,)))
        row.update({
            "metric": metric,
            "higher_is_better": higher_is_better,
            "R_avg": float(np.mean(vals)),
            "R_worst": float(np.min(vals) if higher_is_better else np.max(vals)),
            "R_prod": float(np.exp(np.mean(np.log(vals + eps)))),
            "n_severity_points": int(len(vals)),
        })
        rows.append(row)
    return pd.DataFrame(rows)
