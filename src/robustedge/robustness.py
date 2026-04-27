"""Aggregation of robustness curves and scalar robustness scores."""

from __future__ import annotations

import numpy as np
import pandas as pd


def aggregate_metrics(metrics: pd.DataFrame) -> pd.DataFrame:
    """Aggregate per-run metrics into mean/std/count robustness curves."""
    group_cols = ["detector", "perturbation_family", "perturbation_profile", "severity", "attack_duration", "attack_intensity"]
    metric_cols = [
        c for c in metrics.columns
        if c not in group_cols + ["run_id", "run_dir", "threshold"]
        and pd.api.types.is_numeric_dtype(metrics[c])
    ]
    agg = metrics.groupby(group_cols, dropna=False)[metric_cols].agg(["mean", "std", "count"])
    agg.columns = ["_".join(col).strip("_") for col in agg.columns.to_flat_index()]
    return agg.reset_index()


def robustness_scores(
    curve_df: pd.DataFrame,
    metric: str,
    higher_is_better: bool = True,
    epsilon: float = 1e-9,
) -> pd.DataFrame:
    """Compute average, worst, and product robustness per detector/family.

    ``curve_df`` should contain one row per severity level with a column named
    ``metric``. If it contains aggregate columns, pass e.g. ``event_recall_mean``.
    """
    rows = []
    group_cols = ["detector", "perturbation_family", "attack_duration", "attack_intensity"]
    for keys, g in curve_df.groupby(group_cols, dropna=False):
        vals = g.sort_values("severity")[metric].dropna().astype(float).values
        if len(vals) == 0:
            continue
        if higher_is_better:
            r_avg = float(np.mean(vals))
            r_worst = float(np.min(vals))
            r_prod = float(np.exp(np.mean(np.log(vals + epsilon))))
        else:
            # For lower-is-better metrics, store direct curve summaries.
            r_avg = float(np.mean(vals))
            r_worst = float(np.max(vals))
            r_prod = float(np.exp(np.mean(np.log(vals + epsilon))))
        row = dict(zip(group_cols, keys if isinstance(keys, tuple) else (keys,)))
        row.update({
            "metric": metric,
            "higher_is_better": higher_is_better,
            "R_avg": r_avg,
            "R_worst": r_worst,
            "R_prod": r_prod,
            "n_severity_points": len(vals),
        })
        rows.append(row)
    return pd.DataFrame(rows)
