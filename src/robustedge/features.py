"""Feature extraction for RobustEdgeBench."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from .constants import NON_FEATURE_COLUMNS
from .data import RunData
from .io import infer_time_column, parse_timestamps
from .labels import add_window_labels, attack_intervals_from_run


@dataclass
class SysdigFeatureExtractor:
    """Extract fixed-window syscall features from ``sysdig_logs.ndjson``.

    The extractor supports several sysdig schemas:

    1. one row per window with numeric syscall columns,
    2. one row per syscall/window with columns such as ``syscall`` and ``count``,
    3. nested dictionaries flattened to columns such as ``counts.write`` or ``syscalls.write``.
    """

    window_seconds: float = 4.0

    def transform_run(self, run: RunData) -> pd.DataFrame:
        df = run.sysdig.copy()
        if df.empty:
            return pd.DataFrame()

        time_col = infer_time_column(df)
        if time_col is not None:
            timestamps = parse_timestamps(df[time_col])
        else:
            timestamps = pd.Series(pd.NaT, index=df.index)

        # Case 1: long format with syscall + count.
        long_syscall_col = _find_column(df, ["syscall", "syscall_type", "evt.type", "event_type", "call"])
        long_count_col = _find_column(df, ["count", "n", "value", "counts"])
        if long_syscall_col and long_count_col and time_col:
            temp = pd.DataFrame({
                "timestamp": timestamps,
                "syscall": df[long_syscall_col].astype(str),
                "count": pd.to_numeric(df[long_count_col], errors="coerce").fillna(0.0),
            })
            # Group by timestamp to one row per sysdig window.
            wide = temp.pivot_table(index="timestamp", columns="syscall", values="count", aggfunc="sum", fill_value=0.0)
            wide.columns = [f"syscall_{c}" for c in wide.columns]
            wide = wide.reset_index()
        else:
            wide = df.copy()
            if time_col is not None:
                wide["timestamp"] = timestamps

        # Identify numeric feature columns.
        numeric_cols = []
        for c in wide.columns:
            if c in NON_FEATURE_COLUMNS or c == time_col or c == "timestamp":
                continue
            if any(token in c.lower() for token in ["container", "image", "name", "id"]):
                # Avoid treating string identifiers as features.
                if not pd.api.types.is_numeric_dtype(wide[c]):
                    continue
            converted = pd.to_numeric(wide[c], errors="coerce")
            if converted.notna().any():
                wide[c] = converted.fillna(0.0)
                numeric_cols.append(c)

        if not numeric_cols:
            # Last resort: produce a row index feature so downstream code fails less abruptly.
            wide["sysdig_event_count"] = 1.0
            numeric_cols = ["sysdig_event_count"]

        # Sort by timestamp if available.
        if "timestamp" in wide.columns and not wide["timestamp"].isna().all():
            wide = wide.sort_values("timestamp").reset_index(drop=True)
            start_ts = wide["timestamp"].min()
            relative_time_s = (wide["timestamp"] - start_ts).dt.total_seconds()
        else:
            wide = wide.reset_index(drop=True)
            relative_time_s = pd.Series(np.arange(len(wide)) * self.window_seconds, index=wide.index)
            wide["timestamp"] = pd.NaT

        out = wide[numeric_cols].copy()
        out.columns = [_clean_feature_name(c) for c in out.columns]
        out.insert(0, "relative_time_s", relative_time_s.astype(float).values)
        out.insert(1, "window_start", out["relative_time_s"])
        out.insert(2, "window_end", out["relative_time_s"] + self.window_seconds)

        # Add run/scenario metadata.
        out["run_id"] = run.run_id
        out["run_dir"] = str(run.run_dir)
        out["perturbation"] = run.scenario.perturbation
        out["perturbation_family"] = run.scenario.perturbation_family
        out["perturbation_profile"] = run.scenario.perturbation_profile
        out["severity"] = run.scenario.severity
        out["attack_duration"] = run.scenario.attack_duration
        out["attack_intensity"] = run.scenario.attack_intensity
        out["attack_start_delay"] = run.scenario.attack_start_delay
        out["test_duration"] = run.scenario.test_duration
        out["iteration"] = run.scenario.iteration

        intervals = attack_intervals_from_run(run)
        out = add_window_labels(out, intervals)
        return out


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    lower_map = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


def _clean_feature_name(name: str) -> str:
    name = str(name).replace("counts.", "syscall_").replace("syscalls.", "syscall_")
    name = name.replace("fields.", "").replace("tags.", "")
    name = name.replace(" ", "_").replace("/", "_").replace("-", "_")
    if not name.startswith("syscall_") and any(k in name.lower() for k in ["write", "read", "nanosleep", "open", "close"]):
        name = f"syscall_{name}"
    return name


class FeatureTableBuilder:
    """Build a combined feature table from a list of runs."""

    def __init__(self, sysdig_window_seconds: float = 4.0):
        self.sysdig_extractor = SysdigFeatureExtractor(window_seconds=sysdig_window_seconds)

    def transform_runs(self, runs: list[RunData]) -> pd.DataFrame:
        tables = []
        for run in runs:
            table = self.sysdig_extractor.transform_run(run)
            if table.empty:
                print(f"[WARN] No features extracted for run: {run.run_id}")
                continue
            tables.append(table)
        if not tables:
            return pd.DataFrame()
        # Align feature columns across runs. Missing syscalls become zeros.
        return pd.concat(tables, ignore_index=True).fillna(0.0)


def infer_feature_columns(df: pd.DataFrame) -> list[str]:
    """Return detector feature columns from a combined feature table."""
    cols: list[str] = []
    for c in df.columns:
        if c in NON_FEATURE_COLUMNS:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols
