"""Attack-window labeling utilities."""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

from .data import RunData
from .io import infer_time_column, parse_timestamps


def attack_intervals_from_run(run: RunData) -> list[tuple[float, float]]:
    """Return attack intervals in seconds relative to run start.

    The function first tries to infer intervals from ``annotations.ndjson``. If
    annotations are unavailable or not machine-readable, it falls back to
    ``attack_start_delay`` and ``attack_duration`` in ``scenario.json``.
    """
    intervals = _intervals_from_annotations(run.annotations)
    if intervals:
        return intervals
    interval = run.scenario.attack_interval
    return [interval] if interval is not None else []


def _intervals_from_annotations(df: pd.DataFrame) -> list[tuple[float, float]]:
    if df.empty:
        return []

    # Common convention: event/type/name columns contain attack_start and attack_end markers.
    text_cols = [c for c in df.columns if df[c].dtype == "object"]
    time_col = infer_time_column(df)
    if not text_cols or time_col is None:
        return []

    time_values = parse_timestamps(df[time_col])
    if time_values.isna().all():
        return []
    run_start = time_values.min()

    starts: list[float] = []
    ends: list[float] = []
    for idx, row in df.iterrows():
        text = " ".join(str(row[c]).lower() for c in text_cols if pd.notna(row[c]))
        t = time_values.loc[idx]
        if pd.isna(t):
            continue
        rel = (t - run_start).total_seconds()
        if re.search(r"attack[_ -]?start|start[_ -]?attack", text):
            starts.append(rel)
        elif re.search(r"attack[_ -]?end|end[_ -]?attack|attack[_ -]?stop", text):
            ends.append(rel)

    intervals: list[tuple[float, float]] = []
    for s, e in zip(starts, ends):
        if e > s:
            intervals.append((s, e))
    return intervals


def add_window_labels(
    features: pd.DataFrame,
    intervals: list[tuple[float, float]],
    time_col: str = "relative_time_s",
    label_col: str = "label",
) -> pd.DataFrame:
    """Add binary attack labels to a per-window feature table."""
    out = features.copy()
    if time_col not in out.columns:
        out[label_col] = 0
        return out
    y = pd.Series(0, index=out.index, dtype=int)
    for start, end in intervals:
        y |= ((out[time_col] >= start) & (out[time_col] < end)).astype(int)
    out[label_col] = y.astype(int)
    return out
