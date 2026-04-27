
"""Attack-window extraction and labeling.

The generated campaign can contain several possible sources of attack timing:
``attack_records.ndjson``, explicit attack intervals in ``annotations.ndjson``,
or fallback fields in ``scenario.json``. The most robust option is absolute
timestamp alignment: attack intervals are converted to seconds relative to the
same reference timestamp used by the runtime feature table.
"""

from __future__ import annotations

import re
from typing import Iterable

import numpy as np
import pandas as pd

from .data import RunData
from .io import infer_time_column, parse_timestamps


def attack_intervals_from_run(
    run: RunData,
    reference_time: pd.Timestamp | None = None,
) -> list[tuple[float, float]]:
    """Return attack intervals in seconds relative to ``reference_time``.

    Priority order:
    1. min/max timestamps from ``attack_records.ndjson``;
    2. interval rows in ``annotations.ndjson`` with ``time`` and ``timeEnd``;
    3. attack_start/attack_end marker rows in ``annotations.ndjson``;
    4. scenario fallback using ``attack_start_delay`` and ``attack_duration``.

    Parameters
    ----------
    run:
        Loaded run.
    reference_time:
        Timestamp representing ``relative_time_s = 0`` in the feature table.
        If not provided, annotation run_start is used where possible.
    """
    abs_intervals = _absolute_intervals_from_attack_records(run.attack_records)
    if not abs_intervals:
        abs_intervals = _absolute_intervals_from_annotations(run.annotations)

    if abs_intervals:
        if reference_time is None:
            reference_time = _reference_from_annotations(run.annotations)
            if reference_time is None:
                reference_time = abs_intervals[0][0]
        out = []
        for start, end in abs_intervals:
            s = (start - reference_time).total_seconds()
            e = (end - reference_time).total_seconds()
            if e > s:
                out.append((float(s), float(e)))
        return out

    # Fallback to relative scenario values.
    fallback = run.scenario.attack_interval
    return [fallback] if fallback else []


def _absolute_intervals_from_attack_records(df: pd.DataFrame) -> list[tuple[pd.Timestamp, pd.Timestamp]]:
    """Infer the realized attack interval from attack record timestamps."""
    if df.empty:
        return []
    time_col = infer_time_column(df)
    if time_col is None:
        return []
    t = parse_timestamps(df[time_col]).dropna()
    if t.empty:
        return []
    start, end = t.min(), t.max()
    # Add a tiny epsilon to include the last event window.
    if end > start:
        return [(start, end)]
    return []


def _absolute_intervals_from_annotations(df: pd.DataFrame) -> list[tuple[pd.Timestamp, pd.Timestamp]]:
    if df.empty:
        return []
    time_col = infer_time_column(df)
    if time_col is None:
        return []
    t = parse_timestamps(df[time_col])
    if t.isna().all():
        return []

    # Direct interval rows with timeEnd.
    end_col = None
    for c in df.columns:
        if c.lower() in {"timeend", "time_end", "end_time"}:
            end_col = c
            break
    text_cols = [c for c in df.columns if df[c].dtype == "object"]
    intervals = []
    if end_col is not None:
        tend = parse_timestamps(df[end_col])
        for idx, row in df.iterrows():
            text = " ".join(str(row[c]).lower() for c in text_cols if pd.notna(row[c]))
            if "attack" in text and pd.notna(t.loc[idx]) and pd.notna(tend.loc[idx]):
                if tend.loc[idx] > t.loc[idx]:
                    intervals.append((t.loc[idx], tend.loc[idx]))
        if intervals:
            return intervals

    starts, ends = [], []
    for idx, row in df.iterrows():
        text = " ".join(str(row[c]).lower() for c in text_cols if pd.notna(row[c]))
        if pd.isna(t.loc[idx]):
            continue
        if re.search(r"attack[_ -]?start|start[_ -]?attack", text):
            starts.append(t.loc[idx])
        elif re.search(r"attack[_ -]?end|attack[_ -]?stop|end[_ -]?attack", text):
            ends.append(t.loc[idx])
    return [(s, e) for s, e in zip(starts, ends) if e > s]


def _reference_from_annotations(df: pd.DataFrame) -> pd.Timestamp | None:
    """Use run_start marker as reference if available."""
    if df.empty:
        return None
    time_col = infer_time_column(df)
    if time_col is None:
        return None
    t = parse_timestamps(df[time_col])
    text_cols = [c for c in df.columns if df[c].dtype == "object"]
    for idx, row in df.iterrows():
        text = " ".join(str(row[c]).lower() for c in text_cols if pd.notna(row[c]))
        if "run_start" in text and pd.notna(t.loc[idx]):
            return t.loc[idx]
    return t.min() if not t.isna().all() else None


def add_window_labels(
    df: pd.DataFrame,
    intervals: list[tuple[float, float]],
    time_col: str = "relative_time_s",
) -> pd.DataFrame:
    """Add binary labels to a feature table based on relative-time intervals."""
    out = df.copy()
    if time_col not in out.columns:
        out["label"] = 0
        return out
    y = pd.Series(False, index=out.index)
    for s, e in intervals:
        y = y | ((out[time_col] >= s) & (out[time_col] < e))
    out["label"] = y.astype(int)
    return out


def intervals_from_binary_labels(
    y: np.ndarray,
    times_s: np.ndarray,
    window_seconds: float,
) -> list[tuple[float, float]]:
    """Convert binary window labels to contiguous event intervals.

    This is useful during evaluation because the feature table labels already
    account for any timestamp-reference alignment.
    """
    y = np.asarray(y).astype(int)
    times_s = np.asarray(times_s).astype(float)
    if len(y) == 0 or y.max() == 0:
        return []
    intervals: list[tuple[float, float]] = []
    in_event = False
    start = None
    for i, val in enumerate(y):
        if val == 1 and not in_event:
            in_event = True
            start = float(times_s[i])
        if in_event and (val == 0 or i == len(y) - 1):
            end_idx = i if val == 0 else i + 1
            if end_idx < len(times_s):
                end = float(times_s[end_idx])
            else:
                end = float(times_s[-1] + window_seconds)
            intervals.append((float(start), end))
            in_event = False
            start = None
    return intervals
