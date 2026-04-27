"""Low-level I/O utilities.

The functions in this module are deliberately permissive because early data
campaigns often evolve their JSON schemas. The parser therefore supports flat
NDJSON records as well as nested records containing keys such as ``tags``,
``fields``, ``counts`` or ``syscalls``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .constants import CORE_FILES, TIME_COLUMN_CANDIDATES


def read_json(path: str | Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read a JSON file and return a dictionary.

    Parameters
    ----------
    path:
        JSON file path.
    default:
        Value returned if the file does not exist. If ``None`` and the file is
        missing, an empty dict is returned.
    """
    path = Path(path)
    if not path.exists():
        return {} if default is None else default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_ndjson(path: str | Path, max_rows: int | None = None) -> pd.DataFrame:
    """Read newline-delimited JSON into a DataFrame.

    Empty or missing files return an empty DataFrame. Malformed lines are
    skipped, but the line number is stored in a warning printed to stdout.
    """
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()

    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if max_rows is not None and len(rows) >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Keep parsing rather than failing the whole run.
                print(f"[WARN] Skipping malformed JSON line {i} in {path}")
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                rows.append({"value": obj})

    if not rows:
        return pd.DataFrame()
    return pd.json_normalize(rows, sep=".")


def infer_time_column(df: pd.DataFrame) -> str | None:
    """Infer the best timestamp column in a DataFrame."""
    if df.empty:
        return None
    lower_map = {c.lower(): c for c in df.columns}
    for cand in TIME_COLUMN_CANDIDATES:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    # Fallback: first column containing 'time' or 'timestamp'.
    for c in df.columns:
        cl = c.lower()
        if "timestamp" in cl or cl.endswith("time") or cl == "time" or cl.endswith(".time"):
            return c
    return None


def parse_timestamps(series: pd.Series) -> pd.Series:
    """Parse timestamps robustly.

    Supports ISO strings and numeric Unix timestamps. Numeric values larger
    than 1e14 are interpreted as nanoseconds, larger than 1e11 as milliseconds,
    otherwise seconds.
    """
    if series.empty:
        return pd.to_datetime(series)
    if pd.api.types.is_numeric_dtype(series):
        s = series.astype("float64")
        med = s.dropna().median() if not s.dropna().empty else 0
        if med > 1e14:
            return pd.to_datetime(series, unit="ns", utc=True, errors="coerce")
        if med > 1e11:
            return pd.to_datetime(series, unit="ms", utc=True, errors="coerce")
        return pd.to_datetime(series, unit="s", utc=True, errors="coerce")
    return pd.to_datetime(series, utc=True, errors="coerce")


def discover_run_dirs(data_root: str | Path) -> list[Path]:
    """Discover run/iteration directories below ``data_root``.

    A directory is considered a run directory if it contains ``scenario.json``
    and ``sysdig_logs.ndjson``. The function supports two common layouts:

    1. ``scenario_dir/iteration-X/<files>``
    2. ``scenario_dir/<files>``
    """
    data_root = Path(data_root)
    if not data_root.exists():
        raise FileNotFoundError(f"Data root does not exist: {data_root}")

    candidates: set[Path] = set()

    # Directories containing the core files.
    for scenario_path in data_root.rglob("scenario.json"):
        run_dir = scenario_path.parent
        if all((run_dir / fname).exists() for fname in CORE_FILES):
            candidates.add(run_dir)

    return sorted(candidates)


def parse_scenario_name(path: str | Path) -> dict[str, Any]:
    """Parse common fields from scenario directory names.

    Example folder name:
    ``perturbation-moderate_attackDuration-20_intensity-medium_20260320T052205Z``.
    """
    name = Path(path).name
    # If this is an iteration directory, use parent name for scenario fields.
    if re.match(r"iteration[-_]\d+", name, flags=re.IGNORECASE):
        name = Path(path).parent.name
    out: dict[str, Any] = {}
    patterns = {
        "perturbation": r"perturbation-([^_]+)",
        "attack_duration": r"attackDuration-([0-9.]+)",
        "attack_intensity": r"intensity-([^_]+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, name)
        if m:
            val: Any = m.group(1)
            if key == "attack_duration":
                val = float(val)
                if val.is_integer():
                    val = int(val)
            out[key] = val
    return out
