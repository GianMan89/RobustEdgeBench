#!/usr/bin/env python
"""Summarize a RobustEdgeBench raw dataset."""

from __future__ import annotations

import argparse
from pathlib import Path

from robustedge.data import DatasetIndex


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize generated campaign logs.")
    parser.add_argument("--data-root", required=True, help="Path to data/raw/logs or equivalent root.")
    args = parser.parse_args()

    index = DatasetIndex.from_root(args.data_root)
    df = index.to_frame()
    print(f"Discovered {len(df)} run folders below {Path(args.data_root).resolve()}")
    if df.empty:
        return
    print("\nCounts by perturbation / attack duration / intensity:")
    print(df.groupby(["perturbation", "attack_duration", "attack_intensity"], dropna=False).size().reset_index(name="n_runs"))
    print("\nFirst runs:")
    print(df.head(20).to_string(index=False))
    missing = df[df["missing_optional_files"].astype(str) != ""]
    if not missing.empty:
        print("\nRuns with missing optional files:")
        print(missing[["run_id", "missing_optional_files"]].head(20).to_string(index=False))


if __name__ == "__main__":
    main()
