#!/usr/bin/env python
"""Run the complete RobustEdgeBench analysis pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from robustedge.pipeline import run_end_to_end


def main() -> None:
    parser = argparse.ArgumentParser(description="Run full anomaly-detection robustness analysis.")
    parser.add_argument("--data-root", required=True, help="Path to raw logs root.")
    parser.add_argument("--output-dir", default="outputs/etfa_baseline", help="Directory for analysis outputs.")
    parser.add_argument("--config", default="configs/default.yaml", help="YAML configuration file.")
    parser.add_argument("--target-fpr-quantile", type=float, default=None, help="Override quantile threshold, e.g. 0.995.")
    args = parser.parse_args()

    config_path = Path(args.config)
    if args.target_fpr_quantile is not None:
        # Write a temporary config in the output directory with the override.
        with config_path.open("r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        cfg.setdefault("calibration", {})["target_fpr_quantile"] = args.target_fpr_quantile
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        config_path = out / "effective_config.yaml"
        with config_path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f)

    run_end_to_end(data_root=args.data_root, output_dir=args.output_dir, config_path=config_path)


if __name__ == "__main__":
    main()
