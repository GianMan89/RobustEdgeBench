#!/usr/bin/env python
from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from robustedge.pipeline import run_end_to_end


def main() -> None:
    parser = argparse.ArgumentParser(description="Run RobustEdgeBench analysis pipeline.")
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--output-dir", default="outputs/etfa_campaign")
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--feature-view", choices=["runtime", "runtime_process", "runtime_controller", "process_controller", "fused"], default=None)
    args = parser.parse_args()

    config_path = Path(args.config)
    if args.feature_view is not None:
        with config_path.open("r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        cfg.setdefault("features", {})["feature_view"] = args.feature_view
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        config_path = out / "effective_config.yaml"
        with config_path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f)

    run_end_to_end(args.data_root, args.output_dir, config_path)


if __name__ == "__main__":
    main()
