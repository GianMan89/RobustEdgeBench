"""End-to-end RobustEdgeBench pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.preprocessing import StandardScaler

from .calibration import QuantileCalibrator
from .data import DatasetIndex, RunData
from .features import MultiViewFeatureBuilder, infer_feature_columns
from .labels import intervals_from_binary_labels
from .metrics import evaluate_run
from .models import default_detectors
from .plotting import plot_heatmap, plot_profile, plot_timeline
from .robustness import aggregate_metrics, robustness_summary


def load_config(path: str | Path = "configs/default.yaml") -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_features(data_root: str | Path, config: dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame, list[RunData]]:
    profile_to_severity = config.get("scenario", {}).get("profile_to_severity")
    index = DatasetIndex.from_root(data_root, profile_to_severity=profile_to_severity)
    runs = index.load_runs()
    manifest = index.to_frame()
    fcfg = config.get("features", {})
    builder = MultiViewFeatureBuilder(
        window_seconds=float(fcfg.get("sysdig_window_seconds", 4.0)),
        include_runtime_features=bool(fcfg.get("include_runtime_features", True)),
        include_process_features=bool(fcfg.get("include_process_features", True)),
        include_controller_features=bool(fcfg.get("include_controller_features", True)),
        include_alarm_features=bool(fcfg.get("include_alarm_features", False)),
        process_deltas=bool(fcfg.get("process_deltas", True)),
        process_update_counts=bool(fcfg.get("process_update_counts", True)),
        controller_deltas=bool(fcfg.get("controller_deltas", True)),
    )
    features = builder.transform_runs(runs)
    return features, manifest, runs


def select_feature_prefixes(feature_view: str) -> tuple[str, ...]:
    if feature_view == "runtime":
        return ("rt_",)
    if feature_view == "runtime_process":
        return ("rt_", "proc_")
    if feature_view == "runtime_controller":
        return ("rt_", "ctrl_")
    if feature_view == "process_controller":
        return ("proc_", "ctrl_")
    if feature_view == "fused":
        return ("rt_", "proc_", "ctrl_")
    raise ValueError(f"Unknown feature_view: {feature_view}")


def split_phase1_clean_benign(features: pd.DataFrame, train_fraction: float, seed: int) -> tuple[list[str], list[str]]:
    clean = features[features["phase"] == "phase1_clean_benign"]
    run_ids = sorted(clean["run_id"].unique())
    if len(run_ids) < 2:
        raise ValueError("Need at least two phase1_clean_benign runs for training/calibration.")
    rng = np.random.default_rng(seed)
    rng.shuffle(run_ids)
    n_train = max(1, int(round(train_fraction * len(run_ids))))
    n_train = min(n_train, len(run_ids)-1)
    return run_ids[:n_train], run_ids[n_train:]


def fit_evaluate(features: pd.DataFrame, runs: list[RunData], config: dict[str, Any], output_dir: str | Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "models").mkdir(exist_ok=True)

    feature_view = config.get("features", {}).get("feature_view", "fused")
    prefixes = select_feature_prefixes(feature_view)
    feature_cols = infer_feature_columns(features, prefixes=prefixes)
    if not feature_cols:
        raise ValueError(f"No feature columns for view {feature_view}.")
    (output_dir / "feature_columns.json").write_text(json.dumps(feature_cols, indent=2), encoding="utf-8")

    split_cfg = config.get("splits", {})
    train_runs, val_runs = split_phase1_clean_benign(
        features,
        train_fraction=float(split_cfg.get("train_fraction_clean_benign", 0.67)),
        seed=int(split_cfg.get("random_seed", 42)),
    )

    X_train = features[features["run_id"].isin(train_runs)][feature_cols].to_numpy(float)
    X_val = features[features["run_id"].isin(val_runs)][feature_cols].to_numpy(float)

    scaler = StandardScaler().fit(X_train)
    joblib.dump(scaler, output_dir / "models" / "scaler.joblib")
    X_train_s = scaler.transform(X_train)
    X_val_s = scaler.transform(X_val)

    random_state = int(config.get("models", {}).get("random_state", 42))
    detectors = default_detectors(random_state=random_state, include_autoencoder=bool(config.get("models", {}).get("include_autoencoder", True)))
    quantile = float(config.get("calibration", {}).get("target_fpr_quantile", 0.995))
    window_seconds = float(config.get("features", {}).get("sysdig_window_seconds", 4.0))
    run_lookup = {r.run_id: r for r in runs}

    metric_rows, score_tables = [], []
    for detector in detectors:
        print(f"[INFO] training {detector.name}")
        detector.fit(X_train_s)
        val_scores = detector.score(X_val_s)
        cal = QuantileCalibrator(quantile=quantile).fit(val_scores)
        threshold = cal.threshold_
        joblib.dump(detector, output_dir / "models" / f"detector_{detector.name}.joblib")

        for run_id, g in features.groupby("run_id", sort=False):
            X = scaler.transform(g[feature_cols].to_numpy(float))
            scores = detector.score(X)
            preds = cal.predict(scores)
            y = g["label"].to_numpy(int)
            times = g["relative_time_s"].to_numpy(float)
            intervals = intervals_from_binary_labels(y, times, window_seconds)
            m = evaluate_run(y, scores, preds, times, intervals, window_seconds)
            first = g.iloc[0]
            row = {
                "detector": detector.name,
                "feature_view": feature_view,
                "run_id": run_id,
                "run_dir": first.get("run_dir", ""),
                "phase": first.get("phase", ""),
                "perturbation": first.get("perturbation", ""),
                "perturbation_family": first.get("perturbation_family", ""),
                "perturbation_profile": first.get("perturbation_profile", ""),
                "severity": first.get("severity", np.nan),
                "attack_duration": first.get("attack_duration", np.nan),
                "attack_intensity": first.get("attack_intensity", ""),
                "threshold": threshold,
            }
            row.update(m)
            metric_rows.append(row)

            score_df = g[["run_id", "relative_time_s", "label", "phase", "perturbation_family", "severity", "attack_duration", "attack_intensity"]].copy()
            score_df["detector"] = detector.name
            score_df["score"] = scores
            score_df["prediction"] = preds
            score_df["threshold"] = threshold
            score_tables.append(score_df)

    metrics = pd.DataFrame(metric_rows)
    scores = pd.concat(score_tables, ignore_index=True) if score_tables else pd.DataFrame()
    agg = aggregate_metrics(metrics)
    summary_frames = []
    for metric, hib in [("event_recall_mean", True), ("auroc_mean", True), ("auprc_mean", True), ("false_alarms_per_hour_mean", False)]:
        if metric in agg.columns:
            summary_frames.append(robustness_summary(agg, metric=metric, higher_is_better=hib))
    summary = pd.concat(summary_frames, ignore_index=True) if summary_frames else pd.DataFrame()

    metrics.to_csv(output_dir / "metrics_by_run.csv", index=False)
    scores.to_csv(output_dir / "scores_by_window.csv", index=False)
    agg.to_csv(output_dir / "metrics_aggregated.csv", index=False)
    summary.to_csv(output_dir / "robustness_summary.csv", index=False)
    return metrics, scores, agg


def make_figures(agg: pd.DataFrame, scores: pd.DataFrame, output_dir: str | Path) -> None:
    fig_dir = Path(output_dir) / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    if "event_recall_mean" in agg.columns:
        plot_profile(agg[agg["phase"] == "phase4_perturbed_attacked"], "event_recall_mean", fig_dir / "robustness_profiles_event_recall.png", ylabel="Event recall")
        # Heatmap for first detector with phase4 data.
        detectors = agg["detector"].dropna().unique()
        if len(detectors):
            phase4 = agg[agg["phase"] == "phase4_perturbed_attacked"]
            if not phase4.empty:
                plot_heatmap(phase4, "event_recall_mean", detectors[0], output_path=fig_dir / "heatmap_event_recall.png", title=f"Event recall ({detectors[0]})")

    if "false_alarms_per_hour_mean" in agg.columns:
        phase3 = agg[agg["phase"] == "phase3_perturbed_benign"]
        if not phase3.empty:
            detectors = phase3["detector"].dropna().unique()
            if len(detectors):
                plot_heatmap(phase3, "false_alarms_per_hour_mean", detectors[0], output_path=fig_dir / "heatmap_false_alarms_per_hour.png", title=f"FA/h ({detectors[0]})")

    if not scores.empty and (scores["label"] == 1).any():
        row = scores[scores["label"] == 1].iloc[0]
        try:
            plot_timeline(scores, row["run_id"], row["detector"], fig_dir / "timeline_example.png")
        except Exception as exc:
            print(f"[WARN] timeline plot failed: {exc}")


def run_end_to_end(data_root: str | Path, output_dir: str | Path, config_path: str | Path = "configs/default.yaml") -> None:
    config = load_config(config_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    features, manifest, runs = build_features(data_root, config)
    manifest.to_csv(output_dir / "manifest.csv", index=False)
    features.to_csv(output_dir / "features.csv", index=False)
    metrics, scores, agg = fit_evaluate(features, runs, config, output_dir)
    make_figures(agg, scores, output_dir)
    print(f"[INFO] wrote outputs to {output_dir}")
