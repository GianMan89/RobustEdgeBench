"""End-to-end analysis pipeline."""

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
from .features import FeatureTableBuilder, infer_feature_columns
from .labels import attack_intervals_from_run
from .metrics import evaluate_run_predictions
from .models import BaseDetector, default_detectors
from .robustness import aggregate_metrics, robustness_scores
from .plotting import plot_robustness_curve, plot_timeline


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        path = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_feature_dataset(data_root: str | Path, config: dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame, list[RunData]]:
    profile_to_severity = config.get("scenario", {}).get("profile_to_severity", None)
    index = DatasetIndex.from_root(data_root, profile_to_severity=profile_to_severity)
    runs = index.load_runs()
    run_index = index.to_frame()
    window_seconds = float(config.get("features", {}).get("sysdig_window_seconds", 4.0))
    features = FeatureTableBuilder(sysdig_window_seconds=window_seconds).transform_runs(runs)
    return features, run_index, runs


def split_clean_benign_runs(features: pd.DataFrame, train_fraction: float = 0.7, random_seed: int = 42) -> tuple[list[str], list[str]]:
    """Split clean benign runs into training and validation run IDs."""
    clean = features[(features["attack_duration"] == 0) & (features["severity"].fillna(0) == 0)]
    run_ids = sorted(clean["run_id"].unique())
    if len(run_ids) < 2:
        raise ValueError("Need at least two clean benign runs for train/validation split. Add more attack_duration=0, severity=0 runs.")
    rng = np.random.default_rng(random_seed)
    rng.shuffle(run_ids)
    n_train = max(1, int(round(len(run_ids) * train_fraction)))
    n_train = min(n_train, len(run_ids) - 1)
    return run_ids[:n_train], run_ids[n_train:]


def fit_and_evaluate(
    features: pd.DataFrame,
    runs: list[RunData],
    config: dict[str, Any],
    output_dir: str | Path,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Train detectors and evaluate all runs."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "models").mkdir(exist_ok=True)

    if features.empty:
        raise ValueError("Feature table is empty; check data root and sysdig logs.")

    feature_cols = infer_feature_columns(features)
    if not feature_cols:
        raise ValueError("No numeric feature columns found.")
    (output_dir / "feature_columns.json").write_text(json.dumps(feature_cols, indent=2), encoding="utf-8")

    train_fraction = float(config.get("splits", {}).get("train_fraction_clean_benign", 0.7))
    random_seed = int(config.get("splits", {}).get("random_seed", 42))
    train_runs, val_runs = split_clean_benign_runs(features, train_fraction, random_seed)

    train_mask = features["run_id"].isin(train_runs)
    val_mask = features["run_id"].isin(val_runs)
    X_train = features.loc[train_mask, feature_cols].to_numpy(dtype=float)
    X_val = features.loc[val_mask, feature_cols].to_numpy(dtype=float)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    joblib.dump(scaler, output_dir / "models" / "scaler.joblib")

    include_ae = bool(config.get("models", {}).get("include_autoencoder", True))
    detectors = default_detectors(random_state=random_seed, include_autoencoder=include_ae)
    quantile = float(config.get("calibration", {}).get("target_fpr_quantile", 0.995))
    window_seconds = float(config.get("features", {}).get("sysdig_window_seconds", 4.0))

    run_lookup = {r.run_id: r for r in runs}
    metrics_rows: list[dict[str, Any]] = []
    score_rows: list[pd.DataFrame] = []

    for detector in detectors:
        print(f"[INFO] Training detector: {detector.name}")
        detector.fit(X_train_scaled)
        val_scores = detector.score(X_val_scaled)
        calibrator = QuantileCalibrator(quantile=quantile).fit(val_scores)
        threshold = calibrator.threshold_
        joblib.dump(detector, output_dir / "models" / f"detector_{detector.name}.joblib")

        for run_id, g in features.groupby("run_id", sort=False):
            X_run = scaler.transform(g[feature_cols].to_numpy(dtype=float))
            scores = detector.score(X_run)
            y_pred = calibrator.predict(scores)
            y_true = g["label"].to_numpy(dtype=int) if "label" in g.columns else np.zeros(len(g), dtype=int)
            times = g["relative_time_s"].to_numpy(dtype=float)
            intervals = attack_intervals_from_run(run_lookup[run_id]) if run_id in run_lookup else []
            m = evaluate_run_predictions(y_true, scores, y_pred, times, intervals, window_seconds)
            first = g.iloc[0]
            row = {
                "detector": detector.name,
                "run_id": run_id,
                "run_dir": first.get("run_dir", ""),
                "perturbation": first.get("perturbation", ""),
                "perturbation_family": first.get("perturbation_family", ""),
                "perturbation_profile": first.get("perturbation_profile", ""),
                "severity": first.get("severity", np.nan),
                "attack_duration": first.get("attack_duration", np.nan),
                "attack_intensity": first.get("attack_intensity", ""),
                "threshold": threshold,
            }
            row.update(m)
            metrics_rows.append(row)

            score_df = g[["run_id", "relative_time_s", "label", "perturbation_family", "perturbation_profile", "severity", "attack_duration", "attack_intensity"]].copy()
            score_df["detector"] = detector.name
            score_df["score"] = scores
            score_df["prediction"] = y_pred
            score_df["threshold"] = threshold
            score_rows.append(score_df)

    metrics_df = pd.DataFrame(metrics_rows)
    scores_df = pd.concat(score_rows, ignore_index=True) if score_rows else pd.DataFrame()
    agg_df = aggregate_metrics(metrics_df)

    metrics_df.to_csv(output_dir / "metrics_by_run.csv", index=False)
    scores_df.to_csv(output_dir / "scores_by_window.csv", index=False)
    agg_df.to_csv(output_dir / "metrics_aggregated.csv", index=False)

    # Robustness summaries for key higher-is-better metrics when available.
    summary_frames = []
    for metric_col in ["event_recall_mean", "auroc_mean", "auprc_mean"]:
        if metric_col in agg_df.columns:
            summary_frames.append(robustness_scores(agg_df, metric=metric_col, higher_is_better=True))
    if summary_frames:
        summary_df = pd.concat(summary_frames, ignore_index=True)
        summary_df.to_csv(output_dir / "robustness_summary.csv", index=False)
    else:
        summary_df = pd.DataFrame()

    return metrics_df, scores_df, agg_df


def make_default_figures(metrics_agg: pd.DataFrame, scores: pd.DataFrame, output_dir: str | Path) -> None:
    """Create a small default figure set."""
    output_dir = Path(output_dir)
    fig_dir = output_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    if "event_recall_mean" in metrics_agg.columns:
        for family in metrics_agg["perturbation_family"].dropna().unique():
            try:
                plot_robustness_curve(
                    metrics_agg,
                    metric_mean_col="event_recall_mean",
                    metric_std_col="event_recall_std",
                    family=family,
                    output_path=fig_dir / f"robustness_event_recall_{family}.png",
                    ylabel="Event recall",
                )
            except Exception as exc:
                print(f"[WARN] Could not plot event recall for {family}: {exc}")

    if "false_alarms_per_hour_mean" in metrics_agg.columns:
        for family in metrics_agg["perturbation_family"].dropna().unique():
            try:
                plot_robustness_curve(
                    metrics_agg,
                    metric_mean_col="false_alarms_per_hour_mean",
                    metric_std_col="false_alarms_per_hour_std",
                    family=family,
                    output_path=fig_dir / f"robustness_faph_{family}.png",
                    ylabel="False alarms per hour",
                )
            except Exception as exc:
                print(f"[WARN] Could not plot FA/h for {family}: {exc}")

    if not scores.empty:
        # First attacked run and first detector as an example timeline.
        attacked = scores[scores["label"] == 1]
        if not attacked.empty:
            run_id = attacked["run_id"].iloc[0]
            detector = attacked["detector"].iloc[0]
            try:
                plot_timeline(scores, run_id=run_id, detector=detector, output_path=fig_dir / "timeline_example.png")
            except Exception as exc:
                print(f"[WARN] Could not plot timeline: {exc}")


def run_end_to_end(data_root: str | Path, output_dir: str | Path, config_path: str | Path | None = None) -> None:
    """Run the complete analysis workflow."""
    config = load_config(config_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    features, run_index, runs = build_feature_dataset(data_root, config)
    run_index.to_csv(output_dir / "run_index.csv", index=False)
    features.to_csv(output_dir / "features.csv", index=False)

    metrics, scores, agg = fit_and_evaluate(features, runs, config, output_dir)
    make_default_figures(agg, scores, output_dir)
    print(f"[INFO] Analysis complete. Outputs written to: {output_dir}")
