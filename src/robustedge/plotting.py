"""Plotting utilities for publication figures."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_robustness_curve(
    agg: pd.DataFrame,
    metric_mean_col: str,
    metric_std_col: str | None = None,
    detector_col: str = "detector",
    family: str | None = None,
    attack_duration: float | None = None,
    output_path: str | Path | None = None,
    ylabel: str | None = None,
) -> plt.Figure:
    """Plot metric versus severity, grouped by detector."""
    df = agg.copy()
    if family is not None:
        df = df[df["perturbation_family"] == family]
    if attack_duration is not None:
        df = df[df["attack_duration"] == attack_duration]

    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    for detector, g in df.groupby(detector_col):
        g = g.sort_values("severity")
        x = g["severity"].astype(float).values
        y = g[metric_mean_col].astype(float).values
        if metric_std_col and metric_std_col in g.columns:
            yerr = g[metric_std_col].fillna(0.0).astype(float).values
            ax.errorbar(x, y, yerr=yerr, marker="o", label=str(detector), capsize=2)
        else:
            ax.plot(x, y, marker="o", label=str(detector))
    ax.set_xlabel("Perturbation severity $\\lambda$")
    ax.set_ylabel(ylabel or metric_mean_col.replace("_", " "))
    title_bits = []
    if family:
        title_bits.append(str(family))
    if attack_duration is not None:
        title_bits.append(f"attack duration={attack_duration:g}s")
    if title_bits:
        ax.set_title("; ".join(title_bits))
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
    return fig


def plot_timeline(
    scores: pd.DataFrame,
    run_id: str,
    detector: str,
    output_path: str | Path | None = None,
) -> plt.Figure:
    """Plot anomaly score timeline for one run and one detector."""
    df = scores[(scores["run_id"] == run_id) & (scores["detector"] == detector)].copy()
    if df.empty:
        raise ValueError(f"No scores for run_id={run_id!r}, detector={detector!r}")
    df = df.sort_values("relative_time_s")
    fig, ax = plt.subplots(figsize=(7.0, 3.5))
    ax.plot(df["relative_time_s"], df["score"], label="score")
    if "threshold" in df.columns:
        ax.axhline(df["threshold"].iloc[0], linestyle="--", label="threshold")
    if "label" in df.columns and df["label"].max() > 0:
        attack = df[df["label"] == 1]
        ax.axvspan(attack["relative_time_s"].min(), attack["relative_time_s"].max(), alpha=0.2, label="attack")
    ax.set_xlabel("Time since run start [s]")
    ax.set_ylabel("Anomaly score")
    ax.set_title(f"{detector} on {run_id}")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
    return fig
