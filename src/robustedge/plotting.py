"""Plotting utilities for paper figures."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_profile(agg: pd.DataFrame, metric_col: str, output_path: str | Path | None = None, ylabel: str | None = None) -> plt.Figure:
    """Plot robustness profiles over available severity values."""
    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    for (det, fam), g in agg.groupby(["detector", "perturbation_family"], dropna=False):
        g = g.sort_values("severity")
        label = f"{det}/{fam}"
        ax.plot(g["severity"], g[metric_col], marker="o", label=label)
    ax.set_xlabel("Perturbation severity $\\lambda$")
    ax.set_ylabel(ylabel or metric_col)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=7, ncol=2)
    fig.tight_layout()
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
    return fig


def plot_heatmap(agg: pd.DataFrame, metric_col: str, detector: str, attack_duration: float | None = None, output_path: str | Path | None = None, title: str | None = None) -> plt.Figure:
    """Plot perturbation-family by severity heatmap for one detector."""
    df = agg[agg["detector"] == detector].copy()
    if attack_duration is not None:
        df = df[df["attack_duration"] == attack_duration]
    pivot = df.pivot_table(index="perturbation_family", columns="severity", values=metric_col, aggfunc="mean")
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    im = ax.imshow(pivot.values, aspect="auto")
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels([str(c) for c in pivot.columns])
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels([str(i) for i in pivot.index])
    ax.set_xlabel("Severity $\\lambda$")
    ax.set_ylabel("Perturbation family")
    ax.set_title(title or f"{metric_col} ({detector})")
    for i in range(pivot.shape[0]):
        for j in range(pivot.shape[1]):
            val = pivot.values[i, j]
            if not np.isnan(val):
                ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=8)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
    return fig


def plot_timeline(scores: pd.DataFrame, run_id: str, detector: str, output_path: str | Path | None = None) -> plt.Figure:
    df = scores[(scores["run_id"] == run_id) & (scores["detector"] == detector)].sort_values("relative_time_s")
    if df.empty:
        raise ValueError(f"No scores for run_id={run_id}, detector={detector}")
    fig, ax = plt.subplots(figsize=(7.0, 3.5))
    ax.plot(df["relative_time_s"], df["score"], label="score")
    if "threshold" in df:
        ax.axhline(df["threshold"].iloc[0], linestyle="--", label="threshold")
    if "label" in df and df["label"].max() > 0:
        atk = df[df["label"] == 1]
        ax.axvspan(atk["relative_time_s"].min(), atk["relative_time_s"].max(), alpha=0.2, label="attack")
    ax.set_xlabel("Time since run start [s]")
    ax.set_ylabel("Anomaly score")
    ax.set_title(f"{detector}: {run_id}")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
    return fig
