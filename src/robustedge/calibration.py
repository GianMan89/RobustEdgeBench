"""Threshold calibration utilities."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class QuantileCalibrator:
    """Quantile-based threshold calibrator.

    The threshold is fitted on benign validation scores only. Larger scores are
    assumed to be more anomalous.
    """

    quantile: float = 0.995

    def fit(self, scores: np.ndarray) -> "QuantileCalibrator":
        if len(scores) == 0:
            raise ValueError("Cannot calibrate threshold on empty score array.")
        self.threshold_ = float(np.quantile(scores, self.quantile))
        return self

    def predict(self, scores: np.ndarray) -> np.ndarray:
        return (scores > self.threshold_).astype(int)


def threshold_for_false_alarms_per_hour(scores: np.ndarray, window_seconds: float, target_fa_per_hour: float) -> float:
    """Choose a threshold to approximately satisfy an FA/h target on benign data."""
    if len(scores) == 0:
        raise ValueError("Cannot calibrate threshold on empty score array.")
    hours = len(scores) * window_seconds / 3600.0
    allowed_false_alarms = max(0, int(np.floor(target_fa_per_hour * hours)))
    sorted_scores = np.sort(scores)
    if allowed_false_alarms <= 0:
        return float(sorted_scores[-1])
    idx = max(0, len(sorted_scores) - allowed_false_alarms - 1)
    return float(sorted_scores[idx])
