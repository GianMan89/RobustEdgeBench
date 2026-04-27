import numpy as np

from robustedge.metrics import event_recall_and_ttd, false_alarms_per_hour


def test_event_recall_and_ttd_detected():
    times = np.array([0, 4, 8, 12, 16, 20], dtype=float)
    y_pred = np.array([0, 0, 0, 1, 0, 0])
    er, ttd = event_recall_and_ttd(y_pred, times, [(10, 18)])
    assert er == 1.0
    assert ttd == [2.0]


def test_false_alarms_per_hour():
    y_true = np.array([0, 0, 0, 1])
    y_pred = np.array([0, 1, 0, 1])
    faph = false_alarms_per_hour(y_true, y_pred, window_seconds=4.0)
    assert faph == 1 / (3 * 4 / 3600)
