# Evaluation protocol

## Phases

- Phase 1: clean benign, used for training/calibration.
- Phase 2: clean attacked, used for nominal attack-detection baseline.
- Phase 3: perturbed benign, used for false-alarm robustness.
- Phase 4: perturbed attacked, used for robustness under attack.

## Current severity grid

The current campaign contains selected severity values (`0.50`, `1.00`) rather than a dense grid. The repository therefore emphasizes:

- robustness profiles,
- family/severity heatmaps,
- tabular summaries over available severity points.

If future data include more severity levels, the same code can produce curves.

## Metrics

Primary:

- false alarms per hour,
- event recall,
- time-to-detect.

Secondary:

- AUROC,
- AUPRC,
- window-level precision/recall/F1/MCC.

## Splitting

Default training and calibration use only `phase1_clean_benign`. Splits are run-level. All other phases are test data.
