# RobustEdgeBench

**RobustEdgeBench** is a reproducible Python/Jupyter analysis repository for the ETFA 2026 robustness benchmark on **ML-based container attack detection in industrial edge systems**.

The repository assumes that the data-generation campaign has already been run. It does **not** generate telemetry or attacks. Instead, it provides reusable code for:

1. indexing generated campaign folders,
2. parsing run metadata and exported NDJSON files,
3. extracting detector-ready features from `sysdig_logs.ndjson`, `tep_signals.ndjson`, and `tep_controller_mv_commands.ndjson`,
4. training normal-only anomaly detection baselines,
5. evaluating attack detection and false-alarm behavior,
6. generating robustness profiles, heatmaps, timelines, and paper-ready figures.

The code is designed for the current ABB/RUB campaign structure, including folders such as:

```text
phase-phase1_clean_benign_perturbation-none_attackDuration-0_intensity-_20260424T191959Z/
  iteration-1/
    scenario.json
    config.json
    sysdig_logs.ndjson
    tep_signals.ndjson
    tep_controller_mv_commands.ndjson
    tep_alarm_events.ndjson
    annotations.ndjson
    attack_records.ndjson
    container_*.log
```

The public GitHub repository can host this analysis code and either the full dataset or a link to a separate dataset release.

---

## Current campaign phases

The current dataset naming convention is phase-aware:

| Phase | Meaning | Use in analysis |
|---|---|---|
| `phase1_clean_benign` | No attack, no perturbation | Training and validation/calibration |
| `phase2_clean_attacked` | Attack, no perturbation | Nominal attack-detection baseline |
| `phase3_perturbed_benign` | Perturbation, no attack | False-alarm robustness |
| `phase4_perturbed_attacked` | Perturbation and attack | Robustness under attack |

The parser extracts these fields from the folder names:

- `phase`
- `perturbation_family`, e.g. `P1`, `P2`, ...
- `severity`, e.g. `lam0.50`
- `attack_duration`
- `attack_intensity`
- timestamp
- iteration number

The parser intentionally gives priority to the folder name over older `scenario.json` fields when the JSON is less specific.

---

## Feature extraction

The feature extraction follows the idea of the ABB zero-day container attack-detection paper: runtime features are formed from a **bag-of-system-calls** representation of `sysdig_logs.ndjson`. The current repository extends this by optionally appending process and controller context features:

1. **Runtime view** (`sysdig_logs.ndjson`): syscall-count features per sysdig window.
2. **Process view** (`tep_signals.ndjson`): last-observation-carried-forward PV/MV values aligned to each sysdig window, plus selected update-count features.
3. **Controller view** (`tep_controller_mv_commands.ndjson`): last command values aligned to each sysdig window, plus command deltas.
4. **Fused view**: runtime + process + controller features. This is the default because perturbations act on telemetry delivery and can affect both the database workload and observed process/controller streams.

Alarm events are not included by default because alarm activation may also reflect legitimate abnormal process behavior. They can be enabled in configuration for diagnostic studies.

---

## Perturbation handling

The current dataset contains selected perturbation severities rather than a dense grid:

- P1--P5,
- `lambda = 0.50` and `lambda = 1.00`,
- benign and attacked robustness phases,
- three repetitions per condition.

The analysis therefore reports **discrete robustness profiles and heatmaps** rather than assuming smooth robustness curves. If future campaigns add more severity levels, the same code can plot curves.

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e .[dev]
```

or:

```bash
pip install -r requirements.txt
```

---

## Quick start

Place raw generated logs under:

```text
data/raw/logs/
```

Then run:

```bash
python scripts/make_manifest.py --data-root data/raw/logs --output outputs/manifest.csv
python scripts/summarize_dataset.py --data-root data/raw/logs
python scripts/run_pipeline.py --data-root data/raw/logs --output-dir outputs/etfa_campaign
```

The full pipeline produces:

```text
outputs/etfa_campaign/
  manifest.csv
  features.csv
  feature_columns.json
  metrics_by_run.csv
  scores_by_window.csv
  metrics_aggregated.csv
  robustness_summary.csv
  figures/
    heatmap_event_recall.png
    heatmap_false_alarms_per_hour.png
    robustness_profiles_event_recall.png
    timeline_example.png
  models/
    scaler.joblib
    detector_pca.joblib
    detector_gmm.joblib
    ...
```

---

## Notebooks

Recommended order:

1. `notebooks/00_dataset_overview.ipynb`
2. `notebooks/01_feature_extraction.ipynb`
3. `notebooks/02_train_baselines.ipynb`
4. `notebooks/03_evaluate_robustness.ipynb`
5. `notebooks/04_paper_figures.ipynb`

All notebooks call reusable Python code from `src/robustedge/`.

---

## Scientific protocol

Default protocol:

- Train on `phase1_clean_benign`.
- Split clean benign runs at run level into training and calibration.
- Evaluate nominal clean attacks on `phase2_clean_attacked`.
- Evaluate false-alarm robustness on `phase3_perturbed_benign`.
- Evaluate attacked robustness on `phase4_perturbed_attacked`.
- Report FA/h, event recall, TTD, AUROC/AUPRC.
- Report discrete robustness heatmaps by perturbation family and severity.

---

## Patch v2: robustness evaluation and figure updates

This patch addresses the latest analysis requirements:

- uses leave-one-clean-benign-out splits instead of one random split;
- evaluates all configured feature views (`runtime`, `runtime_process`, `runtime_controller`, `fused`);
- excludes training runs from primary evaluation outputs;
- keeps validation clean-benign runs as the lambda=0 benign reference;
- adds false-alarm rate as a percentage of benign windows;
- keeps false alarms per hour as an additional diagnostic;
- writes per-run metrics and pooled window-level condition metrics;
- adds pooled-window metrics for all benign/attack windows together;
- adds lambda=0 clean baselines for heatmap visualization;
- generates heatmaps for all models and feature views;
- generates score timelines for all test runs with all models shown together;
- fixes timestamp alignment dtype issues for pandas.merge_asof.
