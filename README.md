# RobustEdgeBench

**RobustEdgeBench** is a Python/Jupyter repository for robustness analysis of ML-based container attack detection in a containerized industrial edge testbed. It assumes that a separate data-generation campaign has already produced per-run log folders (TEP-inspired telemetry, alarm events, controller commands, attack annotations, and container runtime traces). This repository focuses only on:

1. indexing and validating generated run folders,
2. parsing exported NDJSON and metadata files,
3. constructing detector-ready features from runtime logs,
4. training normal-only anomaly detectors,
5. evaluating attack detection and false-alarm behavior,
6. producing robustness curves and publication figures.

The repository is designed around the ETFA 2026 paper:

> Robustness Benchmarking of ML-Based Container Attack Detection with a Perturbation-Driven Industrial Edge Testbed

The data-generation pipeline is intentionally **not** part of this repository.

---

## Expected dataset layout

The code expects a dataset folder with scenario directories and iteration folders, e.g.

```text
data/raw/logs/
  perturbation-none_attackDuration-20_intensity-medium_20260320T052205Z/
    iteration-1/
      tep_signals.ndjson
      tep_alarm_events.ndjson
      tep_controller_mv_commands.ndjson
      attack_records.ndjson
      annotations.ndjson
      sysdig_logs.ndjson
      scenario.json
      config.json
      container_attack-runner.log
      container_controller.log
      container_grafana.log
      container_influxdb.log
      container_tep-simulator.log
    iteration-2/
      ...
  perturbation-moderate_attackDuration-20_intensity-medium_20260320T052205Z/
    iteration-1/
      ...
```

The loader is permissive: it also accepts run folders where the files are directly in the scenario folder rather than inside an `iteration-X` folder. This is useful for early proof-of-concept campaigns.

---

## Core exported files

| File | Role in analysis |
|---|---|
| `scenario.json` | Run-level metadata: perturbation, attack duration/intensity, iteration, test duration, attack start delay, severity if available. |
| `config.json` | Campaign and generator configuration. |
| `sysdig_logs.ndjson` | Primary detector input: fixed-window syscall aggregates for the monitored container. |
| `annotations.ndjson` | Run markers and attack windows. Used for labels when available. |
| `attack_records.ndjson` | Attack-agent traces. Used for integrity checks and diagnostics. |
| `tep_signals.ndjson` | PV/MV process telemetry. Used for context and optional future fusion. |
| `tep_alarm_events.ndjson` | Alarm event stream. Used for context and optional future fusion. |
| `tep_controller_mv_commands.ndjson` | Controller command/audit stream. Used for context and optional future fusion. |
| `container_*.log` | Container logs for run-integrity checks and troubleshooting. |

The first ETFA analysis focuses on `sysdig_logs.ndjson` as the primary ML input, because the detector target is runtime behavior of the InfluxDB container. Process telemetry and alarm streams are still scientifically important because their perturbations modify the database workload.

---

## Installation

Create a clean environment and install the package in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install --upgrade pip
pip install -e .[dev]
```

Alternatively, install from `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Quick start

### 1. Inspect the dataset

```bash
python scripts/summarize_dataset.py --data-root data/raw/logs
```

This prints the discovered runs, scenario fields, missing files, and counts by perturbation/attack settings.

### 2. Run the full baseline pipeline

```bash
python scripts/run_pipeline.py \
  --data-root data/raw/logs \
  --output-dir outputs/etfa_baseline \
  --target-fpr-quantile 0.995
```

The script will:

1. discover runs,
2. extract sysdig feature windows,
3. train normal-only detectors on clean benign runs,
4. calibrate thresholds on clean benign validation runs,
5. evaluate all runs,
6. write metrics, scores, robustness summaries, and figures to `outputs/etfa_baseline/`.

### 3. Use the notebooks

Recommended notebook order:

1. `notebooks/00_dataset_overview.ipynb`
2. `notebooks/01_preprocess_features.ipynb`
3. `notebooks/02_train_baselines.ipynb`
4. `notebooks/03_evaluate_robustness.ipynb`
5. `notebooks/04_paper_figures.ipynb`

The notebooks call the reusable Python classes in `src/robustedge/` and are intended for transparent scientific analysis.

---

## Perturbation convention used by the analysis

The repository supports both early categorical profiles (`none`, `light`, `moderate`, `heavy`) and continuous severity values. If a run only provides a categorical profile, the default mapping is:

| Profile | Default severity |
|---|---:|
| `none` | 0.0 |
| `light` | 0.25 |
| `moderate` | 0.50 |
| `heavy` | 1.0 |

For the final benchmark, prefer explicit fields in `scenario.json`, for example:

```json
{
  "perturbation_family": "record_loss",
  "severity": 0.5,
  "perturbation_parameters": {
    "affected_tag_fraction": 0.25,
    "drop_probability": 0.15,
    "affected_tags": ["pv_001_feed_flow", "pv_002_recycle_flow"]
  }
}
```

See `docs/perturbations.md` for the detailed ETFA perturbation definitions.

---

## Scientific protocol

The default protocol is:

- **Training:** clean benign runs only (`attack_duration = 0`, severity/profile = none).
- **Validation/calibration:** disjoint clean benign runs only.
- **Benign robustness controls:** no-attack runs under perturbations, used for false alarms per hour.
- **Attack robustness tests:** attacked runs under the same perturbation families/severities.
- **Primary metrics:** false alarms per hour (FA/h), event recall (ER), and time-to-detect (TTD).
- **Secondary diagnostics:** AUROC and AUPRC.
- **Robustness summaries:** average robustness, worst-severity robustness, and product-style robustness over a severity grid.

---

## Outputs

A typical run creates:

```text
outputs/etfa_baseline/
  run_index.csv
  features.csv
  feature_columns.json
  metrics_by_run.csv
  scores_by_window.csv
  robustness_summary.csv
  figures/
    robustness_event_recall.png
    robustness_false_alarms_per_hour.png
    timeline_example.png
  models/
    scaler.joblib
    detector_pca.joblib
    detector_gmm.joblib
    ...
```

---

## Repository structure

```text
robustedge-bench/
  README.md
  pyproject.toml
  requirements.txt
  configs/
    default.yaml
  data/
    README.md
    raw/.gitkeep
    processed/.gitkeep
  docs/
    dataset_schema.md
    perturbations.md
    evaluation_protocol.md
    releasing_data.md
  notebooks/
    00_dataset_overview.ipynb
    01_preprocess_features.ipynb
    02_train_baselines.ipynb
    03_evaluate_robustness.ipynb
    04_paper_figures.ipynb
  scripts/
    summarize_dataset.py
    run_pipeline.py
  src/robustedge/
    io.py
    data.py
    features.py
    labels.py
    models.py
    calibration.py
    metrics.py
    robustness.py
    plotting.py
    pipeline.py
  tests/
    fixtures/minimal_dataset/...
    test_discovery.py
    test_metrics.py
```

---

## Data release note

The repository is designed to work with data tracked separately via Git LFS, Zenodo, OSF, or an institutional data repository. For public release, avoid committing large raw log folders directly to Git. Instead, provide:

1. a stable dataset DOI or release archive,
2. checksums for archives,
3. a manifest listing run folders and scenario metadata,
4. the exact code commit used for the paper.

---

## Citation

A `CITATION.cff` file is included as a placeholder. Please update title, authors, DOI, and repository URL once the public release is finalized.
