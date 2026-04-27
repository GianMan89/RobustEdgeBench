# RobustEdgeBench

**RobustEdgeBench** is a reproducible Python/Jupyter analysis repository for the ETFA 2026 robustness benchmark on **ML-based container attack detection in industrial edge systems**.

The repository assumes that the data-generation campaign has already been executed. It does **not** generate telemetry, perturbations, or attacks. Instead, it provides reusable code for:

1. indexing generated campaign folders,
2. parsing run metadata and exported NDJSON files,
3. extracting detector-ready features from runtime, process, and controller logs,
4. training normal-only anomaly detection baselines,
5. evaluating clean and perturbed attack-detection performance,
6. quantifying false-alarm behavior under telemetry perturbations,
7. generating robustness profiles, heatmaps, timelines, and paper-ready figures.

The repository is designed for the current ABB/RUB campaign structure and supports folders such as:

```text
data/raw/logs/
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