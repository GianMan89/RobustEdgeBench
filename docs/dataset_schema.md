# Dataset schema

This repository expects generated campaign logs. It does not generate data.

## Scenario folders

Scenario folders are named descriptively, for example:

```text
perturbation-moderate_attackDuration-20_intensity-medium_20260320T052205Z
```

Inside each scenario folder, there may be one or more iteration folders:

```text
iteration-1/
iteration-2/
iteration-3/
```

A valid iteration folder should contain at least `scenario.json` and `sysdig_logs.ndjson`.

## Required metadata fields

The loader can infer some fields from folder names, but `scenario.json` should preferably contain:

```json
{
  "perturbation": "moderate",
  "perturbation_family": "record_loss",
  "severity": 0.5,
  "attack_duration": 20,
  "attack_intensity": "medium",
  "iteration": 3,
  "test_duration": 3600,
  "attack_start_delay": 263,
  "perturbation_parameters": {
    "affected_tag_fraction": 0.25,
    "drop_probability": 0.15,
    "affected_tags": ["pv_001_feed_flow"]
  }
}
```

Early campaigns may contain only categorical fields such as `perturbation = moderate`. In that case, the analysis uses the default profile-to-severity mapping in `configs/default.yaml`.

## Timestamps

The code accepts several common timestamp column names: `time`, `timestamp`, `ts`, `datetime`, `window_start`, and nested variants after JSON normalization. If timestamps are missing from `sysdig_logs.ndjson`, window times are inferred from row index and the configured sysdig window size.

## NDJSON flexibility

The NDJSON parser supports both flat and nested records. Nested fields such as `tags`, `fields`, `counts`, or `syscalls` are flattened using dot notation, e.g. `counts.write`.
