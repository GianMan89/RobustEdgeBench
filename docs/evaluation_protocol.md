# Evaluation protocol

## Splits

1. **Training:** clean benign runs only (`attack_duration = 0`, severity 0/profile `none`).
2. **Validation:** disjoint clean benign runs only, used for threshold calibration.
3. **Benign robustness controls:** no-attack perturbed runs, used for false alarms per hour.
4. **Attack robustness tests:** attacked runs under perturbation families and severity sweeps.

Splits are performed at run level, never at window level, to avoid temporal leakage.

## Primary metrics

- **False alarms per hour (FA/h):** evaluated on benign runs.
- **Event recall (ER):** attack event is detected if at least one alarm is raised during the attack interval.
- **Time-to-detect (TTD):** time between attack onset and first detector alarm during the attack interval.

## Secondary metrics

- AUROC
- AUPRC
- Window-level precision/recall/F1/MCC when useful

## Robustness curves

For detector `m`, perturbation family `r`, severity `lambda`, and metric `M`, report:

```text
M_{m,r}(lambda)
```

with mean and dispersion across repetitions. The primary figures should show metric versus severity.

## Scalar robustness summaries

For higher-is-better metrics, the repository computes:

```text
R_avg   = average over severity grid
R_worst = minimum over severity grid
R_prod  = geometric mean over severity grid (with epsilon)
```

For lower-is-better metrics such as FA/h and TTD, the repository reports the raw curves and optional transformed summaries.
