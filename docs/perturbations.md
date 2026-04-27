# ETFA 2026 perturbation definitions

This document summarizes the perturbation families used for robustness analysis. Perturbations are injected during telemetry/alarm/controller delivery, before or during ingestion into InfluxDB. They are not applied to already extracted ML features. This ensures that perturbations such as duplicate writes or buffered delivery can affect the database workload and therefore the runtime/syscall behavior of the monitored container.

## General principles

- Apply one perturbation family at a time for the first ETFA benchmark.
- Use severity `lambda` (also denoted `λ`) in `[0, 1]`.
- `λ = 0` means no perturbation.
- `λ = 1` means the strongest configured perturbation.
- For tag-scoped perturbations, severity controls both:
  1. the perturbation strength for affected tags, and
  2. the number/fraction of sensors/tags that are perturbed.
- Perturb upstream streams only: `tep_signals.ndjson`, `tep_alarm_events.ndjson`, and/or `tep_controller_mv_commands.ndjson`.
- Do not perturb `annotations.ndjson`, `attack_records.ndjson`, or `sysdig_logs.ndjson` directly.

## Scope rule for tag-scoped perturbations

For perturbation families that naturally affect only a subset of sensors/tags, use an affected-tag fraction:

```text
f_aff(lambda) = lambda * f_max, with f_max = 0.50
```

Thus, at `lambda = 1.0`, up to 50% of eligible tags are perturbed. Affected tags should be sampled deterministically from the run seed and stored in `scenario.json`. If `lambda > 0` and the stream is non-empty, select at least one eligible tag.

This scope rule applies by default to P1, P2, P3, and P5. P4 is treated as a path-level outage by default.

## P1 — Record loss / missing records

**Goal:** model random telemetry loss, gateway drops, wireless loss, or unreliable delivery.

**Scope:** affected tags selected by `f_aff(lambda)`.

**Mechanism:** for records belonging to affected tags, apply independent Bernoulli dropping.

```text
f_aff(lambda) = lambda * 0.50
p_drop(lambda) = lambda * p_max, with p_max = 0.30
```

Examples:

- `lambda=0.0`: no affected tags and 0% drops,
- `lambda=0.5`: up to 25% of tags affected and 15% drop probability within those tags,
- `lambda=1.0`: up to 50% of tags affected and 30% drop probability within those tags.

## P2 — Duplicate records / spurious repeated writes

**Goal:** model duplicate records caused by retries, reconnect behavior, at-least-once delivery, or duplicate publication by a gateway.

**Scope:** affected tags selected by `f_aff(lambda)`.

**Mechanism:** for records belonging to affected tags, select records with probability `p_dup(lambda)` and emit one additional copy with the same tag/value/unit. Shift duplicate timestamps slightly (`+1 ms` to `+500 ms`) or log duplicate write attempts explicitly to avoid silent overwrites.

```text
f_aff(lambda) = lambda * 0.50
p_dup(lambda) = lambda * d_max, with d_max = 0.20
```

## P3 — Timing disorder / jitter / out-of-order delivery

**Goal:** model timestamp uncertainty, latency jitter, clock noise, and local out-of-order arrival while preserving values and record count.

**Scope:** affected tags selected by `f_aff(lambda)`.

**Mechanism:** for records belonging to affected tags, perturb timestamps:

```text
f_aff(lambda) = lambda * 0.50
J(lambda) = lambda * J_max, with J_max = 30 s
t' = t + epsilon, epsilon ~ Uniform[-J(lambda), +J(lambda)]
```

If possible, preserve both original generation timestamp and perturbed/write timestamp.

## P4 — Buffered delivery / outage and burst flush

**Goal:** model a telemetry gateway or communication path that temporarily holds data and then flushes buffered data after reconnect.

**Scope:** default is global for the selected delivery path. This reflects a gateway/network outage. A tag-scoped variant can be added separately.

**Mechanism:** during an outage interval, generate but do not deliver records. After the outage, release buffered records as a compressed burst.

```text
D_out(lambda) = lambda * D_max, with D_max = 600 s
kappa(lambda) = 1 + lambda * (kappa_max - 1), with kappa_max = 20
D_flush ~= D_out(lambda) / kappa(lambda)
```

For attacked runs, schedule the outage/flush so that it overlaps with or begins immediately before the attack window. For benign controls, sample a synthetic reference time from the same start-delay distribution.

## P5 — Rate degradation / downsampling / throttling

**Goal:** model reduced telemetry rate, gateway throttling, bandwidth limitations, or sensor-side rate degradation.

**Scope:** affected telemetry tags selected by `f_aff(lambda)`.

**Mechanism:** for affected tags, keep only every `q(lambda)`-th record.

```text
f_aff(lambda) = lambda * 0.50
q(lambda) = 1 + floor(9 * lambda)
```

Examples:

- `lambda=0.25`: up to 12.5% of tags affected and `q=3`,
- `lambda=0.5`: up to 25% of tags affected and `q=5`,
- `lambda=1.0`: up to 50% of tags affected and `q=10`.
