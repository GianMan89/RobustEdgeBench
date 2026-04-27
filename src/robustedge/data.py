"""Dataset indexing and per-run loading."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from .constants import OPTIONAL_FILES, PROFILE_TO_SEVERITY
from .io import discover_run_dirs, parse_scenario_name, read_json, read_ndjson


@dataclass
class Scenario:
    """Normalized run-level metadata."""

    perturbation: str = "unknown"
    perturbation_family: str = "unknown"
    perturbation_profile: str = "unknown"
    severity: float | None = None
    attack_duration: float = 0.0
    attack_intensity: str = "unknown"
    iteration: int | None = None
    test_duration: float | None = None
    attack_start_delay: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_sources(
        cls,
        scenario_json: dict[str, Any],
        path_fields: dict[str, Any] | None = None,
        profile_to_severity: dict[str, float] | None = None,
    ) -> "Scenario":
        """Build normalized metadata from JSON and path-derived fields."""
        profile_to_severity = profile_to_severity or PROFILE_TO_SEVERITY
        merged: dict[str, Any] = {}
        if path_fields:
            merged.update(path_fields)
        merged.update(scenario_json or {})

        perturbation = str(merged.get("perturbation", merged.get("perturbation_profile", "unknown")))
        perturbation_profile = str(merged.get("perturbation_profile", perturbation))
        perturbation_family = str(merged.get("perturbation_family", perturbation))

        severity_raw = merged.get("severity", merged.get("lambda", None))
        if severity_raw is None:
            severity = profile_to_severity.get(perturbation_profile, profile_to_severity.get(perturbation, None))
        else:
            severity = float(severity_raw)

        return cls(
            perturbation=perturbation,
            perturbation_family=perturbation_family,
            perturbation_profile=perturbation_profile,
            severity=severity,
            attack_duration=float(merged.get("attack_duration", merged.get("attackDuration", 0.0)) or 0.0),
            attack_intensity=str(merged.get("attack_intensity", merged.get("intensity", "unknown"))),
            iteration=_safe_int(merged.get("iteration")),
            test_duration=_safe_float(merged.get("test_duration")),
            attack_start_delay=_safe_float(merged.get("attack_start_delay")),
            raw=merged,
        )

    @property
    def has_attack(self) -> bool:
        return self.attack_duration > 0

    @property
    def attack_interval(self) -> tuple[float, float] | None:
        if not self.has_attack or self.attack_start_delay is None:
            return None
        return (float(self.attack_start_delay), float(self.attack_start_delay + self.attack_duration))


def _safe_int(x: Any) -> int | None:
    if x is None:
        return None
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _safe_float(x: Any) -> float | None:
    if x is None:
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


@dataclass
class RunData:
    """All data available for a single run/iteration folder."""

    run_id: str
    run_dir: Path
    scenario: Scenario
    config: dict[str, Any]
    sysdig: pd.DataFrame
    annotations: pd.DataFrame
    attack_records: pd.DataFrame
    signals: pd.DataFrame
    alarm_events: pd.DataFrame
    mv_commands: pd.DataFrame

    @classmethod
    def load(cls, run_dir: str | Path, profile_to_severity: dict[str, float] | None = None) -> "RunData":
        run_dir = Path(run_dir)
        scenario_json = read_json(run_dir / "scenario.json")
        path_fields = parse_scenario_name(run_dir)
        scenario = Scenario.from_sources(scenario_json, path_fields, profile_to_severity=profile_to_severity)
        run_id = make_run_id(run_dir, scenario)
        return cls(
            run_id=run_id,
            run_dir=run_dir,
            scenario=scenario,
            config=read_json(run_dir / "config.json"),
            sysdig=read_ndjson(run_dir / "sysdig_logs.ndjson"),
            annotations=read_ndjson(run_dir / "annotations.ndjson"),
            attack_records=read_ndjson(run_dir / "attack_records.ndjson"),
            signals=read_ndjson(run_dir / "tep_signals.ndjson"),
            alarm_events=read_ndjson(run_dir / "tep_alarm_events.ndjson"),
            mv_commands=read_ndjson(run_dir / "tep_controller_mv_commands.ndjson"),
        )

    def missing_optional_files(self) -> list[str]:
        return [fname for fname in OPTIONAL_FILES if not (self.run_dir / fname).exists()]


def make_run_id(run_dir: Path, scenario: Scenario) -> str:
    """Create a stable run identifier from folder names and iteration."""
    scenario_name = run_dir.parent.name if run_dir.name.startswith("iteration") else run_dir.name
    iteration = run_dir.name if run_dir.name.startswith("iteration") else f"iteration-{scenario.iteration or 0}"
    return f"{scenario_name}__{iteration}"


@dataclass
class DatasetIndex:
    """Index of all discovered runs."""

    data_root: Path
    run_dirs: list[Path]
    profile_to_severity: dict[str, float] = field(default_factory=lambda: PROFILE_TO_SEVERITY.copy())

    @classmethod
    def from_root(
        cls,
        data_root: str | Path,
        profile_to_severity: dict[str, float] | None = None,
    ) -> "DatasetIndex":
        data_root = Path(data_root)
        return cls(
            data_root=data_root,
            run_dirs=discover_run_dirs(data_root),
            profile_to_severity=profile_to_severity or PROFILE_TO_SEVERITY.copy(),
        )

    def load_runs(self) -> list[RunData]:
        return [RunData.load(p, profile_to_severity=self.profile_to_severity) for p in self.run_dirs]

    def to_frame(self) -> pd.DataFrame:
        rows: list[dict[str, Any]] = []
        for run_dir in self.run_dirs:
            rd = RunData.load(run_dir, profile_to_severity=self.profile_to_severity)
            rows.append({
                "run_id": rd.run_id,
                "run_dir": str(rd.run_dir),
                "scenario_dir": rd.run_dir.parent.name if rd.run_dir.name.startswith("iteration") else rd.run_dir.name,
                "iteration": rd.scenario.iteration,
                "perturbation": rd.scenario.perturbation,
                "perturbation_family": rd.scenario.perturbation_family,
                "perturbation_profile": rd.scenario.perturbation_profile,
                "severity": rd.scenario.severity,
                "attack_duration": rd.scenario.attack_duration,
                "attack_intensity": rd.scenario.attack_intensity,
                "attack_start_delay": rd.scenario.attack_start_delay,
                "test_duration": rd.scenario.test_duration,
                "n_sysdig_rows": len(rd.sysdig),
                "n_annotation_rows": len(rd.annotations),
                "missing_optional_files": ",".join(rd.missing_optional_files()),
            })
        return pd.DataFrame(rows)
