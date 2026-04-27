# Public data release guidance

Recommended public release structure:

1. GitHub repository for code and documentation.
2. Dataset archive via GitHub Releases, Zenodo, OSF, or an institutional repository.
3. A manifest CSV with one row per run.
4. Checksums for all dataset archives.
5. A tagged code release matching the paper submission/camera-ready version.

Do not commit large raw logs directly to Git unless Git LFS is explicitly configured.

Recommended manifest columns:

- `run_id`
- `scenario_dir`
- `iteration`
- `perturbation_family`
- `perturbation_profile`
- `severity`
- `attack_duration`
- `attack_intensity`
- `attack_start_delay`
- `test_duration`
- `sysdig_window_seconds`
- `random_seed`
- `has_sysdig`
- `has_annotations`
- `has_attack_records`
