# v0.3.0 — repository-ready / reproducibility baseline

This release does **not** claim Medium/Hard runtime validation. It hardens the validated Easy generator into a reusable project framework.

## Added

- `AGENTS.md` non-regression/authoring contract.
- Git-ready `.gitignore`, `Makefile`, `VERSION`, status/release scripts.
- Scenario registry for Easy/Medium/Hard with explicit validation status, index, UTC window, scope, seed, and question targets.
- SILK SPECTER actor profile and reusable new-scenario/APT extension points.
- `ScenarioContext` relative UTC timing and CLI `--scenario`, `--start`, `--end` support.
- Time-window refactor for Easy campaign/background: raw vendor timestamps and HEC `_time` move together.
- Scenario-scoped ground-truth output to prevent future Medium/Hard overwrites.
- Semantic `NetworkFlow` / `NetworkLedger` helper for future correlated network observations.
- Question-bank directories for all three tiers; Easy contains the validated starter pool and Medium/Hard are authoring-gated schemas.
- Full network-purpose/layout, TA-compatibility, Splunk-load, scenario-authoring, and question-bank docs.
- Host-side `scripts/load_to_splunk.sh`, including interactive `splunk login` and fresh-index guard.
- Repository-readiness tests.

## Preserved

All v0.2.3 TA/data-generation fixes and the validated 56,844-event Easy corpus remain intact.
