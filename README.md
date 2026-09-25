# SILK SPECTER v3 / Asteron CTF framework — v0.3.0

Repository-ready source of truth for the Asteron Utilities Group, Inc. synthetic Splunk investigation/CTF environment.

## What is validated now

The **Easy** SILK SPECTER scenario is the current validated baseline. It regenerates the v0.2.3-compatible corpus:

- 56,844 events
- 36 sourcetypes
- 750 hosts/devices/services
- 1,096 malicious/campaign observations
- default UTC window April 6–10, 2026
- 25 validated starter questions, target 180

The user confirmed v0.2.3 passed the target Splunk TA/CIM validation checks. v0.3.0 preserves those generator contracts while adding repository/scenario/time-window infrastructure.

**Medium and Hard are intentionally marked `authoring`.** Their environment scope/config/question schemas exist, but their distinct campaign paths and 170/150-question pools have not yet completed Splunk validation. The generator refuses to ship them until that gate is cleared.

## Start here

1. Read [`AGENTS.md`](AGENTS.md) before changing generated data.
2. Review [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md).
3. Review [`docs/NETWORK_PURPOSE_AND_LAYOUT.md`](docs/NETWORK_PURPOSE_AND_LAYOUT.md).
4. Run validation:

```bash
python3 -m unittest discover -s tests -v
```

5. Regenerate Easy:

```bash
python3 generator/generate.py \
  --scenario easy \
  --output dataset/easy \
  --background-events 5000 \
  --enterprise-background-events 45000
```

6. Load to the rootless Podman Splunk lab:

```bash
./scripts/load_to_splunk.sh easy asteron_easy_v030
```

The load workflow includes an interactive `splunk login` step. Full manual commands are in [`docs/SPLUNK_LOAD.md`](docs/SPLUNK_LOAD.md).

## Scenario windows

Each scenario owns a UTC start/end range in `config/scenarios/`. Easy event placement is relative to that window rather than hard-coded to April dates. Example shifted test build:

```bash
python3 generator/generate.py \
  --scenario easy \
  --start 2026-05-04T00:00:00Z \
  --end 2026-05-08T23:59:59Z \
  --output /tmp/easy-shifted
```

Raw payload timestamps and Splunk HEC `_time` shift together.

## Git model

The repo is intended to be committed directly:

```bash
git init
git add .
git commit -m "baseline: validated Asteron Easy generator and CTF framework"
```

Large reproducible `dataset/*/raw` and `dataset/*/hec` outputs are ignored by default while generator/config/test/question/documentation source remains versioned. Release packages can still include generated Easy data for immediate Splunk loading.

## Important documents

- `AGENTS.md` — engineering handoff and non-regression contract
- `docs/TA_COMPATIBILITY.md` — validated source/sourcetype/payload contracts
- `docs/SPLUNK_LOAD.md` — full Podman/Splunk ingest workflow
- `docs/SCENARIO_AUTHORING.md` — Easy/Medium/Hard and new-APT authoring rules
- `docs/QUESTION_BANK.md` — 500-question architecture/hint rules
- `docs/NETWORK_PURPOSE_AND_LAYOUT.md` — enterprise purpose/topology/site segmentation
- `VALIDATION.md` — validated Easy corpus details

## Safety/realism boundary

All infrastructure, victim identities, and attack evidence are synthetic. The project represents defensive telemetry and investigation evidence; it must not ship live exploit payloads, malware, operational credential theft, or real exfiltration tooling.
