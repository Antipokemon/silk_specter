# SILK SPECTER  — Asteron CTF framework

A synthetic Splunk investigation environment for defensive-cyber training.
Participants investigate a realistic intrusion across a fictional multinational
critical-infrastructure enterprise — **Asteron Utilities Group, Inc.** — using
only Splunk search skills, data discovery, and cross-source correlation.

The scenario follows **SILK SPECTER**, a threat actor whose tradecraft is
inspired by publicly documented Volt Typhoon (G1017) behavior.  All evidence is
inert, synthetic telemetry; no malware, live exploits, or operational tooling
is included.

---

## How it works

The generator (`generator/generate.py`) produces source-native log lines that
match the installed Splunk technology add-ons (Windows Event Log, Sysmon,
Zeek/Corelight, Cisco ASA, Palo Alto, FortiGate, Juniper, AWS CloudTrail,
Microsoft Defender, Tenable, etc.).  The same generator adds enterprise
background noise so learners discover threat signals rather than being handed
sourcetypes.

Configuration drives everything — site topology, domain model, network
placement, service map, actor profile, and scenario scope/timing — so the
same platform can serve multiple actors and difficulty tiers.

Three difficulty tiers (Easy, Medium, Hard) share the environment model but
differ in attack scope, detection coverage, and investigative complexity.
Each tier ships to its own Splunk index.

## Scenario status

`make status` shows which scenarios are ready:

| Scenario | Status  | Questions |
|----------|---------|-----------|
| Easy     | Validated | 25 / 180  |
| Medium   | Authoring | — / 170   |
| Hard     | Authoring | — / 150   |

Only **Easy** is Splunk-validated and generation-ready. The generator refuses
to emit Medium or Hard data until their telemetry and question banks complete
full laboratory validation.

## Quick start

```bash
# 1. Run local tests
make validate

# 2. Generate the Easy corpus
make generate-easy

# 3. Load into a local Splunk lab (Podman-based)
make splunk-load
```

Custom time windows are supported:

```bash
python3 generator/generate.py \
  --scenario easy \
  --start 2026-05-04T00:00:00Z \
  --end 2026-05-08T23:59:59Z \
  --output /tmp/easy-shifted
```

Shifted windows move both raw log timestamps and HEC `_time` together.

## Repository layout

```
config/               Environment topology, actors, scenario config
generator/            Event generators and source-native renderers
splunk/               Index configs, ingest scripts, detection searches, TA helper
question_bank/        Questions, answers, and hints per scenario
instructor/           Ground-truth evidence, reference SPL, answer keys
participant/          Participant-facing briefs, environment docs, exports
docs/                 Architecture, authoring guide, load workflow, network map
tests/                Local validation test suite
scripts/              Load, status, and release-packaging helpers
```

Generated data (`dataset/<scenario>/`) is reproducible and excluded from Git
by default.  Release packages include it for immediate Splunk loading.

## Key make targets

| Target            | Command                                      |
|-------------------|----------------------------------------------|
| `validate`        | Run local test suite (`python3 -m unittest`)  |
| `generate-easy`   | Generate Easy corpus with default noise levels |
| `splunk-load`     | Load generated data into a Podman Splunk lab   |
| `status`          | Print scenario status for all tiers            |

## Key documents

| File                                                    | Covers                                    |
|---------------------------------------------------------|-------------------------------------------|
| `AGENTS.md`                                             | Engineering contract and non-regression rules |
| `docs/TA_COMPATIBILITY.md`                              | Source/sourcetype/payload compatibility     |
| `docs/SPLUNK_LOAD.md`                                   | Splunk ingest workflow and lab setup        |
| `docs/SCENARIO_AUTHORING.md`                            | Difficulty tiers and new-actor authoring    |
| `docs/QUESTION_BANK.md`                                 | Question architecture and hint philosophy   |
| `docs/NETWORK_PURPOSE_AND_LAYOUT.md`                    | Enterprise topology and site segmentation   |
| `VALIDATION.md`                                         | Validated corpus details and test coverage  |

Read `AGENTS.md` before modifying generators, renderers, or scenario
configuration — it preserves hard-won TA-compatibility contracts.

## Safety boundary

All infrastructure, identities, and attack evidence are synthetic.  The
project represents defensive telemetry and investigation practice; it must
not ship live exploit payloads, malware, operational credential theft, or
real exfiltration tooling.
