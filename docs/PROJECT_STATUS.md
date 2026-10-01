# Project status

## Easy

- Status: **validated**
- Validated source/data release: v0.2.3
- Current regenerated corpus in this repository: 56,844 events
- Current starter questions: 25 / target 180
- Local compatibility tests: 34 historical v0.2.3 tests plus repository-readiness tests in v0.3.0
- Splunk runtime: user confirmed v0.2.3 passed all checks

## Medium

- Status: **authoring** (runtime validation pending)
- Distinct multi-region campaign is implemented across UKLO, DEFR, NLAM, and AUSY.
- Current campaign includes valid-account VPN access, native-tool credential access, cross-region WMI, GitLab/AWS collection, SMB collection, deliberate archive staging, HTTPS exfiltration, cleanup, and benign administrative/transfer lookalikes.
- Validation builds can be generated with `--allow-authoring` and loaded with `ALLOW_AUTHORING=1` without falsely changing the scenario to validated.
- The 170-question bank remains intentionally empty until the generated telemetry passes Splunk TA/CIM runtime checks.

## Hard

- Status: **authoring**
- Scenario config/time window/all-site scope exists.
- Distinct global pre-positioning path, MFT-abuse exfiltration, detection pack, generated corpus, and 150-question bank are not yet authored/validated.

Do not change Medium/Hard `status` to `validated` until runtime Splunk TA/CIM checks pass.
