# Project status

## Easy

- Status: **validated**
- Validated source/data release: v0.2.3
- Current regenerated corpus in this repository: 56,844 events
- Current starter questions: 25 / target 180
- Local compatibility tests: 34 historical v0.2.3 tests plus repository-readiness tests in v0.3.0
- Splunk runtime: user confirmed v0.2.3 passed all checks

## Medium

- Status: **authoring**
- Scenario config/time window/site scope exists.
- Static multi-region attack path, 170-question bank, three-hint coverage, and an 8-search reduced detection pack are authored. Runtime Splunk TA/CIM and answer validation are still pending.

## Hard

- Status: **authoring**
- Scenario config/time window/all-site scope exists.
- Static global pre-positioning path, 150-question bank, three-hint coverage, legitimate lookalikes, MFT-abuse exfiltration, and a 5-search sparse detection pack are authored. Runtime Splunk TA/CIM and answer validation are still pending.

Do not change Medium/Hard `status` to `validated` until runtime Splunk TA/CIM checks pass.
