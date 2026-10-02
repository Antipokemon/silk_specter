# Hard Scenario Ground Truth — Instructor Only

This file must not be distributed to participants.

## Normalized static corpus

- Static events: **1500**
- Malicious campaign/corroboration: **450**
- Fixed benign lookalikes: **1050**
- Sourcetypes represented: **31**
- Signal ratio: **30.0% malicious / 70.0% fixed lookalike**
- Original canonical answer-bearing spine preserved: **75 events**

## Campaign spine

1. `103.27.186.44` uses a valid SGSI vendor/service identity without matching approved change context.
2. `SGSI-NET-JMP-02` performs low-and-slow discovery and credential discovery, then creates a covert `netsh interface portproxy` path.
3. The actor reaches `JPTY-HIST-MGMT-01` over WinRM and conducts OT-adjacent pre-positioning without direct ICS/SCADA manipulation.
4. Engineering support files are collected from `JPTY-ENG-FS-01` and staged with native PowerShell.
5. The artifact is moved to `NZAK-MFT-GW-02`, restaged with Linux tooling, and uploaded to the legitimate `mft.apac-grid-services.example` service without a matching approved change.
6. Cleanup removes the proxy and staged artifacts.

## Difficulty model

Hard deliberately contains more fixed benign/admin lookalikes than malicious observations. Approved changes, vendor VPNs, portproxy maintenance, WinRM, OT maintenance, MFT, Linux backup, cloud/CI, patching, physical access, and endpoint-management activity overlap with attacker behavior. Authorization context and lineage are required.

Use `hard_evidence_matrix.csv` for activity-level truth and `hard_tactic_summary.csv` for malicious phase counts.
