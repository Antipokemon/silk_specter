# Medium Scenario Ground Truth — Instructor Only

This file must not be distributed to participants.

## Normalized static corpus

- Static events: **1250**
- Malicious campaign/corroboration: **650**
- Fixed benign lookalikes: **600**
- Sourcetypes represented: **24**
- Signal ratio: **52.0% malicious / 48.0% fixed lookalike**
- Original canonical answer-bearing spine preserved: **65 events**

## Campaign spine

1. `18.170.44.73` authenticates through UKLO VPN as `EU\svc-fieldops` after three failures, reaching `UKLO-JMP-01`.
2. The jump host performs native Windows discovery and accesses LSASS with `rundll32.exe` + `comsvcs.dll`.
3. WMI/DCOM pivots from UKLO to `DEFR-ENG-APP-03` using `svc-engbuild`.
4. The DE host accesses GitLab and the `EngineeringDataReadOnly` AWS role, then reads engineering files from `DEFR-FS-02`.
5. Data is staged with 7-Zip, activity reappears in AUSY, and the collection is restaged on `NLAM-OPS-LNX-04`.
6. The final staged archive is sent over HTTPS to `34.240.118.91` / `objects-eu-west.examplecdn.net`, followed by cleanup.

## Difficulty model

Medium mixes substantial fixed legitimate lookalikes with stronger cross-source corroboration than Hard. VPN administration, SCCM/WMI, GitLab CI, AWS automation, SMB backup, archive jobs, MFT transfers, and Linux maintenance can resemble parts of the intrusion.

Use `medium_evidence_matrix.csv` for activity-level truth and `medium_tactic_summary.csv` for malicious phase counts.
