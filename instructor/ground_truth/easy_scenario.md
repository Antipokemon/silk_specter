# Easy Scenario Ground Truth — Instructor Only

This file must not be distributed to participants.

1. `199.45.154.125` performs benign Censys Internet measurement scanning against the Asteron public portal.
2. A later connection from `23.20.77.81` (AWS-owned public range; malicious attribution is fictional) is associated with exploitation evidence against the portal.
3. `USHQ-WEB-02` is the first compromised host. Linux Sysmon and auditd show the web application spawning `/bin/sh` and conducting host/network discovery.
4. Existing deployment context leads to `git.asteron.example`; `svc-webdeploy` accesses GitLab and a limited AWS deployment role performs enumeration.
5. `svc-appdeploy` authenticates from the compromised DMZ path to `USHQ-APP-07`; WMI-backed command execution and Windows discovery follow.
6. `svc-engsync` is used across a direct critical-dependency VPN path to `USVA-ENG-APP-01`.
7. Engineering data is accessed from `USVA-FS-01`.
8. Easy uses a straightforward staging phase: selected engineering files are copied into `C:\ProgramData\Asteron\EngineeringSync\outbound\` before `engsync.exe` performs a large outbound TLS transfer to `sync-update.example` / `50.19.77.200`.
9. Medium and Hard must use independent campaign paths and detection packs. Easy detections are scoped only to `index=asteron_easy`.
