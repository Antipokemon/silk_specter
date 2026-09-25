# Asteron Utilities Group, Inc.

Asteron Utilities Group, Inc. is a fictional multinational critical-infrastructure company providing electric distribution, drinking-water treatment/distribution, wastewater services, and supporting engineering operations.

Asteron operates traditional corporate IT, geographically distributed operating facilities, on-premises Windows identity and services, Linux infrastructure, AWS-hosted business services, engineering environments, OT-adjacent management systems, and centralized security monitoring.

## Identity

The forest root is `ASTERON.LOCAL`, with regional child domains including `US.ASTERON.LOCAL`, `EU.ASTERON.LOCAL`, `AU.ASTERON.LOCAL`, `APAC.ASTERON.LOCAL`, and `LATAM.ASTERON.LOCAL`. Normal users generally authenticate with username/password. Privileged and selected special-service access uses CAC/certificate-backed authentication.

## Host naming

Hosts generally use `<SITE>-<ROLE>-<NUMBER>`, for example `USHQ-APP-07`, `USVA-ENG-APP-01`, or `DEFR-APP-03`. Site codes identify geography; role codes identify technical function.

## Investigation principle

The presence of PowerShell, WMI, RDP, SMB, SSH, administrative accounts, scanning, or other management behavior is not by itself proof of malicious activity. Asteron has legitimate administrative, vulnerability-management, patching, monitoring, and engineering activity. Context and correlation matter.
