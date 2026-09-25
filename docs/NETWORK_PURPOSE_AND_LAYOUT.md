# Asteron Utilities Group, Inc. — Network Purpose and Layout

## Mission and environment purpose

Asteron Utilities Group, Inc. is a fictional multinational critical-infrastructure holding company operating water, power/grid, engineering, infrastructure-operations, digital-service, and regional utility subsidiaries. The environment exists to support defensive Splunk investigation training. It intentionally combines corporate IT, engineering, cloud services, physical access, and OT-adjacent management without requiring participants to operate industrial control processes.

All scenario timestamps are generated in UTC. User and operator activity is modeled against each site’s IANA time zone so the global enterprise does not behave like a single 8-hour workday.

## Global site inventory

| Code | Location | Country | Time zone | Aggregate | Purpose | Size |
|---|---|---|---|---|---|---|
| `USHQ` | Virginia | US | `America/New_York` | `10.44.0.0/16` | Global headquarters | large |
| `USNO` | Texas | US | `America/Chicago` | `10.45.0.0/16` | NOC/SOC and infrastructure operations | large |
| `USCP` | Colorado | US | `America/Denver` | `10.46.0.0/16` | COOP alternate operations | large |
| `USVA` | Virginia | US | `America/New_York` | `10.47.0.0/16` | Water operations | large |
| `USTX` | Texas | US | `America/Chicago` | `10.48.0.0/16` | Water operations | large |
| `USOH` | Ohio | US | `America/New_York` | `10.49.0.0/16` | Power operations | large |
| `USCA` | California | US | `America/Los_Angeles` | `10.50.0.0/16` | Power operations | large |
| `CATO` | Toronto | CA | `America/Toronto` | `10.51.0.0/16` | Canadian operations | small |
| `UKLO` | London | UK | `Europe/London` | `10.52.0.0/16` | UK regional operations | large |
| `IEDU` | Dublin | IE | `Europe/Dublin` | `10.53.0.0/16` | European service operations | small |
| `DEFR` | Frankfurt | DE | `Europe/Berlin` | `10.54.0.0/16` | EU engineering | large |
| `NLAM` | Amsterdam | NL | `Europe/Amsterdam` | `10.55.0.0/16` | EU infrastructure/services | large |
| `PLWA` | Warsaw | PL | `Europe/Warsaw` | `10.56.0.0/16` | Eastern European operations | small |
| `AUSY` | Sydney | AU | `Australia/Sydney` | `10.57.0.0/16` | Australia regional operations | large |
| `AUME` | Melbourne | AU | `Australia/Melbourne` | `10.58.0.0/16` | Engineering/power | large |
| `AUPE` | Perth | AU | `Australia/Perth` | `10.59.0.0/16` | Western Australia operations | small |
| `SGSI` | Singapore | SG | `Asia/Singapore` | `10.60.0.0/16` | APAC services | large |
| `JPTY` | Tokyo | JP | `Asia/Tokyo` | `10.61.0.0/16` | APAC engineering | large |
| `NZAK` | Auckland | NZ | `Pacific/Auckland` | `10.62.0.0/16` | New Zealand operations | small |
| `BRSP` | São Paulo | BR | `America/Sao_Paulo` | `10.63.0.0/16` | LATAM operations | large |

## Standard location segmentation

Each site receives a routed `/16` aggregate. Functional networks normally use the same third-octet convention, but a scenario may introduce documented legacy exceptions at Medium/Hard difficulty. A site only instantiates networks it needs.

| Third octet | Function | Typical systems |
|---:|---|---|
| 2 | Network management | routers, switches, firewalls, AAA management |
| 5 | Remote access | VPN termination and remote-access services |
| 6 | Security sensors | Zeek/Corelight-style sensors and monitoring |
| 10 | Identity/core | AD/DC, DNS, PKI/CAC-related services |
| 15 | DMZ | public web, reverse proxy, externally reachable services |
| 20 | Shared servers | file, print, update, shared infrastructure |
| 30 | Applications/databases | line-of-business apps, VDI, data services |
| 40–47 | User endpoints | workstations and laptops |
| 50 | Privileged management | PAWs, jump hosts, admin services |
| 60 | Engineering | engineering workstations/applications |
| 70 | Backup/recovery | backup, recovery, COOP replication |
| 80 | OT management | systems used to manage operational environments |
| 81 | ICS/SCADA | selected control/management infrastructure |
| 82 | Remote telemetry | field/remote telemetry systems |
| 90 | Vendor/contractor | controlled third-party access |
| 95 | Physical security | badge/PACS controllers and management |

## Connectivity model

- Site connectivity is primarily Internet-based encrypted IPsec VPN, reflecting a cost-conscious high-assurance transport model rather than a private WAN dependency.
- Major sites maintain primary/backup regional termination and selected direct site-to-site tunnels for critical dependencies.
- OSPF may be used internally; BGP is represented where appropriate at routed/WAN/cloud edges.
- Zeek visibility is modeled on trusted sides of VPN/security boundaries so analysts can follow internal flows even though the Internet transport is encrypted.
- TLS is selectively break-and-inspect. Some flows expose application-level metadata/content at approved gateways; other flows remain encrypted and provide connection/TLS/certificate metadata only.
- On-prem DNS is preferred for internal systems; cloud workloads use cloud DNS except when resolving internal Asteron resources.

## Defense in depth

Large sites use three distinct firewall/security vendor layers; smaller sites use two. A single site should not depend on one firewall vendor for every security boundary. The authoritative device allocation is `config/network_devices.json`. Current families include Palo Alto, Fortinet, Cisco Secure Firewall/ASA-style telemetry, and Juniper SRX/Junos.

## Identity and administration

Forest: `ASTERON.LOCAL` with regional child domains `US.ASTERON.LOCAL`, `EU.ASTERON.LOCAL`, `AU.ASTERON.LOCAL`, `APAC.ASTERON.LOCAL`, and `LATAM.ASTERON.LOCAL`. Some smaller sites use RODCs. Normal users use username/password. Privileged administration and special-service access use CAC/certificate-backed authentication where appropriate. PAWs and jump hosts are expected administrative origins. Network-device AAA intentionally includes both TACACS+ and RADIUS because regions and equipment generations differ.

## Enterprise services

Asteron includes Active Directory, DNS, DHCP, PKI/CAC, Tenable, VDI, ServiceNow, secure file transfer, print, SCCM/MECM, WSUS, Ivanti, self-managed GitLab, Atlassian, Microsoft Defender, Trellix, backup, monitoring, vulnerability management, physical access control, and AWS-hosted service platforms. AWS ownership is service-oriented (for example GitLab, web, AI/analytics, data, observability, artifacts, engineering data) with Dev/Test/Prod lifecycle accounts beneath the service where appropriate.

## Participant-facing expectation

The participant should receive organization purpose, topology, naming conventions, and a scenario starting point—not the actor path, ground truth, ATT&CK mapping, answer key, or detection disposition. Easy includes a Splunk discovery guide; Medium and Hard progressively remove that scaffolding.
