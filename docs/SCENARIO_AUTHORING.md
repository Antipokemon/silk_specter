# Scenario and APT authoring

## Shared environment

All difficulties use the same Asteron Utilities Group, Inc. canonical environment, site codes, subnet conventions, identity hierarchy, enterprise services, and vendor-diverse defense-in-depth model. Each difficulty uses a separate Splunk index and a distinct attack path/detection pack so findings cannot bleed between tiers.

## Difficulty contract

### Easy

- U.S. scope across several locations.
- Windows, Linux, cloud, identity, endpoint, firewall, Corelight/Zeek, physical-access evidence.
- Multiple firewall vendors even within a location.
- External recon can include identifiable Internet scanners plus separate cloud-hosted malicious infrastructure.
- Simple data discovery and staging, obvious exfil, useful but non-oracle findings.
- Teaches source discovery and pivots.

### Medium

- Expand into multiple regions/countries and additional vendor/identity paths.
- More legitimate admin lookalikes and NAT/VPN complexity.
- Collection must include deliberate staging/archives and cleanup.
- Notables reveal only pieces of the campaign; some actor activity has no finding.
- Questions require two to four or more sources and longer time pivots.

### Hard

- Global environment and heterogeneous control planes.
- Sparse detections, substantial benign overlap, partial visibility.
- Legitimate secure-transfer/MFT path abuse is preferred for exfiltration.
- Actor may use valid credentials, native tools, intermediate systems, network-device access, and OT-adjacent pre-positioning.
- Questions should test proof and reconstruction, not IOC lookup.

## Time model

Each scenario config defines `start` and `end` UTC timestamps. Scenario code uses `ScenarioContext.at(day,hour,minute,second)` so payload timestamps and Splunk `_time` move together when a window is shifted. User/background behavior uses site IANA time zones and is constrained back into the declared UTC window.

Use:

```bash
python3 generator/generate.py --scenario easy \
  --start 2026-05-04T00:00:00Z \
  --end 2026-05-08T23:59:59Z \
  --output /tmp/asteron-easy-shifted
```

A scenario window must be long enough for its authored relative timeline. The generator hard-fails if any event escapes the configured bounds.

## Network correlation rule

Create one semantic connection and render all observations from the same tuple/session facts. `generator/core/network.py` provides `NetworkFlow` and `NetworkLedger` for new scenario modules. Major attack transitions should have a defensible network observation unless the protocol/location truly prevents it.

Typical correlation chain:

endpoint process -> endpoint network -> Corelight/Zeek -> firewall/NAT -> remote auth -> remote process/file

## Adding another APT

1. Add `config/actors/<actor>.json` with fictional exercise identity, public-source inspiration, behavior library, and provenance note.
2. Reuse the Asteron environment unless the exercise explicitly needs a new organization.
3. Add scenario configs with independent seeds/indexes/windows/status.
4. Build semantic actor actions first, then source-native observations.
5. Add benign lookalikes for the same techniques.
6. Add detections/findings with instructor-only expected dispositions.
7. Author questions only after evidence exists.
8. Run local tests, load a fresh Splunk index, validate installed TAs/CIM, then mark the scenario `validated`.
