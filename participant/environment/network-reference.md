# Asteron Network Reference

Asteron separates networks by **location and function**. Each major site receives a routed site aggregate, and functional networks exist inside the site where needed.

## Functional network pattern

| Third octet | Function |
|---|---|
| `.2` | Network infrastructure |
| `.5` | Remote access |
| `.6` | Security sensors |
| `.10` | Identity/core services |
| `.15` | DMZ |
| `.20` | Shared servers |
| `.30` | Applications/databases |
| `.40-.47` | User endpoints |
| `.50` | Privileged management |
| `.60` | Engineering |
| `.70` | Backup/recovery |
| `.80` | OT management |
| `.81` | ICS/SCADA |
| `.82` | Remote telemetry |
| `.90` | Vendor/contractor |
| `.95` | Physical security/badging |

Not every site contains every network.

## Site connectivity

Asteron primarily uses Internet-based encrypted site-to-site VPNs. Regional hubs provide common connectivity, while selected critical dependencies maintain direct tunnels. Traffic is observable on trusted-side sensors before encryption or after decryption at the tunnel boundary.

## Security layers

Large sites use three firewall/security layers from multiple vendors; smaller sites use two. Asteron intentionally avoids relying on one firewall vendor for every boundary.

## Easy-tier U.S. site aggregates

| Site | Aggregate | Purpose |
|---|---|---|
| USHQ | `10.44.0.0/16` | Headquarters |
| USNO | `10.45.0.0/16` | NOC/SOC |
| USCP | `10.46.0.0/16` | COOP |
| USVA | `10.47.0.0/16` | Water operations |
| USTX | `10.48.0.0/16` | Water operations |
| USOH | `10.49.0.0/16` | Power operations |
| USCA | `10.50.0.0/16` | Power operations |

Asteron's full enterprise contains additional international sites.
