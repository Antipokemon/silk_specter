# Easy Scenario — Splunk Discovery Guide

Easy includes limited search scaffolding so you learn how to explore an unfamiliar Splunk deployment. Medium and Hard assume you already know these techniques.

## Discover indexes and sourcetypes together

```spl
| tstats values(sourcetype) where index=* by index
```

This is often a better starting point than guessing where data lives.

## Discover data for a host

```spl
| tstats count where index=<training_index> host=<host> by sourcetype
| sort - count
```

## Discover hosts and sources

```spl
| tstats count where index=<training_index> by host sourcetype
| sort host sourcetype
```

## Inspect fields only after finding a promising source

```spl
index=<training_index> sourcetype=<sourcetype>
| fieldsummary
```

## Pivot

When you identify an interesting user, IP address, hostname, process, domain, file, or port, search for it in other data sources. One activity can be represented by endpoint, authentication, network, firewall, cloud, and application telemetry.
