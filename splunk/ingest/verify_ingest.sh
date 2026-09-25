#!/usr/bin/env bash
set -euo pipefail
INDEX="${1:-asteron_easy_v020}"

cat <<EOF2
Run these searches in Splunk after ingestion completes:

1) Total events (expected 50,111 for v0.2.0):
   | tstats count where index=$INDEX

2) Event dates (all should be 2026-04-06 through 2026-04-10 UTC):
   index=$INDEX earliest=0
   | eval event_date=strftime(_time,"%Y-%m-%d")
   | stats count by event_date
   | sort event_date

3) Sourcetype reconciliation:
   | tstats count where index=$INDEX by sourcetype
   | sort - count

4) Detect any index-time timestamp fallback:
   index=$INDEX earliest=0
   | where _time < strptime("2026-04-06T00:00:00Z","%Y-%m-%dT%H:%M:%SZ")
       OR _time > strptime("2026-04-10T23:59:59Z","%Y-%m-%dT%H:%M:%SZ")
   | stats count by sourcetype source

5) Corelight connection extraction:
   index=$INDEX sourcetype=bro:conn:json
   | head 20
   | table _time uid src_ip src_port dest_ip dest_port transport action bytes_in bytes_out

6) Network Traffic data model visibility:
   | tstats summariesonly=f count
       from datamodel=Network_Traffic.All_Traffic
       where index=$INDEX
       by All_Traffic.sourcetype
EOF2
