# Load Asteron data into Splunk with rootless Podman

Validated lab assumptions:

- Splunk container name: `splunk`
- administrative Splunk CLI is executed as the container OS user `splunk`
- project is on the host; data is copied into `/tmp` and removed after validation if desired
- vendor TAs are installed separately and are **not** modified by this project
- `splunk/app/TA-asteron-v3` only provides the HEC-envelope file parser used by the canonical dataset loader

## 1. Work from the repository root

```bash
cd ~/silk-specter-v3-v0.3.0
```

## 2. Validate the package before loading

```bash
python3 -m unittest discover -s tests -v
```

For the validated Easy snapshot, the canonical event count is recorded in:

```text
dataset/easy/manifest.json
```

## 3. Install/update the Asteron ingest helper

```bash
podman cp \
  splunk/app/TA-asteron-v3 \
  splunk:/opt/splunk/etc/apps/TA-asteron-v3

podman restart splunk
```

Verify the parser after Splunk is running:

```bash
podman exec --user splunk splunk \
  /opt/splunk/bin/splunk btool props list asteron:hec --debug
```

Expected setting:

```text
INDEXED_EXTRACTIONS = HEC
```

## 4. Login to the Splunk CLI

This step is required. Do not put the password on the command line.

```bash
podman exec -it --user splunk splunk \
  /opt/splunk/bin/splunk login
```

Enter the Splunk application credentials interactively.

## 5. Create a fresh index

Never reload a corrected generator build into an old validation index. Already indexed events retain their previous `_raw` and metadata.

Example:

```bash
podman exec --user splunk splunk \
  /opt/splunk/bin/splunk add index asteron_easy_v030
```

## 6. Copy the generated dataset and loader

```bash
podman exec --user 0 splunk \
  rm -rf /tmp/silk-specter-v3-easy

podman cp \
  dataset/easy \
  splunk:/tmp/silk-specter-v3-easy

podman cp \
  splunk/ingest/load_hec.sh \
  splunk:/tmp/silk-specter-v3-easy/load_hec.sh
```

The loader writes any temporary remap file under `/tmp`, not inside the copied dataset directory, so it does not depend on the copied directory being owned by the `splunk` OS user.

## 7. Load the dataset

```bash
podman exec --user splunk splunk bash \
  /tmp/silk-specter-v3-easy/load_hec.sh \
  /tmp/silk-specter-v3-easy \
  asteron_easy_v030
```

## 8. Validate event count and time range

```spl
| tstats count where index=asteron_easy_v030
```

Compare against `dataset/easy/manifest.json`.

```spl
index=asteron_easy_v030 earliest=0
| eval event_date=strftime(_time,"%Y-%m-%d")
| stats count by event_date
| sort event_date
```

For the default Easy window, only April 6–10, 2026 should appear.

## 9. Reconcile sourcetypes

```spl
index=asteron_easy_v030
| stats count by sourcetype
| sort sourcetype
```

Compare against:

```text
dataset/easy/expected_counts.csv
```

## 10. Windows channel validation

```spl
index=asteron_easy_v030 sourcetype=XmlWinEventLog
| stats count by source
```

Expected Windows source families include:

```text
XmlWinEventLog:Security
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

## 11. Corelight/Zeek CIM validation

```spl
index=asteron_easy_v030 sourcetype=bro:conn:json
| head 20
| table _time uid src_ip src_port dest_ip dest_port transport action bytes_in bytes_out
```

```spl
| tstats summariesonly=f count
    from datamodel=Network_Traffic.All_Traffic
    where index=asteron_easy_v030
    by All_Traffic.sourcetype
```

## 12. Optional cleanup after successful indexing

Once the index is validated, remove the copied source data from the container:

```bash
podman exec --user 0 splunk \
  rm -rf /tmp/silk-specter-v3-easy
```

The host copy can also be removed if the repository/generator is retained and the generated release is archived elsewhere.

## Automated host-side workflow

The repository includes:

```bash
./scripts/load_to_splunk.sh easy asteron_easy_v030
```

It performs the same TA copy/check, restart, interactive `splunk login`, fresh-index guard, data copy, and loader execution. It intentionally refuses to load scenarios whose config status is not `validated`.
