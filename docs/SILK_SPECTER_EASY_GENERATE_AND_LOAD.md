# SILK SPECTER Easy Dataset: Generate and Load into Splunk

This guide starts **after the GitHub repository has already been downloaded or cloned**.

It covers:

1. Entering the repository
2. Generating the Easy dataset
3. Validating the generated data
4. Creating a fresh Splunk index
5. Installing/verifying the Asteron ingest TA
6. Logging into the Splunk CLI
7. Copying the generated data into the Splunk container
8. Loading the data
9. Verifying counts, timestamps, and sourcetypes
10. Cleaning up temporary files

---

## 1. Enter the repository

```bash
cd ~/Documents/silk_specter
```

Check scenario status:

```bash
python3 scripts/scenario_status.py
```

Easy should show as:

```text
validated
```

The Easy generator automatically reads its default timeframe and scenario settings from:

```text
config/scenarios/easy.json
```

You do not need to provide `--start` or `--end` unless you intentionally want to override the scenario timeframe.

---

## 2. Generate the Easy dataset

For the normal baseline dataset:

```bash
make generate-easy
```

This is equivalent to:

```bash
python3 generator/generate.py   --scenario easy   --output dataset/easy   --background-events 5000   --enterprise-background-events 45000
```

The generator creates both:

```text
normal Asteron activity
+
SILK SPECTER campaign activity
```

The dataset is rebuilt from scratch. It does not append to a previous generated dataset.

### Generate a larger-noise dataset

If you want substantially more benign/background activity:

```bash
make generate-easy   BACKGROUND_EVENTS=25000   ENTERPRISE_BACKGROUND_EVENTS=225000
```

The SILK SPECTER campaign remains the same while the surrounding benign activity increases.

---

## 3. Validate the generated dataset

Run:

```bash
make validate
```

Inspect the generated manifest:

```bash
python3 -m json.tool dataset/easy/manifest.json
```

Check the generated HEC event count:

```bash
wc -l dataset/easy/hec/events.jsonl
```

The HEC line count should match the `events` value in:

```text
dataset/easy/manifest.json
```

Inspect generated sourcetype counts:

```bash
column -s, -t < dataset/easy/expected_counts.csv | less
```

---

## 4. Choose a fresh Splunk index

Use a new index for each newly generated corpus.

Example:

```bash
INDEX=asteron_easy_run01
```

Do not load regenerated data into an old Easy index.

---

## 5. Install or update the Asteron ingest TA

From the repository root:

```bash
podman cp   splunk/app/TA-asteron-v3   splunk:/opt/splunk/etc/apps/TA-asteron-v3
```

Restart Splunk:

```bash
podman restart splunk
```

Verify the HEC parser:

```bash
podman exec --user splunk splunk   /opt/splunk/bin/splunk btool props list asteron:hec --debug
```

Confirm that the output includes:

```text
INDEXED_EXTRACTIONS = HEC
```

---

## 6. Log into the Splunk CLI

```bash
podman exec -it --user splunk splunk   /opt/splunk/bin/splunk login
```

Enter your Splunk username and password when prompted.

---

## 7. Create the Easy index

Using the `INDEX` variable defined earlier:

```bash
podman exec --user splunk splunk   /opt/splunk/bin/splunk add index "$INDEX"
```

Verify that the index exists:

```bash
podman exec --user splunk splunk   /opt/splunk/bin/splunk list index | grep "$INDEX"
```

---

## 8. Copy the generated Easy dataset into the Splunk container

Remove any previous temporary copy:

```bash
podman exec --user 0 splunk   rm -rf /tmp/silk-specter-v3-easy
```

Copy the generated Easy dataset:

```bash
podman cp   dataset/easy   splunk:/tmp/silk-specter-v3-easy
```

Copy the loader script:

```bash
podman cp   splunk/ingest/load_hec.sh   splunk:/tmp/silk-specter-v3-easy/load_hec.sh
```

Make sure the loader is executable:

```bash
podman exec --user 0 splunk   chmod 755 /tmp/silk-specter-v3-easy/load_hec.sh
```

---

## 9. Load the generated data into Splunk

Run:

```bash
podman exec --user splunk splunk bash   /tmp/silk-specter-v3-easy/load_hec.sh   /tmp/silk-specter-v3-easy   "$INDEX"
```

The loader checks the generated dataset and submits the canonical HEC stream to Splunk.

---

## 10. Verify the expected event count

From the host, view the expected count and scenario window:

```bash
python3 - <<'PY'
import json

m = json.load(open("dataset/easy/manifest.json"))

print("Expected events:", m["events"])
print("Start:", m["window_start"])
print("End:", m["window_end"])
PY
```

Then search Splunk:

```spl
| tstats count where index=asteron_easy_run01
```

Replace `asteron_easy_run01` with the index name you selected.

The Splunk count should match the generated manifest.

---

## 11. Verify the timeframe in Splunk

Run:

```spl
index=asteron_easy_run01 earliest=0
| stats min(_time) as first max(_time) as last
| convert ctime(first) ctime(last)
```

For the standard Easy scenario configuration, generated events should remain within:

```text
2026-04-06 00:00:00 UTC
through
2026-04-10 23:59:59 UTC
```

The host operating system can use its local timezone. The generated SILK SPECTER/Asteron event timestamps are intentionally UTC.

---

## 12. Verify sourcetypes

Run:

```spl
index=asteron_easy_run01
| stats count by sourcetype
| sort sourcetype
```

Compare the results with:

```text
dataset/easy/expected_counts.csv
```

### Verify Windows data

```spl
index=asteron_easy_run01 sourcetype=XmlWinEventLog
| stats count by source
```

You should see Windows sources including:

```text
XmlWinEventLog:Security
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### Verify Zeek/Corelight connection data

```spl
index=asteron_easy_run01 sourcetype=bro:conn:json
| head 20
| table _time uid src_ip src_port dest_ip dest_port transport action bytes_in bytes_out
```

---

## 13. Clean up the temporary container copy

After the Splunk data is verified:

```bash
podman exec --user 0 splunk   rm -rf /tmp/silk-specter-v3-easy
```

The generated host-side data remains under:

```text
dataset/easy/
```

That directory can be committed to Git along with the generator/configuration that produced it.

---

## Alternative: use the helper loader

The repository also includes:

```bash
./scripts/load_to_splunk.sh easy <index>
```

Example:

```bash
./scripts/load_to_splunk.sh easy asteron_easy_run01
```

If you use this helper, **do not manually create the index first**. The helper expects a fresh index name and creates the index itself.

Use either:

- the full manual workflow documented above, or
- the helper loader

but do not mix the two index-creation methods for the same run.
