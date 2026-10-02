# Validation status

- **Easy:** validated baseline.
- **Medium:** authored; target-Splunk runtime validation pending.
- **Hard:** authored; target-Splunk runtime validation pending.

Run local checks with:

```bash
make validate
```

The suite verifies the canonical question bank, normalized static-campaign counts and signal ratios, instructor ground-truth reconciliation, TA-sensitive event shapes, track layout, notable-noise scaling, and operator-script behavior across Easy/Medium/Hard.

For Medium/Hard promotion, use a fresh index and verify:

1. indexed totals against `dataset/<track>/manifest.json`;
2. source/sourcetype and TA field extraction;
3. relevant CIM/data-model mappings;
4. every question `ReferenceSPL` and answer;
5. notable counts, fields, and drilldowns.

Only then change the track status to `validated`.
