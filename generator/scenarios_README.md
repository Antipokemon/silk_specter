# Scenario loaders

`config/scenarios/<track>.json` is the scenario registry. Each track's loader in `generator/scenarios/` reads the fixed file configured by `static_campaign` and adds those records to the generated corpus.

The loader must not create or randomize answer-bearing attack evidence. New/changed attack-chain events belong in `scenario_data/<track>/attack_events.jsonl` and require coordinated question/reference validation.
