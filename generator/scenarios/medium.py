"""SILK SPECTER Medium campaign extension point.

Status is intentionally `authoring` in config/scenarios/medium.json. Implement a
campaign distinct from Easy before enabling generation. Use ScenarioContext for
all times and NetworkFlow/NetworkLedger for semantic network sessions.
"""

def build_campaign(store, ctx, environment):
    raise NotImplementedError(
        'Medium is authoring-gated. Build the distinct multi-region campaign, '
        'detections, questions, and Splunk validation before enabling it.'
    )
