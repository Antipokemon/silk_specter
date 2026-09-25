"""SILK SPECTER Hard campaign extension point.

Status is intentionally `authoring` in config/scenarios/hard.json. Hard should
use global/heterogeneous paths, sparse findings, legitimate admin lookalikes,
OT-adjacent pre-positioning, and approved MFT abuse for exfiltration where the
investigation proves unauthorized context rather than relying on a bad IOC.
"""

def build_campaign(store, ctx, environment):
    raise NotImplementedError(
        'Hard is authoring-gated. Build the distinct global campaign, detections, '
        'questions, and Splunk validation before enabling it.'
    )
