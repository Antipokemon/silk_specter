"""Template for a new scenario/APT campaign module."""
from generator.core.network import NetworkFlow, NetworkLedger


def build_campaign(store, ctx, environment):
    """Add causal actor actions and source-native observations to EventStore.

    Requirements:
    - use ctx.at(...) for all authored times;
    - derive correlated network observations from shared NetworkFlow facts;
    - keep participant payload free of truth labels/activity IDs;
    - preserve validated renderer/TA contracts;
    - add scenario-specific tests before changing status to validated.
    """
    raise NotImplementedError
