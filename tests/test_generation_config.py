from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GenerationConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.easy = json.loads(
            (ROOT / "config/scenarios/easy.json").read_text(encoding="utf-8")
        )

    def test_easy_generation_defaults_live_in_scenario_config(self):
        self.assertIn("generation", self.easy)

        generation = self.easy["generation"]

        self.assertIn("background_events", generation)
        self.assertIn("enterprise_background_events", generation)

        self.assertIsInstance(generation["background_events"], int)
        self.assertIsInstance(generation["enterprise_background_events"], int)

        self.assertGreaterEqual(generation["background_events"], 0)
        self.assertGreaterEqual(generation["enterprise_background_events"], 0)

    def test_generation_count_precedence(self):
        from generator.generate import resolve_generation_counts

        generation = self.easy["generation"]

        configured_background = generation["background_events"]
        configured_enterprise = generation["enterprise_background_events"]

        # With no CLI overrides, scenario config is the source of truth.
        self.assertEqual(
            resolve_generation_counts(self.easy),
            (
                configured_background,
                configured_enterprise,
            ),
        )

        # Background override replaces only the configured background count.
        background_override = configured_background + 1

        self.assertEqual(
            resolve_generation_counts(
                self.easy,
                background_override,
                None,
            ),
            (
                background_override,
                configured_enterprise,
            ),
        )

        # Enterprise override replaces only the configured enterprise count.
        enterprise_override = configured_enterprise + 1

        self.assertEqual(
            resolve_generation_counts(
                self.easy,
                None,
                enterprise_override,
            ),
            (
                configured_background,
                enterprise_override,
            ),
        )

        # Both CLI overrides take precedence over scenario configuration.
        self.assertEqual(
            resolve_generation_counts(
                self.easy,
                background_override,
                enterprise_override,
            ),
            (
                background_override,
                enterprise_override,
            ),
        )

    def test_internal_fallbacks_exist_for_older_scenario_configs(self):
        from generator.generate import (
            DEFAULT_BACKGROUND_EVENTS,
            DEFAULT_ENTERPRISE_BACKGROUND_EVENTS,
            resolve_generation_counts,
        )

        self.assertEqual(
            resolve_generation_counts({}),
            (
                DEFAULT_BACKGROUND_EVENTS,
                DEFAULT_ENTERPRISE_BACKGROUND_EVENTS,
            ),
        )

    def test_negative_generation_counts_are_rejected(self):
        from generator.generate import resolve_generation_counts

        with self.assertRaises(ValueError):
            resolve_generation_counts(self.easy, -1, None)

        with self.assertRaises(ValueError):
            resolve_generation_counts(self.easy, None, -1)

    def test_makefile_does_not_duplicate_easy_default_counts(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        target = makefile.split("generate-easy:", 1)[1].split(
            "\n\nsplunk-load:", 1
        )[0]

        # Easy generation defaults belong in config/scenarios/easy.json.
        # The Makefile may expose optional override variables, but it should
        # not provide literal numeric generation counts.
        self.assertIsNone(
            re.search(r"--background-events\s+\d+", target)
        )
        self.assertIsNone(
            re.search(r"--enterprise-background-events\s+\d+", target)
        )

        self.assertIn("$(BACKGROUND_OVERRIDE)", target)
        self.assertIn("$(ENTERPRISE_BACKGROUND_OVERRIDE)", target)

    def test_easy_attack_generation_calls_are_still_present(self):
        source = (ROOT / "generator/generate.py").read_text(encoding="utf-8")

        self.assertIn("add_attack(store)", source)
        self.assertIn("add_attack_corroboration(store,CFG)", source)
        self.assertIn("add_attack_expansion(store,CFG)", source)


if __name__ == "__main__":
    unittest.main()