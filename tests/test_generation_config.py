from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GenerationConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.easy = json.loads((ROOT / 'config/scenarios/easy.json').read_text(encoding='utf-8'))

    def test_easy_generation_defaults_live_in_scenario_config(self):
        self.assertEqual(
            self.easy['generation'],
            {
                'background_events': 5000,
                'enterprise_background_events': 45000,
            },
        )

    def test_generation_count_precedence(self):
        from generator.generate import resolve_generation_counts

        self.assertEqual(resolve_generation_counts(self.easy), (5000, 45000))
        self.assertEqual(resolve_generation_counts(self.easy, 25000, None), (25000, 45000))
        self.assertEqual(resolve_generation_counts(self.easy, None, 225000), (5000, 225000))
        self.assertEqual(resolve_generation_counts(self.easy, 100, 1000), (100, 1000))

    def test_internal_fallbacks_exist_for_older_scenario_configs(self):
        from generator.generate import resolve_generation_counts

        self.assertEqual(resolve_generation_counts({}), (5000, 45000))

    def test_negative_generation_counts_are_rejected(self):
        from generator.generate import resolve_generation_counts

        with self.assertRaises(ValueError):
            resolve_generation_counts(self.easy, -1, None)
        with self.assertRaises(ValueError):
            resolve_generation_counts(self.easy, None, -1)

    def test_makefile_does_not_duplicate_easy_default_counts(self):
        makefile = (ROOT / 'Makefile').read_text(encoding='utf-8')
        target = makefile.split('generate-easy:', 1)[1].split('\n\nsplunk-load:', 1)[0]
        self.assertNotIn('--background-events 5000', target)
        self.assertNotIn('--enterprise-background-events 45000', target)
        self.assertIn('$(BACKGROUND_OVERRIDE)', target)
        self.assertIn('$(ENTERPRISE_BACKGROUND_OVERRIDE)', target)

    def test_easy_attack_generation_calls_are_still_present(self):
        source = (ROOT / 'generator/generate.py').read_text(encoding='utf-8')
        self.assertIn('add_attack(store)', source)
        self.assertIn('add_attack_corroboration(store,CFG)', source)
        self.assertIn('add_attack_expansion(store,CFG)', source)


if __name__ == '__main__':
    unittest.main()
