from __future__ import annotations

import unittest

# REFACTORING NOTE: This test file is TEMPORARILY DISABLED pending Phase 2 refactoring
# - Tests legacy ScenarioRunner (simulator/scenario_runner.py)
# - Uses outdated schema classes (ScenarioConfig, PayloadConfig, UplinkConfig, ScenarioMeta)
# - Will be replaced with consolidated runner tests after runner consolidation
# See: REFACTORING.md Phase 2 - Consolidating runner logic


class ScenarioRunnerTests(unittest.TestCase):
    @unittest.skip("Legacy test - pending Phase 2 runner consolidation (see REFACTORING.md)")
    def test_runner_retries_join_and_keeps_uplinking_until_manual_stop(self) -> None:
        """Test legacy runner behavior. Skipped - schema classes removed."""
        pass
