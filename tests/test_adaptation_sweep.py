import unittest

from analysis.adaptation_sweep import (
    ADAPTATION_LEVELS,
    CORE_ARCHITECTURES,
    run_adaptation_sweep,
)


class AdaptationSweepTests(unittest.TestCase):
    def test_sweep_has_expected_dimensions(self):
        results = run_adaptation_sweep(seeds=range(2))
        self.assertEqual(len(results), 2 * len(CORE_ARCHITECTURES) * len(ADAPTATION_LEVELS))

    def test_adaptation_levels_are_represented(self):
        results = run_adaptation_sweep(seeds=range(1))
        self.assertEqual(
            {result.adaptation_level for result in results},
            set(ADAPTATION_LEVELS),
        )


if __name__ == "__main__":
    unittest.main()
