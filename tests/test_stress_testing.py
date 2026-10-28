import unittest

from edr_sim.models import ArchitectureMode
from edr_sim.stress_testing import (
    CORE_ARCHITECTURES,
    PRESSURE_LEVELS,
    run_stress_experiment,
    run_stress_trial,
)


class StressTestingTests(unittest.TestCase):
    def test_stress_experiment_has_expected_dimensions(self):
        results = run_stress_experiment(seeds=range(2))
        self.assertEqual(len(results), 2 * len(CORE_ARCHITECTURES) * len(PRESSURE_LEVELS))
        self.assertEqual({result.architecture for result in results}, set(CORE_ARCHITECTURES))

    def test_backlog_increases_with_pressure(self):
        low = run_stress_trial(0, 1, architecture=ArchitectureMode.LOCAL)
        high = run_stress_trial(0, 32, architecture=ArchitectureMode.LOCAL)
        self.assertEqual(low.backlog_sessions, 0)
        self.assertGreater(high.backlog_sessions, low.backlog_sessions)
        self.assertGreater(high.operator_burden_index, low.operator_burden_index)

    def test_federated_capacity_exceeds_local_capacity(self):
        local = run_stress_trial(0, 16, architecture=ArchitectureMode.LOCAL)
        federated = run_stress_trial(0, 16, architecture=ArchitectureMode.FEDERATED)
        self.assertGreater(federated.capacity_sessions, local.capacity_sessions)
        self.assertLess(federated.backlog_sessions, local.backlog_sessions)


if __name__ == "__main__":
    unittest.main()
