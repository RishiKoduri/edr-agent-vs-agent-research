import unittest

from edr_sim.models import TrafficClass
from edr_sim.simulation import run_experiment, run_trial


class BaselineSimulationTests(unittest.TestCase):
    def test_experiment_generates_all_traffic_classes(self):
        runs = run_experiment(range(2))
        self.assertEqual(len(runs), 6)
        self.assertEqual({run.traffic_class for run in runs}, set(TrafficClass))

    def test_scripted_attacker_scores_higher_than_benign_admin(self):
        benign = run_trial(TrafficClass.BENIGN_ADMIN, seed=7)
        scripted = run_trial(TrafficClass.SCRIPTED_ATTACKER, seed=7)
        self.assertGreater(scripted.score, benign.score)

    def test_ai_agent_attacker_is_detectable_in_baseline(self):
        result = run_trial(TrafficClass.AI_AGENT_ATTACKER, seed=11)
        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 4.0)


if __name__ == "__main__":
    unittest.main()
