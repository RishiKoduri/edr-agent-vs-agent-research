import unittest

from edr_sim.metrics import summarize_by_architecture, summarize_by_class
from edr_sim.models import ActorProfile, ArchitectureMode, TrafficClass
from edr_sim.simulation import run_experiment, run_trial


class BaselineSimulationTests(unittest.TestCase):
    def test_experiment_generates_all_traffic_classes(self):
        runs = run_experiment(range(2))
        self.assertEqual(len(runs), 56)
        self.assertEqual({run.traffic_class for run in runs}, set(TrafficClass))
        self.assertEqual({run.architecture for run in runs}, set(ArchitectureMode))
        self.assertTrue(
            {
                ActorProfile.OFFICE_WORKER,
                ActorProfile.DEVELOPER,
                ActorProfile.SYSADMIN,
                ActorProfile.HELPDESK,
                ActorProfile.SERVICE_ACCOUNT,
            }.issubset({run.actor_profile for run in runs})
        )

    def test_scripted_attacker_scores_higher_than_benign_admin(self):
        benign = run_trial(TrafficClass.BENIGN_ADMIN, seed=7)
        scripted = run_trial(TrafficClass.SCRIPTED_ATTACKER, seed=7)
        self.assertGreater(scripted.score, benign.score)

    def test_ai_agent_attacker_is_detectable_in_baseline(self):
        result = run_trial(TrafficClass.AI_AGENT_ATTACKER, seed=11)
        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 4.0)

    def test_federated_scores_at_least_local_for_ai_agent(self):
        local = run_trial(
            TrafficClass.AI_AGENT_ATTACKER,
            seed=11,
            architecture=ArchitectureMode.LOCAL,
            adaptation_level=2,
        )
        federated = run_trial(
            TrafficClass.AI_AGENT_ATTACKER,
            seed=11,
            architecture=ArchitectureMode.FEDERATED,
            adaptation_level=2,
        )
        self.assertGreaterEqual(federated.score, local.score)

    def test_metric_summaries_are_generated(self):
        runs = run_experiment(range(3))
        self.assertEqual(len(summarize_by_architecture(runs)), 4)
        self.assertEqual(len(summarize_by_class(runs)), 28)


if __name__ == "__main__":
    unittest.main()
