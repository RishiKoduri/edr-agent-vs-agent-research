import unittest

from analysis.adaptation_sweep import (
    ADAPTATION_LEVELS,
    CORE_ARCHITECTURES,
    run_adaptation_sweep,
)
from edr_sim.generators import generate_session
from edr_sim.models import ActorProfile, TrafficClass


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

    def test_adaptation_level_changes_generated_behavior(self):
        low = generate_session(
            TrafficClass.AI_AGENT_ATTACKER,
            seed=7,
            length=32,
            adaptation_level=0,
            actor_profile=ActorProfile.ADAPTIVE_AI_AGENT,
        )
        high = generate_session(
            TrafficClass.AI_AGENT_ATTACKER,
            seed=7,
            length=32,
            adaptation_level=4,
            actor_profile=ActorProfile.ADAPTIVE_AI_AGENT,
        )
        self.assertNotEqual(low[-1].timestamp, high[-1].timestamp)
        self.assertNotEqual(
            [event.event_type for event in low],
            [event.event_type for event in high],
        )


if __name__ == "__main__":
    unittest.main()
