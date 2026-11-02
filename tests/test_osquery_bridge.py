import tempfile
import unittest
from pathlib import Path

from edr_sim.models import ArchitectureMode, EventType
from edr_sim.osquery_bridge import (
    infer_event_type,
    read_osquery_jsonl,
    row_to_event,
    score_osquery_sessions,
    write_synthetic_fixture,
)


class OsqueryBridgeTests(unittest.TestCase):
    def test_explicit_event_type_is_preserved(self):
        event = row_to_event(
            {
                "event_type": "sensitive_access",
                "host_identifier": "host-1",
                "username": "test-user",
                "name": "powershell",
                "target": "database",
                "session_id": "session-1",
            },
            1,
        )
        self.assertEqual(event.event_type, EventType.SENSITIVE_ACCESS)
        self.assertEqual(event.metadata["source"], "osquery")

    def test_fallback_inference_uses_query_name(self):
        self.assertEqual(infer_event_type({"query_name": "process_events"}), EventType.PROCESS_START)
        self.assertEqual(infer_event_type({"query_name": "network_sockets"}), EventType.NETWORK_CONNECT)

    def test_synthetic_fixture_scores_human_and_ai_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.jsonl"
            write_synthetic_fixture(path)
            rows = read_osquery_jsonl(path)
            results = score_osquery_sessions(
                rows,
                architecture=ArchitectureMode.CENTRALIZED,
            )
        self.assertEqual({result["session_id"] for result in results}, {"human-office", "ai-adaptive"})
        self.assertTrue(next(result for result in results if result["session_id"] == "ai-adaptive")["detected"])


if __name__ == "__main__":
    unittest.main()
