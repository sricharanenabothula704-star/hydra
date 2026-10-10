import tempfile
import unittest
from pathlib import Path

from core.autopilot import AutopilotEngine, HuntPhase


class AutopilotTruthfulnessTests(unittest.TestCase):
    def test_unconfigured_recon_does_not_claim_a_scan_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = AutopilotEngine(Path(tmp))
            hunt_id, result = engine.start_hunt("example", "example.com")
            engine.execute_phase(hunt_id)  # init -> recon
            outcome = engine.execute_phase(hunt_id)
            if outcome is None:
                self.fail("phase returned no result")
            self.assertEqual(outcome["status"], "blocked")
            self.assertEqual(result.phase, HuntPhase.PAUSED)
            self.assertEqual(result.subdomains_found, [])
            self.assertEqual(result.endpoints_discovered, [])

    def test_completed_hunt_uses_stored_id_and_findings_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = AutopilotEngine(Path(tmp))
            hunt_id, result = engine.start_hunt("example", "example.com")
            result.phase = HuntPhase.COMPLETE
            result.findings.append({"id": "finding-1"})
            setattr(result, "completed_at", result.started_at + 1)
            setattr(result, "duration", 1.0)
            engine.completed_hunts.append(result.to_dict())
            engine.active_hunts.pop(hunt_id)
            engine._save_completed()
            reloaded = AutopilotEngine(Path(tmp))
            self.assertIsNotNone(reloaded.get_status(hunt_id))
            self.assertEqual(reloaded.stats()["total_findings"], 1)


if __name__ == "__main__":
    unittest.main()
