import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ideal_lifecycle_decision import IdealCycle


class IdealDecisionTests(unittest.TestCase):
    def test_exhaustive_three_arc_reachable_states(self):
        initial = IdealCycle.create("session", 3)
        visited, pending = {initial}, [initial]
        actions = [("commit", None), ("abort", None)] + [
            (action, arc) for arc in range(3)
            for action in ("fund", "ready", "withdraw", "refund")]
        while pending:
            state = pending.pop()
            self.assertFalse("withdrawn" in state.assets and "refunded" in state.assets)
            if state.decision == "commit":
                self.assertTrue(all(state.ready))
            for action, arc in actions:
                try:
                    child = state.step("session", action, arc)
                except ValueError:
                    continue
                if state.decision != "pending":
                    self.assertEqual(state.decision, child.decision)
                if child not in visited:
                    visited.add(child)
                    pending.append(child)
        self.assertTrue(any(s.assets == ("withdrawn",) * 3 for s in visited))
        self.assertTrue(any(s.assets == ("refunded",) * 3 for s in visited))

    def test_partial_funding_abort_and_session_binding(self):
        state = IdealCycle.create("session", 3).step("session", "fund", 0)
        with self.assertRaises(ValueError):
            state.step("session", "commit")
        state = state.step("session", "abort").step("session", "refund", 0)
        self.assertEqual(state.assets, ("refunded", "unfunded", "unfunded"))
        for action in ("fund", "withdraw", "refund"):
            with self.assertRaises(ValueError):
                state.step("session", action, 0)
        with self.assertRaises(ValueError):
            state.step("different-session", "abort")
