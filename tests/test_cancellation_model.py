"""Counterexample for unconditional timed cancellation, not protocol execution.

Each arc represents one original funding output. Withdraw pays its receiver;
cancel returns it to its sender. This intentionally models the proposed weak
extension without a cross-arc authorization rule, to show why local unspent
checks and a timeout alone do not establish atomicity.
"""
import itertools
import unittest


def apply(states, arc, action):
    if states[arc] != "locked":
        raise ValueError("output already spent")
    if action not in ("withdraw", "cancel"):
        raise ValueError("unknown action")
    result = list(states)
    result[arc] = action
    return tuple(result)


def mixed_terminal(states):
    return "withdraw" in states and "cancel" in states


class CancellationModelTests(unittest.TestCase):
    def test_local_double_spend_rejection_does_not_imply_atomicity(self):
        # At the cutoff, valid competing transactions can be ordered differently
        # on independent chains. The attacker receives arc 0 and cancels arc 1.
        states = apply(("locked",) * 3, 0, "withdraw")
        states = apply(states, 1, "cancel")
        states = apply(states, 2, "cancel")
        self.assertTrue(mixed_terminal(states))
        self.assertEqual(states, ("withdraw", "cancel", "cancel"))
        for arc in range(3):
            with self.assertRaisesRegex(ValueError, "already spent"):
                apply(states, arc, "withdraw")

    def test_all_action_orders_preserve_the_counterexample(self):
        for order in itertools.permutations(range(3)):
            states = ("locked",) * 3
            for arc in order:
                states = apply(states, arc, "withdraw" if arc == 0 else "cancel")
            self.assertTrue(mixed_terminal(states))

    def test_uniform_outcomes_are_not_this_counterexample(self):
        self.assertFalse(mixed_terminal(("withdraw",) * 3))
        self.assertFalse(mixed_terminal(("cancel",) * 3))
