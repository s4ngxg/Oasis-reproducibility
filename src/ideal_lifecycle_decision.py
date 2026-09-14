"""Symbolic shared-decision functionality, not a blockchain refund mechanism.

Assumes a trusted, available, globally consistent decision and honest readiness
validation. Realizing these assumptions across ledgers is NOT implemented here.
No native signatures, VTDs, or benchmark measurements are produced.
"""
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class IdealCycle:
    session: str
    ready: tuple[bool, ...]
    assets: tuple[str, ...]
    decision: str = "pending"

    @classmethod
    def create(cls, session, participants):
        if not isinstance(session, str) or not session:
            raise ValueError("session required")
        if type(participants) is not int or participants < 3:
            raise ValueError("at least three participants required")
        return cls(session, (False,) * participants, ("unfunded",) * participants)

    def step(self, session, action, arc=None):
        if session != self.session:
            raise ValueError("wrong session")
        if action in ("commit", "abort"):
            if self.decision != "pending":
                raise ValueError("decision is immutable")
            if action == "commit" and (
                    not all(self.ready) or any(a != "locked" for a in self.assets)):
                raise ValueError("all funded arcs must be ready")
            return replace(self, decision=action)
        if type(arc) is not int or not 0 <= arc < len(self.assets):
            raise ValueError("invalid arc")
        assets, ready = list(self.assets), list(self.ready)
        if action == "fund":
            if self.decision != "pending" or assets[arc] != "unfunded":
                raise ValueError("funding refused")
            assets[arc] = "locked"
        elif action == "ready":
            if self.decision != "pending" or assets[arc] != "locked":
                raise ValueError("readiness refused")
            ready[arc] = True
        elif action in ("withdraw", "refund"):
            expected = "commit" if action == "withdraw" else "abort"
            if self.decision != expected or assets[arc] != "locked":
                raise ValueError("terminal action refused")
            assets[arc] = "withdrawn" if action == "withdraw" else "refunded"
        else:
            raise ValueError("unknown action")
        return replace(self, assets=tuple(assets), ready=tuple(ready))
