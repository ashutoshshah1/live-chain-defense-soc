from __future__ import annotations

from uuid import uuid4

from live_chain_defense.models import RelayMode, ResponseAction


class PrivateRelayClient:
    """Simulates private relay and bundle submission."""

    def __init__(self) -> None:
        self.submissions: list[dict] = []

    def submit(self, action: ResponseAction, mode: RelayMode) -> str:
        submission_id = f"relay-{uuid4().hex[:12]}"
        self.submissions.append(
            {
                "submission_id": submission_id,
                "mode": mode.value,
                "action_type": action.action_type,
                "payload": action.payload,
            }
        )
        return submission_id

    def submit_bundle(self, actions: list[ResponseAction]) -> str:
        submission_id = f"bundle-{uuid4().hex[:12]}"
        self.submissions.append(
            {
                "submission_id": submission_id,
                "mode": RelayMode.bundle.value,
                "actions": [a.action_type for a in actions],
            }
        )
        return submission_id

    def recent_submissions(self, limit: int = 100) -> list[dict]:
        return self.submissions[-limit:][::-1]
