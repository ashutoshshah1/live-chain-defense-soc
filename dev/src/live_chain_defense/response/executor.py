from __future__ import annotations

from live_chain_defense.config import Settings
from live_chain_defense.models import Alert, GuardedExecutionResult, Incident, RelayMode, ResponseAction
from live_chain_defense.response.guardrails import ONCHAIN_ACTION_TYPES, ActionGuardrails
from live_chain_defense.response.relay import PrivateRelayClient


class AutoResponseExecutor:
    """Executes policy-approved actions with relay-aware routing."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.guardrails = ActionGuardrails(settings)
        self.relay = PrivateRelayClient()

    def execute(self, alert: Alert, actions: list[ResponseAction], incident: Incident | None) -> list[GuardedExecutionResult]:
        results: list[GuardedExecutionResult] = []
        onchain_actions = [a for a in actions if a.action_type in ONCHAIN_ACTION_TYPES]

        bundled_id: str | None = None
        if self.settings.response_mode == "enforce" and len(onchain_actions) > 1:
            bundled_id = self.relay.submit_bundle(onchain_actions)

        for action in actions:
            allowed, reason = self.guardrails.evaluate(alert, action, incident)
            if not allowed:
                results.append(
                    GuardedExecutionResult(
                        action_id=action.action_id,
                        allowed=False,
                        mode=RelayMode.public_mempool,
                        reason=reason,
                    )
                )
                continue

            mode = _mode_for_action(action, default_mode=self.settings.relay_default_mode)
            relay_submission_id: str | None = None

            if self.settings.response_mode == "enforce":
                if bundled_id and action.action_type in ONCHAIN_ACTION_TYPES:
                    relay_submission_id = bundled_id
                    mode = RelayMode.bundle
                elif action.action_type in ONCHAIN_ACTION_TYPES:
                    relay_submission_id = self.relay.submit(action, mode)
            else:
                reason = "dry-run mode: action validated but not executed"

            results.append(
                GuardedExecutionResult(
                    action_id=action.action_id,
                    allowed=True,
                    mode=mode,
                    reason=reason,
                    relay_submission_id=relay_submission_id,
                )
            )

        return results


def _mode_for_action(action: ResponseAction, default_mode: str) -> RelayMode:
    if action.action_type not in ONCHAIN_ACTION_TYPES:
        return RelayMode.public_mempool
    if default_mode == RelayMode.bundle.value:
        return RelayMode.bundle
    if default_mode == RelayMode.private_relay.value:
        return RelayMode.private_relay
    return RelayMode.public_mempool
