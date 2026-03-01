from __future__ import annotations

from live_chain_defense.config import Settings
from live_chain_defense.models import Alert, Incident, ResponseAction


ONCHAIN_ACTION_TYPES = {
    "pause_contract",
    "limit_withdrawals",
    "revoke_role",
    "block_bridge_route",
    "submit_preconfirm_block",
}


class ActionGuardrails:
    """Safety checks before automated response execution."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(self, alert: Alert, action: ResponseAction, incident: Incident | None) -> tuple[bool, str]:
        if incident and len(incident.actions) >= self.settings.max_auto_actions_per_incident:
            return False, "max actions per incident reached"

        if action.action_type == "pause_contract" and self.settings.require_manual_approval_for_pause:
            return False, "manual approval required for pause action"

        if action.action_type in ONCHAIN_ACTION_TYPES and alert.severity.value not in {"high", "critical"}:
            return False, "on-chain actions allowed only for high/critical alerts"

        if action.action_type == "limit_withdrawals" and alert.risk_score < self.settings.critical_score_threshold:
            return False, "withdrawal limiting reserved for critical risk"

        return True, "allowed"
