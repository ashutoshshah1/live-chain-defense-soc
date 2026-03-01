from __future__ import annotations

from live_chain_defense.models import ActionStatus, Alert, ResponseAction, Severity


class ResponsePolicyEngine:
    """Determines incident response actions from alert severity and context."""

    def __init__(self, mode: str = "dry_run") -> None:
        self.mode = mode

    def plan(self, alert: Alert) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        contract = alert.event.contract_address

        if alert.event.event_type.value == "pending_tx":
            actions.append(
                ResponseAction(
                    action_type="notify_preconfirm_channel",
                    description="Notify mempool defense channel for pre-confirmation response",
                    status=self._default_status(),
                    payload={"channel": "mempool-war-room"},
                )
            )

        if alert.severity in {Severity.high, Severity.critical}:
            actions.append(
                ResponseAction(
                    action_type="notify_admin_oncall",
                    description="Escalate to security on-call and treasury owner",
                    status=self._default_status(),
                    payload={"channel": "pagerduty+slack"},
                )
            )

        if alert.campaign_id:
            actions.append(
                ResponseAction(
                    action_type="open_campaign_war_room",
                    description="Create coordinated incident war-room for linked campaign activity",
                    status=self._default_status(),
                    payload={"campaign_id": alert.campaign_id},
                )
            )

        if alert.severity == Severity.critical and contract:
            actions.append(
                ResponseAction(
                    action_type="pause_contract",
                    description="Trigger emergency pause for critical contract",
                    status=self._default_status(),
                    payload={"contract": contract},
                )
            )
            actions.append(
                ResponseAction(
                    action_type="limit_withdrawals",
                    description="Apply temporary withdrawal rate limits",
                    status=self._default_status(),
                    payload={"scope": "treasury"},
                )
            )

        if alert.severity == Severity.critical and alert.confidence >= 0.75:
            actions.append(
                ResponseAction(
                    action_type="escalate_exchange_freeze",
                    description="Notify exchanges/custodians for rapid freeze request",
                    status=self._default_status(),
                    payload={"destination": alert.event.to_address, "campaign_id": alert.campaign_id},
                )
            )

        if alert.severity in {Severity.high, Severity.critical} and alert.event.to_address:
            actions.append(
                ResponseAction(
                    action_type="mark_destination_watchlist",
                    description="Add destination address to exchange/escalation watchlist",
                    status=self._default_status(),
                    payload={"address": alert.event.to_address},
                )
            )

        if alert.event.event_type.value == "bridge" and alert.severity in {Severity.high, Severity.critical}:
            actions.append(
                ResponseAction(
                    action_type="block_bridge_route",
                    description="Temporarily disable the suspicious bridge route",
                    status=self._default_status(),
                    payload={"bridge_contract": contract or alert.event.to_address},
                )
            )

        return actions

    def _default_status(self) -> ActionStatus:
        return ActionStatus.suggested if self.mode == "dry_run" else ActionStatus.executed
