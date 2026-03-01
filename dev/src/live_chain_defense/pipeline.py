from __future__ import annotations

from time import perf_counter
from threading import RLock

from live_chain_defense.config import Settings
from live_chain_defense.detection.risk_engine import RiskEngine
from live_chain_defense.feedback.learning import AnalystFeedbackLoop
from live_chain_defense.intelligence.campaigns import CampaignCorrelator
from live_chain_defense.intelligence.entities import CrossChainEntityIntel
from live_chain_defense.intelligence.graph import AddressGraphIntel
from live_chain_defense.models import (
    Alert,
    ChainEvent,
    EventType,
    LabelVerdict,
    NotificationProvider,
    PendingTx,
    PreconfirmAssessment,
    ResponseAction,
    RiskAssessment,
    Severity,
)
from live_chain_defense.ops.slo import SLOMonitor
from live_chain_defense.response.executor import AutoResponseExecutor
from live_chain_defense.response.notifier import Notifier
from live_chain_defense.response.playbooks import ResponsePolicyEngine
from live_chain_defense.store import InMemoryStore
from live_chain_defense.stream.mempool import PreconfirmationSentinel
from live_chain_defense.stream.replay import ReplaySafetyManager


class DefensePipeline:
    def __init__(self, settings: Settings, store: InMemoryStore) -> None:
        self.settings = settings
        self.store = store
        self._lock = RLock()

        self.graph = AddressGraphIntel(malicious_seeds=set(settings.default_malicious_seeds))
        self.entity_intel = CrossChainEntityIntel(malicious_seeds=set(settings.default_malicious_seeds))
        self.campaigns = CampaignCorrelator(merge_window_seconds=settings.campaign_merge_window_seconds)
        self.replay = ReplaySafetyManager(
            confirmation_depth=settings.reorg_confirmation_depth,
            dedup_enabled=settings.replay_dedup_enabled,
        )
        self.mempool = PreconfirmationSentinel(settings)
        self.risk_engine = RiskEngine(settings)
        self.notifier = Notifier()
        self.response = ResponsePolicyEngine(mode=settings.response_mode)
        self.executor = AutoResponseExecutor(settings)
        self.feedback = AnalystFeedbackLoop(settings)
        self.slo = SLOMonitor(settings)

    def process_event(self, event: ChainEvent) -> dict:
        with self._lock:
            started = perf_counter()

            replay_result = self.replay.ingest_confirmed(event)
            if not replay_result["accepted"]:
                latency_ms = (perf_counter() - started) * 1000
                self.slo.record_confirmed(latency_ms)
                return {
                    "event_id": event.event_id,
                    "tx_hash": event.tx_hash,
                    "dropped": True,
                    "drop_reason": replay_result["reason"],
                    "canonical_event_id": replay_result["canonical_event_id"],
                }

            campaign_context = self.campaigns.assign(event)
            graph_signals = self.graph.preview_signals(event)
            entity_signals = self.entity_intel.ingest(event)
            merged_signals = {**graph_signals, **entity_signals}

            assessment: RiskAssessment = self.risk_engine.assess(event, merged_signals)

            payload = event.model_dump(mode="json")
            payload["canonical_event_id"] = replay_result["canonical_event_id"]
            payload["reorg_detected"] = replay_result["reorg_detected"]
            self.store.add_event(payload)
            self.graph.ingest(event)

            result: dict = {
                "event_id": event.event_id,
                "canonical_event_id": replay_result["canonical_event_id"],
                "tx_hash": event.tx_hash,
                "severity": assessment.severity.value,
                "risk_score": assessment.score,
                "confidence": assessment.confidence,
                "signals": {**assessment.signals.model_dump(), **entity_signals},
                "reasons": assessment.reasons,
                "campaign": campaign_context,
                "reorg_detected": replay_result["reorg_detected"],
                "alerted": False,
                "actions": [],
                "execution": [],
            }

            if assessment.score >= self.settings.alert_score_threshold:
                alert = self._build_alert(
                    event=event,
                    assessment=assessment,
                    campaign_id=str(campaign_context["campaign_id"]),
                )
                incident = self.store.add_alert(alert)
                self.notifier.send(alert)
                actions = self.response.plan(alert)
                actions = self._augment_actions_for_prevention(alert, actions)
                incident.actions.extend(actions)

                execution_results = self.executor.execute(alert=alert, actions=actions, incident=incident)

                result["alerted"] = True
                result["actions"] = [a.model_dump(mode="json") for a in actions]
                result["execution"] = [r.model_dump(mode="json") for r in execution_results]
                result["incident_id"] = incident.incident_id

            latency_ms = (perf_counter() - started) * 1000
            self.slo.record_confirmed(latency_ms)
            return result

    def process_pending_tx(self, pending_tx: PendingTx) -> dict:
        with self._lock:
            started = perf_counter()

            replay_result = self.replay.ingest_pending(pending_tx)
            if not replay_result["accepted"]:
                latency_ms = (perf_counter() - started) * 1000
                self.slo.record_preconfirm(latency_ms)
                return {
                    "pending_id": pending_tx.pending_id,
                    "tx_hash": pending_tx.tx_hash,
                    "dropped": True,
                    "drop_reason": replay_result["reason"],
                }

            destination_taint = self.entity_intel.taint.get(pending_tx.to_address.lower(), 0.0)
            assessment: PreconfirmAssessment = self.mempool.assess(pending_tx, destination_taint=destination_taint)

            result: dict = {
                "pending_id": pending_tx.pending_id,
                "tx_hash": pending_tx.tx_hash,
                "severity": assessment.severity.value,
                "risk_score": assessment.risk_score,
                "confidence": assessment.confidence,
                "reasons": assessment.reasons,
                "alerted": False,
                "actions": [],
                "execution": [],
            }

            if assessment.risk_score >= self.settings.mempool_alert_score_threshold:
                synthetic_event = ChainEvent(
                    chain=pending_tx.chain,
                    timestamp=pending_tx.seen_at,
                    tx_hash=pending_tx.tx_hash,
                    from_address=pending_tx.from_address,
                    to_address=pending_tx.to_address,
                    method=pending_tx.method,
                    amount_usd=pending_tx.value_usd,
                    event_type=EventType.pending_tx,
                    metadata={"preconfirm": True, **pending_tx.metadata},
                )
                campaign_context = self.campaigns.assign(synthetic_event)
                alert = Alert(
                    severity=assessment.severity,
                    risk_score=assessment.risk_score,
                    confidence=assessment.confidence,
                    campaign_id=str(campaign_context["campaign_id"]),
                    message=(
                        f"PRECONFIRM {assessment.severity.value.upper()} risk {assessment.risk_score} "
                        f"for pending tx {pending_tx.tx_hash}"
                    ),
                    event=synthetic_event,
                    reasons=assessment.reasons,
                )

                incident = self.store.add_alert(alert)
                self.notifier.send(alert)
                actions = self.response.plan(alert)
                actions = self._augment_actions_for_prevention(alert, actions)
                incident.actions.extend(actions)

                execution_results = self.executor.execute(alert=alert, actions=actions, incident=incident)
                result["alerted"] = True
                result["actions"] = [a.model_dump(mode="json") for a in actions]
                result["execution"] = [r.model_dump(mode="json") for r in execution_results]
                result["incident_id"] = incident.incident_id

            latency_ms = (perf_counter() - started) * 1000
            self.slo.record_preconfirm(latency_ms)
            return result

    def replay_events(self, events: list[ChainEvent]) -> dict:
        with self._lock:
            outputs = [self.process_event(event) for event in events]
            dropped = sum(1 for item in outputs if item.get("dropped"))
            alerted = sum(1 for item in outputs if item.get("alerted"))
            return {
                "processed": len(outputs),
                "dropped": dropped,
                "alerts": alerted,
                "last": outputs[-1] if outputs else None,
            }

    def add_malicious_seed(self, address: str) -> None:
        with self._lock:
            self.graph.add_malicious_seed(address)
            self.entity_intel.taint[address.lower()] = 1.0

    def remove_malicious_seed(self, address: str) -> None:
        with self._lock:
            self.graph.remove_malicious_seed(address)

    def list_malicious_seeds(self) -> list[str]:
        return self.graph.list_malicious_seeds()

    def list_campaigns(self, limit: int = 100) -> list[dict]:
        return self.campaigns.list_campaigns(limit=limit)

    def list_bridge_links(self, limit: int = 100) -> list[dict]:
        return self.entity_intel.list_bridge_links(limit=limit)

    def add_critical_contract(self, address: str) -> None:
        with self._lock:
            current = {c.lower() for c in self.settings.critical_contracts}
            current.add(address.lower())
            self.settings.critical_contracts = tuple(sorted(current))

    def remove_critical_contract(self, address: str) -> None:
        with self._lock:
            current = {c.lower() for c in self.settings.critical_contracts}
            current.discard(address.lower())
            self.settings.critical_contracts = tuple(sorted(current))

    def list_critical_contracts(self) -> list[str]:
        return sorted(c.lower() for c in self.settings.critical_contracts)

    def add_notification_channel(
        self,
        *,
        provider: str,
        destination: str,
        min_severity: str = Severity.high.value,
        enabled: bool = True,
        metadata: dict | None = None,
    ) -> dict:
        with self._lock:
            channel = self.notifier.configure_channel(
                provider=NotificationProvider(provider),
                destination=destination,
                min_severity=Severity(min_severity),
                enabled=enabled,
                metadata=metadata or {},
            )
            return channel.model_dump(mode="json")

    def remove_notification_channel(self, channel_id: str) -> bool:
        with self._lock:
            return self.notifier.remove_channel(channel_id)

    def list_notification_channels(self) -> list[dict]:
        with self._lock:
            return [channel.model_dump(mode="json") for channel in self.notifier.list_channels()]

    def list_notification_messages(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return [dispatch.model_dump(mode="json") for dispatch in self.notifier.list_sent(limit=limit)]

    def test_notification(self, channel_id: str | None = None, message: str = "Test notification") -> list[dict]:
        with self._lock:
            dispatches = self.notifier.send_test(channel_id=channel_id, message=message)
            return [dispatch.model_dump(mode="json") for dispatch in dispatches]

    def add_analyst_label(self, alert_id: str, verdict: str, notes: str = "") -> dict:
        with self._lock:
            label = self.feedback.add_label(alert_id=alert_id, verdict=LabelVerdict(verdict), notes=notes)
            return label.model_dump(mode="json")

    def recalibrate_from_feedback(self) -> dict:
        with self._lock:
            recent_alerts = self.store.list_alerts(limit=500)
            return self.feedback.recalibrate_weekly(recent_alerts)

    def run_backtest(self) -> dict:
        from live_chain_defense.simulation.backtesting import RedTeamBacktester

        backtester = RedTeamBacktester(self.settings)
        result = backtester.run()
        return result.model_dump(mode="json")

    def run_failover_drill(self) -> dict:
        with self._lock:
            return self.slo.run_failover_drill()

    def report_outage(self, seconds: float) -> None:
        with self._lock:
            self.slo.register_outage(seconds)

    def runtime_stats(self) -> dict:
        return {
            "seed_count": len(self.graph.malicious_seeds),
            "campaign_count": len(self.campaigns.campaigns),
            "notifier_messages": len(self.notifier.sent),
            "notification_channels": len(self.notifier.channels),
            "relay_submissions": len(self.executor.relay.submissions),
            "feedback": self.feedback.summary(),
            "replay": self.replay.stats(),
            "slo": self.slo.status(),
        }

    def recent_reorgs(self, limit: int = 100) -> list[dict]:
        return self.replay.list_recent_reorgs(limit=limit)

    def recent_relay_submissions(self, limit: int = 100) -> list[dict]:
        return self.executor.relay.recent_submissions(limit=limit)

    def recent_labels(self, limit: int = 200) -> list[dict]:
        return [label.model_dump(mode="json") for label in self.feedback.recent_labels(limit=limit)]

    def _build_alert(self, event: ChainEvent, assessment: RiskAssessment, campaign_id: str) -> Alert:
        message = (
            f"{assessment.severity.value.upper()} risk {assessment.score} on "
            f"{event.chain} tx {event.tx_hash}"
        )

        if assessment.severity == Severity.critical:
            message = (
                f"CRITICAL drain threat: {event.amount_usd:,.0f} USD flow from "
                f"{event.from_address} (confidence={assessment.confidence:.2f})"
            )

        return Alert(
            severity=assessment.severity,
            risk_score=assessment.score,
            confidence=assessment.confidence,
            campaign_id=campaign_id,
            message=message,
            event=event,
            reasons=assessment.reasons,
        )

    def _augment_actions_for_prevention(self, alert: Alert, actions: list[ResponseAction]) -> list[ResponseAction]:
        if alert.event.event_type == EventType.pending_tx and alert.severity in {Severity.high, Severity.critical}:
            actions.append(
                ResponseAction(
                    action_type="submit_preconfirm_block",
                    description="Submit pre-confirmation blocking transaction via private relay",
                    payload={
                        "tx_hash": alert.event.tx_hash,
                        "campaign_id": alert.campaign_id,
                        "strategy": "bundle_front_run_guard",
                    },
                )
            )
        return actions
