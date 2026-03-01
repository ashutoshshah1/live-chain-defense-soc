from __future__ import annotations

from datetime import datetime, timedelta, timezone

from live_chain_defense.config import Settings
from live_chain_defense.models import BacktestResult, ChainEvent, EventType
from live_chain_defense.pipeline import DefensePipeline
from live_chain_defense.store import InMemoryStore


class RedTeamBacktester:
    """Runs synthetic exploit scenarios and measures detection effectiveness."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self) -> BacktestResult:
        scenarios = self._build_scenarios()
        alerts_triggered = 0
        critical_alerts = 0
        latencies: list[float] = []
        prevented_usd = 0.0

        for scenario in scenarios:
            store = InMemoryStore()
            settings_copy = Settings(**self.settings.model_dump())
            pipeline = DefensePipeline(settings=settings_copy, store=store)

            attack_start = scenario["attack_start"]
            total_drain = scenario["total_drain_usd"]
            first_alert_time: datetime | None = None

            for event in scenario["events"]:
                result = pipeline.process_event(event)
                if result["alerted"]:
                    alerts_triggered += 1
                    if result["severity"] == "critical":
                        critical_alerts += 1
                    if first_alert_time is None:
                        first_alert_time = event.timestamp

            if first_alert_time is not None:
                latency = max(0.0, (first_alert_time - attack_start).total_seconds())
                latencies.append(latency)
                prevented_fraction = 0.75 if latency <= 20 else (0.45 if latency <= 60 else 0.2)
                prevented_usd += total_drain * prevented_fraction

        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        return BacktestResult(
            scenarios=len(scenarios),
            alerts_triggered=alerts_triggered,
            critical_alerts=critical_alerts,
            avg_detection_latency_seconds=round(avg_latency, 3),
            estimated_loss_prevented_usd=round(prevented_usd, 2),
        )

    def _build_scenarios(self) -> list[dict]:
        base_time = datetime.now(timezone.utc).replace(microsecond=0)

        scenario_a_events = [
            ChainEvent(
                chain="ethereum",
                timestamp=base_time,
                tx_hash="0xa1",
                from_address="0xTreasuryA",
                to_address="0xVendorA",
                amount_usd=40_000,
                event_type=EventType.transfer,
            ),
            ChainEvent(
                chain="ethereum",
                timestamp=base_time + timedelta(seconds=15),
                tx_hash="0xa2",
                from_address="0xTreasuryA",
                to_address="0xAttackerA",
                amount_usd=1_800_000,
                event_type=EventType.transfer,
            ),
            ChainEvent(
                chain="ethereum",
                timestamp=base_time + timedelta(seconds=30),
                tx_hash="0xa3",
                from_address="0xTreasuryA",
                to_address="0xAttackerB",
                amount_usd=2_400_000,
                event_type=EventType.transfer,
            ),
            ChainEvent(
                chain="ethereum",
                timestamp=base_time + timedelta(seconds=50),
                tx_hash="0xa4",
                from_address="0xAttackerB",
                to_address="0xBridge1",
                amount_usd=2_000_000,
                event_type=EventType.bridge,
                metadata={"bridge": True, "target_chain": "base", "target_address": "0xAttackerBase"},
            ),
        ]

        scenario_b_events = [
            ChainEvent(
                chain="arbitrum",
                timestamp=base_time + timedelta(minutes=5),
                tx_hash="0xb1",
                from_address="0xOpsWallet",
                to_address="0xRoutine",
                amount_usd=12_000,
                event_type=EventType.transfer,
            ),
            ChainEvent(
                chain="arbitrum",
                timestamp=base_time + timedelta(minutes=5, seconds=25),
                tx_hash="0xb2",
                from_address="0xOpsWallet",
                to_address="0xUnknown",
                amount_usd=1_000_000,
                event_type=EventType.transfer,
            ),
            ChainEvent(
                chain="arbitrum",
                timestamp=base_time + timedelta(minutes=5, seconds=40),
                tx_hash="0xb3",
                from_address="0xOpsWallet",
                to_address="0xUnknown2",
                amount_usd=900_000,
                event_type=EventType.transfer,
            ),
        ]

        return [
            {
                "attack_start": scenario_a_events[1].timestamp,
                "total_drain_usd": 4_200_000.0,
                "events": scenario_a_events,
            },
            {
                "attack_start": scenario_b_events[1].timestamp,
                "total_drain_usd": 1_900_000.0,
                "events": scenario_b_events,
            },
        ]
