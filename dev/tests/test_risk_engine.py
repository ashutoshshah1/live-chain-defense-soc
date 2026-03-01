from datetime import datetime, timezone

from live_chain_defense.config import Settings
from live_chain_defense.detection.risk_engine import RiskEngine
from live_chain_defense.models import ChainEvent, EventType, Severity


def test_critical_score_on_large_burst_drain() -> None:
    settings = Settings(
        alert_score_threshold=65,
        large_transfer_usd=500_000,
        burst_tx_threshold=2,
        burst_window_seconds=120,
    )
    engine = RiskEngine(settings)

    e1 = ChainEvent(
        chain="ethereum",
        timestamp=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
        tx_hash="0x1",
        from_address="0xTreasury",
        to_address="0xA",
        contract_address="0xTreasuryContract",
        amount=1,
        amount_usd=1_000_000,
        event_type=EventType.transfer,
    )
    e2 = ChainEvent(
        chain="ethereum",
        timestamp=datetime(2026, 3, 1, 0, 0, 30, tzinfo=timezone.utc),
        tx_hash="0x2",
        from_address="0xTreasury",
        to_address="0xB",
        contract_address="0xTreasuryContract",
        amount=1,
        amount_usd=1_500_000,
        event_type=EventType.transfer,
    )

    first = engine.assess(
        e1,
        graph_signals={"new_counterparty_score": 1.0, "exposure_score": 0.0, "fanout_score": 0.0, "bridge_hop_score": 0.0},
    )
    second = engine.assess(
        e2,
        graph_signals={"new_counterparty_score": 1.0, "exposure_score": 0.5, "fanout_score": 0.2, "bridge_hop_score": 0.0},
    )

    assert first.score >= 20
    assert second.score >= 85
    assert second.severity == Severity.critical
    assert 0.0 <= second.confidence <= 1.0


def test_sequence_pattern_detected_for_approval_to_transfer() -> None:
    settings = Settings(large_transfer_usd=500_000, sequence_window_seconds=180)
    engine = RiskEngine(settings)

    approval = ChainEvent(
        chain="ethereum",
        timestamp=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
        tx_hash="0xapprove",
        from_address="0xVictim",
        to_address="0xMaliciousSpender",
        amount=1,
        amount_usd=300_000,
        event_type=EventType.approval,
    )
    transfer = ChainEvent(
        chain="ethereum",
        timestamp=datetime(2026, 3, 1, 0, 0, 45, tzinfo=timezone.utc),
        tx_hash="0xtransfer",
        from_address="0xVictim",
        to_address="0xAttacker",
        amount=1,
        amount_usd=900_000,
        event_type=EventType.transfer,
    )

    engine.assess(
        approval,
        graph_signals={"new_counterparty_score": 1.0, "exposure_score": 0.0, "fanout_score": 0.0, "bridge_hop_score": 0.0},
    )
    result = engine.assess(
        transfer,
        graph_signals={"new_counterparty_score": 1.0, "exposure_score": 0.0, "fanout_score": 0.0, "bridge_hop_score": 0.0},
    )

    assert result.signals.sequence_score >= 0.7
    assert any("sequence" in reason.lower() for reason in result.reasons)


def test_baseline_deviation_rises_after_normal_history() -> None:
    settings = Settings(large_transfer_usd=500_000, baseline_history_size=50)
    engine = RiskEngine(settings)
    graph = {"new_counterparty_score": 0.0, "exposure_score": 0.0, "fanout_score": 0.0, "bridge_hop_score": 0.0}

    for idx in range(6):
        normal = ChainEvent(
            chain="ethereum",
            timestamp=datetime(2026, 3, 1, 0, idx, 0, tzinfo=timezone.utc),
            tx_hash=f"0xnormal{idx}",
            from_address="0xOpsWallet",
            to_address="0xVendor",
            amount=1,
            amount_usd=10_000 + (idx * 100),
            event_type=EventType.transfer,
        )
        engine.assess(normal, graph_signals=graph)

    anomaly = ChainEvent(
        chain="ethereum",
        timestamp=datetime(2026, 3, 1, 0, 7, 0, tzinfo=timezone.utc),
        tx_hash="0xanomaly",
        from_address="0xOpsWallet",
        to_address="0xUnknown",
        amount=1,
        amount_usd=1_000_000,
        event_type=EventType.transfer,
    )
    result = engine.assess(anomaly, graph_signals=graph)

    assert result.signals.baseline_deviation_score >= 0.8
