from datetime import datetime, timezone

from live_chain_defense.config import Settings
from live_chain_defense.models import ChainEvent, EventType, PendingTx
from live_chain_defense.stream.mempool import PreconfirmationSentinel
from live_chain_defense.stream.replay import ReplaySafetyManager


def test_replay_dedup_and_reorg_detection() -> None:
    replay = ReplaySafetyManager(confirmation_depth=6, dedup_enabled=True)

    e1 = ChainEvent(
        chain="ethereum",
        block_number=123,
        tx_hash="0xabc",
        from_address="0xA",
        to_address="0xB",
        amount_usd=1000,
        event_type=EventType.transfer,
        metadata={"block_hash": "0xblock1", "log_index": 1},
        timestamp=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    e2 = e1.model_copy(update={"metadata": {"block_hash": "0xblock2", "log_index": 2}, "tx_hash": "0xdef"})

    r1 = replay.ingest_confirmed(e1)
    assert r1["accepted"] is True

    duplicate = replay.ingest_confirmed(e1)
    assert duplicate["accepted"] is False

    r2 = replay.ingest_confirmed(e2)
    assert r2["reorg_detected"] is True
    assert len(replay.list_recent_reorgs()) == 1


def test_mempool_high_risk_pending_tx() -> None:
    sentinel = PreconfirmationSentinel(Settings(large_transfer_usd=500_000))

    pending = PendingTx(
        chain="ethereum",
        tx_hash="0xpend",
        from_address="0xTreasury",
        to_address="0xAttacker",
        method="transfer",
        value_usd=1_500_000,
        gas_price_gwei=140,
    )

    assessment = sentinel.assess(pending, destination_taint=0.8)
    assert assessment.risk_score >= 65
    assert assessment.severity.value in {"high", "critical"}
