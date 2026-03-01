from datetime import datetime, timezone

from live_chain_defense.intelligence.graph import AddressGraphIntel
from live_chain_defense.models import ChainEvent


def _event(tx_hash: str, src: str, dst: str) -> ChainEvent:
    return ChainEvent(
        chain="ethereum",
        timestamp=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
        tx_hash=tx_hash,
        from_address=src,
        to_address=dst,
        amount=1,
        amount_usd=1000,
    )


def test_exposure_score_detects_proximity_to_seed() -> None:
    intel = AddressGraphIntel(malicious_seeds={"0xseed"})
    intel.ingest(_event("0x1", "0xA", "0xB"))
    intel.ingest(_event("0x2", "0xB", "0xseed"))

    signals = intel.preview_signals(_event("0x3", "0xTreasury", "0xA"))
    assert signals["exposure_score"] > 0.0


def test_new_counterparty_signal() -> None:
    intel = AddressGraphIntel()
    e1 = _event("0x1", "0xS", "0xD")

    first = intel.preview_signals(e1)
    assert first["new_counterparty_score"] == 1.0

    intel.ingest(e1)
    second = intel.preview_signals(_event("0x2", "0xS", "0xD"))
    assert second["new_counterparty_score"] == 0.0
