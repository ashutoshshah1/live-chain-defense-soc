from datetime import datetime, timedelta, timezone

from live_chain_defense.intelligence.campaigns import CampaignCorrelator
from live_chain_defense.models import ChainEvent


def _event(chain: str, tx_hash: str, src: str, dst: str, ts: datetime) -> ChainEvent:
    return ChainEvent(
        chain=chain,
        timestamp=ts,
        tx_hash=tx_hash,
        from_address=src,
        to_address=dst,
        amount=1,
        amount_usd=1000,
    )


def test_campaign_stitches_related_events_across_chains() -> None:
    correlator = CampaignCorrelator(merge_window_seconds=7200)
    t0 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    first = correlator.assign(_event("ethereum", "0x1", "0xTreasury", "0xAttacker", t0))
    second = correlator.assign(_event("arbitrum", "0x2", "0xAttacker", "0xBridge", t0 + timedelta(minutes=3)))

    assert first["campaign_id"] == second["campaign_id"]
    assert second["chain_count"] == 2
    assert second["tx_count"] == 2


def test_campaign_expires_when_outside_merge_window() -> None:
    correlator = CampaignCorrelator(merge_window_seconds=30)
    t0 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    first = correlator.assign(_event("ethereum", "0x1", "0xA", "0xB", t0))
    second = correlator.assign(_event("ethereum", "0x2", "0xA", "0xC", t0 + timedelta(minutes=2)))

    assert first["campaign_id"] != second["campaign_id"]
