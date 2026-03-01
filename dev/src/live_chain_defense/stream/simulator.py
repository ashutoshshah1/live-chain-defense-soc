from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from live_chain_defense.models import ChainEvent, EventType, PendingTx


def load_events_from_jsonl(path: str | Path) -> list[ChainEvent]:
    events: list[ChainEvent] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            events.append(ChainEvent(**payload))
    return events


def load_pending_from_jsonl(path: str | Path) -> list[PendingTx]:
    pending_txs: list[PendingTx] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            pending_txs.append(PendingTx(**payload))
    return pending_txs


def generate_sample_attack_scenario() -> list[ChainEvent]:
    now = datetime.now(timezone.utc)
    base = "0xTreasury"
    attacker = "0xAttackerA"
    mule = "0xMuleB"
    bridge = "0xBridgeC"

    events = [
        ChainEvent(
            chain="ethereum",
            timestamp=now,
            tx_hash="0xnormal1",
            from_address=base,
            to_address="0xMarketMaker",
            contract_address="0xTreasuryContract",
            amount=20,
            amount_usd=50_000,
            asset_symbol="ETH",
            event_type=EventType.transfer,
        ),
        ChainEvent(
            chain="ethereum",
            timestamp=now + timedelta(seconds=7),
            tx_hash="0xnormal2",
            from_address=base,
            to_address="0xVendor",
            contract_address="0xTreasuryContract",
            amount=35,
            amount_usd=80_000,
            asset_symbol="ETH",
            event_type=EventType.transfer,
        ),
        ChainEvent(
            chain="ethereum",
            timestamp=now + timedelta(seconds=20),
            tx_hash="0xdrain1",
            from_address=base,
            to_address=attacker,
            contract_address="0xTreasuryContract",
            method="transfer",
            amount=900,
            amount_usd=2_300_000,
            asset_symbol="ETH",
            event_type=EventType.transfer,
        ),
        ChainEvent(
            chain="ethereum",
            timestamp=now + timedelta(seconds=31),
            tx_hash="0xdrain2",
            from_address=base,
            to_address=attacker,
            contract_address="0xTreasuryContract",
            method="transfer",
            amount=700,
            amount_usd=1_700_000,
            asset_symbol="ETH",
            event_type=EventType.transfer,
        ),
        ChainEvent(
            chain="ethereum",
            timestamp=now + timedelta(seconds=45),
            tx_hash="0xdrain3",
            from_address=attacker,
            to_address=mule,
            contract_address="0xToken",
            method="transfer",
            amount=1500,
            amount_usd=3_900_000,
            asset_symbol="USDC",
            event_type=EventType.transfer,
        ),
        ChainEvent(
            chain="ethereum",
            timestamp=now + timedelta(seconds=65),
            tx_hash="0xbridge1",
            from_address=attacker,
            to_address=bridge,
            contract_address="0xBridgeContract",
            method="bridgeOut",
            amount=1200,
            amount_usd=3_100_000,
            asset_symbol="USDC",
            event_type=EventType.bridge,
            metadata={"bridge": True, "target_chain": "arbitrum"},
        ),
    ]
    return events


def generate_sample_mempool_scenario() -> list[PendingTx]:
    now = datetime.now(timezone.utc)
    return [
        PendingTx(
            chain="ethereum",
            seen_at=now,
            tx_hash="0xpend1",
            from_address="0xTreasury",
            to_address="0xVendor",
            method="transfer",
            value_usd=30_000,
            gas_price_gwei=20,
        ),
        PendingTx(
            chain="ethereum",
            seen_at=now + timedelta(seconds=8),
            tx_hash="0xpend2",
            from_address="0xTreasury",
            to_address="0xAttackerA",
            method="transfer",
            value_usd=1_600_000,
            gas_price_gwei=120,
            metadata={"note": "suspicious large pending transfer"},
        ),
        PendingTx(
            chain="ethereum",
            seen_at=now + timedelta(seconds=12),
            tx_hash="0xpend3",
            from_address="0xTreasury",
            to_address="0xAttackerA",
            method="transfer",
            value_usd=1_400_000,
            gas_price_gwei=130,
        ),
    ]
