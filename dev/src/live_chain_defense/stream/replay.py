from __future__ import annotations

import hashlib
from collections import defaultdict

from live_chain_defense.models import ChainEvent, PendingTx


class ReplaySafetyManager:
    """Deduplicates events and detects simple same-height reorgs."""

    def __init__(self, confirmation_depth: int = 6, dedup_enabled: bool = True) -> None:
        self.confirmation_depth = confirmation_depth
        self.dedup_enabled = dedup_enabled
        self.seen_event_ids: set[str] = set()
        self.seen_pending_ids: set[str] = set()
        self.chain_block_hash: dict[str, dict[int, str]] = defaultdict(dict)
        self.reorg_events: list[dict] = []
        self.duplicate_events = 0

    def ingest_confirmed(self, event: ChainEvent) -> dict:
        canonical_id = canonical_event_id(event)

        if self.dedup_enabled and canonical_id in self.seen_event_ids:
            self.duplicate_events += 1
            return {
                "accepted": False,
                "canonical_event_id": canonical_id,
                "reason": "duplicate_confirmed_event",
                "reorg_detected": False,
            }

        reorg_detected = False
        if event.block_number is not None:
            block_hash = str(event.metadata.get("block_hash", ""))
            if block_hash:
                chain_map = self.chain_block_hash[event.chain]
                previous = chain_map.get(event.block_number)
                if previous and previous != block_hash:
                    reorg_detected = True
                    self.reorg_events.append(
                        {
                            "chain": event.chain,
                            "block_number": event.block_number,
                            "old_hash": previous,
                            "new_hash": block_hash,
                            "tx_hash": event.tx_hash,
                        }
                    )
                chain_map[event.block_number] = block_hash
                self._trim_old_blocks(chain_map, event.block_number)

        self.seen_event_ids.add(canonical_id)
        return {
            "accepted": True,
            "canonical_event_id": canonical_id,
            "reason": "accepted",
            "reorg_detected": reorg_detected,
        }

    def ingest_pending(self, pending_tx: PendingTx) -> dict:
        pending_id = canonical_pending_id(pending_tx)
        if self.dedup_enabled and pending_id in self.seen_pending_ids:
            return {
                "accepted": False,
                "canonical_pending_id": pending_id,
                "reason": "duplicate_pending_tx",
            }

        self.seen_pending_ids.add(pending_id)
        return {
            "accepted": True,
            "canonical_pending_id": pending_id,
            "reason": "accepted",
        }

    def list_recent_reorgs(self, limit: int = 100) -> list[dict]:
        return self.reorg_events[-limit:][::-1]

    def stats(self) -> dict:
        return {
            "seen_confirmed": len(self.seen_event_ids),
            "seen_pending": len(self.seen_pending_ids),
            "duplicates": self.duplicate_events,
            "reorg_count": len(self.reorg_events),
        }

    def _trim_old_blocks(self, chain_map: dict[int, str], latest_block: int) -> None:
        min_keep = max(0, latest_block - (self.confirmation_depth * 4))
        stale = [height for height in chain_map if height < min_keep]
        for height in stale:
            del chain_map[height]


def canonical_event_id(event: ChainEvent) -> str:
    raw = "|".join(
        [
            event.chain.lower(),
            str(event.block_number or 0),
            event.tx_hash.lower(),
            str(event.metadata.get("log_index", 0)),
            event.from_address.lower(),
            event.to_address.lower(),
            (event.method or "").lower(),
            event.event_type.value,
            f"{event.amount_usd:.6f}",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def canonical_pending_id(pending_tx: PendingTx) -> str:
    raw = "|".join(
        [
            pending_tx.chain.lower(),
            pending_tx.tx_hash.lower(),
            pending_tx.from_address.lower(),
            pending_tx.to_address.lower(),
            (pending_tx.method or "").lower(),
            f"{pending_tx.value_usd:.6f}",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
