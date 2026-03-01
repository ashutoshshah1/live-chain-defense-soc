from __future__ import annotations

from collections import defaultdict

from live_chain_defense.models import ChainEvent


class CrossChainEntityIntel:
    """Entity clustering + taint propagation across chains and bridge flows."""

    def __init__(self, malicious_seeds: set[str] | None = None) -> None:
        self.parent: dict[str, str] = {}
        self.size: dict[str, int] = {}
        self.taint: dict[str, float] = defaultdict(float)
        self.bridge_links: list[dict] = []

        for seed in malicious_seeds or set():
            addr = seed.lower()
            self.parent[addr] = addr
            self.size[addr] = 1
            self.taint[addr] = 1.0

    def ingest(self, event: ChainEvent) -> dict[str, float]:
        src = event.from_address.lower()
        dst = event.to_address.lower()
        self._ensure(src)
        self._ensure(dst)

        # Direct interaction slightly links entities; strong link if metadata marks it.
        if event.metadata.get("same_entity_hint"):
            self._union(src, dst)

        bridge_score = 0.0
        if event.event_type.value == "bridge" or event.metadata.get("bridge", False):
            bridge_score = 1.0
            target = str(event.metadata.get("target_address", "")).lower() or dst
            self._ensure(target)
            self._union(dst, target)
            self.bridge_links.append(
                {
                    "from_chain": event.chain,
                    "to_chain": str(event.metadata.get("target_chain", "unknown")),
                    "source": src,
                    "bridge": dst,
                    "target": target,
                    "tx_hash": event.tx_hash,
                }
            )

        propagated = self._propagate_taint(src, dst, amount_usd=event.amount_usd)
        taint_dst = self.taint[dst]

        entity_root = self._find(dst)
        entity_size = float(self.size[self._find(entity_root)])

        return {
            "taint_score": round(min(1.0, taint_dst), 4),
            "taint_delta": round(propagated, 4),
            "entity_size_score": round(min(1.0, entity_size / 20.0), 4),
            "bridge_entity_score": bridge_score,
        }

    def cluster_of(self, address: str) -> list[str]:
        root = self._find(address.lower())
        members = [addr for addr in self.parent if self._find(addr) == root]
        return sorted(members)

    def list_bridge_links(self, limit: int = 100) -> list[dict]:
        return self.bridge_links[-limit:][::-1]

    def _propagate_taint(self, src: str, dst: str, amount_usd: float) -> float:
        src_taint = self.taint[src]
        if src_taint <= 0:
            return 0.0

        decay = 0.85 if amount_usd >= 50_000 else 0.65
        new_taint = max(self.taint[dst], src_taint * decay)
        delta = max(0.0, new_taint - self.taint[dst])
        self.taint[dst] = new_taint
        return delta

    def _ensure(self, address: str) -> None:
        if address not in self.parent:
            self.parent[address] = address
            self.size[address] = 1

    def _find(self, address: str) -> str:
        self._ensure(address)
        if self.parent[address] != address:
            self.parent[address] = self._find(self.parent[address])
        return self.parent[address]

    def _union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        self.taint[ra] = max(self.taint[ra], self.taint[rb])
