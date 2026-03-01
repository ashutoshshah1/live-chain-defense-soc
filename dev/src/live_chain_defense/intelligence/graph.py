from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from live_chain_defense.models import ChainEvent


class AddressGraphIntel:
    """Tracks value-flow graph and computes fast exposure/novelty signals."""

    def __init__(self, malicious_seeds: set[str] | None = None) -> None:
        self.out_neighbors: dict[str, set[str]] = defaultdict(set)
        self.in_neighbors: dict[str, set[str]] = defaultdict(set)
        self.last_seen: dict[str, datetime] = {}
        self.last_outflow: dict[str, datetime] = {}
        self.malicious_seeds = {a.lower() for a in (malicious_seeds or set())}

    def add_malicious_seed(self, address: str) -> None:
        self.malicious_seeds.add(address.lower())

    def remove_malicious_seed(self, address: str) -> None:
        self.malicious_seeds.discard(address.lower())

    def list_malicious_seeds(self) -> list[str]:
        return sorted(self.malicious_seeds)

    def preview_signals(self, event: ChainEvent) -> dict[str, float]:
        src = event.from_address.lower()
        dst = event.to_address.lower()

        is_new_counterparty = dst not in self.out_neighbors[src]
        new_counterparty_score = 1.0 if is_new_counterparty else 0.0

        fanout = len(self.out_neighbors[src])
        fanout_score = min(1.0, fanout / 10.0)

        exposure_score = self._exposure_score(dst)

        bridge_hop_score = 0.0
        if event.event_type.value == "bridge" or event.metadata.get("bridge", False):
            last = self.last_outflow.get(src)
            if last is not None:
                if event.timestamp - last < timedelta(minutes=5):
                    bridge_hop_score = 1.0
                else:
                    bridge_hop_score = 0.4
            else:
                bridge_hop_score = 0.4

        return {
            "new_counterparty_score": new_counterparty_score,
            "fanout_score": fanout_score,
            "exposure_score": exposure_score,
            "bridge_hop_score": bridge_hop_score,
        }

    def ingest(self, event: ChainEvent) -> None:
        src = event.from_address.lower()
        dst = event.to_address.lower()
        ts = event.timestamp

        self.out_neighbors[src].add(dst)
        self.in_neighbors[dst].add(src)
        self.last_seen[src] = ts
        self.last_seen[dst] = ts
        self.last_outflow[src] = ts

    def _exposure_score(self, address: str, max_depth: int = 3) -> float:
        start = address.lower()
        if start in self.malicious_seeds:
            return 1.0

        # BFS over undirected neighborhood. Nearer malicious connections imply higher risk.
        visited = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])

        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue

            neighbors = self.out_neighbors[node] | self.in_neighbors[node]
            for nxt in neighbors:
                if nxt in visited:
                    continue
                if nxt in self.malicious_seeds:
                    distance = depth + 1
                    return max(0.2, 1.0 - (distance * 0.25))
                visited.add(nxt)
                queue.append((nxt, depth + 1))

        return 0.0
