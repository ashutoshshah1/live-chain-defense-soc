from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from statistics import median

from live_chain_defense.models import ChainEvent


class RollingFlowState:
    """Maintains short-window transfer state for burst and velocity signals."""

    def __init__(self, window_seconds: int) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.address_events: dict[str, deque[tuple]] = defaultdict(deque)

    def update_and_get_features(self, event: ChainEvent) -> dict[str, float]:
        key = event.from_address.lower()
        bucket = self.address_events[key]
        now = event.timestamp

        bucket.append((now, event.amount_usd))

        cutoff = now - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        tx_count = len(bucket)
        total_usd = float(sum(amount for _, amount in bucket))
        avg_usd = total_usd / tx_count if tx_count else 0.0

        return {
            "window_tx_count": float(tx_count),
            "window_total_usd": total_usd,
            "window_avg_usd": avg_usd,
        }


class AdaptiveBaselineState:
    """Tracks per-address historical transfer sizes for deviation scoring."""

    def __init__(self, history_size: int = 60) -> None:
        self.history_size = history_size
        self.amount_history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=history_size))

    def update_and_get_features(self, event: ChainEvent) -> dict[str, float]:
        key = event.from_address.lower()
        history = self.amount_history[key]

        sample_count = len(history)
        baseline_median = float(median(history)) if history else 0.0

        if sample_count < 5 or baseline_median <= 0:
            deviation_ratio = 1.0
        else:
            deviation_ratio = event.amount_usd / baseline_median

        history.append(event.amount_usd)

        return {
            "sample_count": float(sample_count),
            "baseline_median_usd": baseline_median,
            "deviation_ratio": deviation_ratio,
        }


class SequencePatternState:
    """Detects short-window attack sequences such as approval->drain."""

    def __init__(self, window_seconds: int = 180, large_transfer_usd: float = 500_000.0) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.large_transfer_usd = large_transfer_usd
        self.recent_events: dict[str, deque[tuple]] = defaultdict(deque)

    def update_and_get_features(self, event: ChainEvent) -> dict[str, float | str]:
        key = event.from_address.lower()
        now = event.timestamp
        bucket = self.recent_events[key]

        cutoff = now - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        score = 0.0
        pattern = ""

        for ts, event_type, amount_usd, method in bucket:
            elapsed = (now - ts).total_seconds()
            if elapsed < 0:
                continue

            if (
                event.event_type.value == "transfer"
                and event_type == "approval"
                and event.amount_usd >= (self.large_transfer_usd * 0.5)
            ):
                score = max(score, 0.8)
                pattern = "approval_to_transfer"

            if (
                event.event_type.value == "transfer"
                and event_type == "privileged_call"
                and event.amount_usd >= (self.large_transfer_usd * 0.7)
            ):
                if method:
                    pattern = f"privileged_call_to_transfer:{method}"
                else:
                    pattern = "privileged_call_to_transfer"
                score = max(score, 1.0)

        bucket.append((now, event.event_type.value, event.amount_usd, event.method))

        return {
            "sequence_score": score,
            "sequence_pattern": pattern,
        }
