from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from live_chain_defense.config import Settings
from live_chain_defense.models import PendingTx, PreconfirmAssessment, Severity


class PreconfirmationSentinel:
    """Scores pending transactions before block confirmation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.pending_by_sender: dict[str, deque[tuple]] = defaultdict(deque)

    def assess(self, pending_tx: PendingTx, destination_taint: float = 0.0) -> PreconfirmAssessment:
        sender = pending_tx.from_address.lower()
        bucket = self.pending_by_sender[sender]

        bucket.append((pending_tx.seen_at, pending_tx.value_usd))
        cutoff = pending_tx.seen_at - timedelta(seconds=90)
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        burst = len(bucket)
        amount_score = min(1.0, pending_tx.value_usd / max(1.0, self.settings.large_transfer_usd))
        burst_score = min(1.0, max(0, burst - 1) / 3.0)

        high_risk_method = (pending_tx.method or "") in self.settings.high_risk_methods
        method_score = 1.0 if high_risk_method else 0.0

        gas_score = 1.0 if pending_tx.gas_price_gwei >= 100 else (0.6 if pending_tx.gas_price_gwei >= 50 else 0.0)

        score = (
            (amount_score * 55)
            + (burst_score * 5)
            + (method_score * 10)
            + (destination_taint * 20)
            + (gas_score * 10)
        )
        score = round(min(100.0, score), 2)

        reasons: list[str] = []
        if amount_score >= 0.9:
            reasons.append("Large pending value transfer")
        if burst_score >= 0.5:
            reasons.append("Burst of pending transactions from sender")
        if method_score > 0:
            reasons.append(f"High-risk pending method: {pending_tx.method}")
        if destination_taint >= 0.5:
            reasons.append("Pending destination is tainted")
        if gas_score >= 0.6:
            reasons.append("High gas priority indicates urgency/racing")
        if not reasons:
            reasons.append("No critical pre-confirmation anomaly")

        confidence = 0.35 + (0.15 if amount_score >= 0.9 else 0) + (0.1 if burst_score >= 0.5 else 0)
        confidence += 0.1 if method_score > 0 else 0
        confidence += 0.1 if destination_taint >= 0.5 else 0
        confidence = min(0.98, round(confidence, 4))

        return PreconfirmAssessment(
            risk_score=score,
            severity=_severity_from_score(score),
            confidence=confidence,
            reasons=reasons,
            pending_tx=pending_tx,
        )


def _severity_from_score(score: float) -> Severity:
    if score >= 85:
        return Severity.critical
    if score >= 65:
        return Severity.high
    if score >= 40:
        return Severity.medium
    return Severity.low
