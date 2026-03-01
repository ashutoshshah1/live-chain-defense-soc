from __future__ import annotations

from live_chain_defense.config import Settings
from live_chain_defense.detection.rules import AdaptiveBaselineState, RollingFlowState, SequencePatternState
from live_chain_defense.models import ChainEvent, RiskAssessment, RiskSignals, Severity


class RiskEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.flow_state = RollingFlowState(window_seconds=settings.burst_window_seconds)
        self.baseline_state = AdaptiveBaselineState(history_size=settings.baseline_history_size)
        self.sequence_state = SequencePatternState(
            window_seconds=settings.sequence_window_seconds,
            large_transfer_usd=settings.large_transfer_usd,
        )

    def assess(self, event: ChainEvent, graph_signals: dict[str, float]) -> RiskAssessment:
        reasons: list[str] = []

        flow_features = self.flow_state.update_and_get_features(event)
        baseline_features = self.baseline_state.update_and_get_features(event)
        sequence_features = self.sequence_state.update_and_get_features(event)

        amount_score = min(1.0, event.amount_usd / max(1.0, self.settings.large_transfer_usd))

        burst_score = 0.0
        if flow_features["window_tx_count"] >= self.settings.burst_tx_threshold:
            overflow = flow_features["window_tx_count"] - self.settings.burst_tx_threshold + 1
            burst_score = min(1.0, overflow / 3.0)

        flow_score = _clamp01((amount_score * 0.7) + (burst_score * 0.3))

        behavioral_score = 0.0
        if event.event_type.value == "approval" and event.amount_usd >= (self.settings.large_transfer_usd * 0.5):
            behavioral_score = max(behavioral_score, 0.8)
            reasons.append("Large approval event with drain potential")

        if event.event_type.value == "privileged_call" and (event.method or "") in self.settings.high_risk_methods:
            behavioral_score = max(behavioral_score, 0.9)
            reasons.append(f"High-risk privileged call: {event.method}")

        new_counterparty = graph_signals.get("new_counterparty_score", 0.0)
        exposure = graph_signals.get("exposure_score", 0.0)
        fanout = graph_signals.get("fanout_score", 0.0)
        bridge_hop = graph_signals.get("bridge_hop_score", 0.0)
        taint_score = graph_signals.get("taint_score", 0.0)
        entity_size_score = graph_signals.get("entity_size_score", 0.0)

        graph_score = _clamp01(
            (exposure * 0.35)
            + (fanout * 0.15)
            + (bridge_hop * 0.2)
            + (taint_score * 0.2)
            + (entity_size_score * 0.1)
        )

        sample_count = baseline_features["sample_count"]
        deviation_ratio = baseline_features["deviation_ratio"]
        if sample_count < 5:
            baseline_score = 0.0
        else:
            baseline_score = _clamp01((deviation_ratio - 1.0) / 4.0)

        sequence_score = float(sequence_features.get("sequence_score", 0.0))
        sequence_pattern = str(sequence_features.get("sequence_pattern", ""))

        context_score = 0.0
        if event.contract_address and event.contract_address.lower() in {
            c.lower() for c in self.settings.critical_contracts
        }:
            context_score = 1.0
            reasons.append("Critical contract involved")

        if amount_score >= 0.9:
            reasons.append("Very large transfer amount")

        if burst_score >= 0.6:
            reasons.append("High transfer burst velocity")

        if exposure >= 0.5:
            reasons.append("Destination connected to malicious cluster")

        if taint_score >= 0.5:
            reasons.append("Destination taint score is elevated")

        if new_counterparty >= 1.0 and amount_score >= 0.7:
            reasons.append("Large transfer to new counterparty")

        if bridge_hop >= 0.8:
            reasons.append("Rapid bridge-hop behavior")

        if baseline_score >= 0.8:
            reasons.append("Transfer sharply deviates from wallet baseline")

        if sequence_score >= 0.7:
            if sequence_pattern:
                reasons.append(f"High-risk sequence detected: {sequence_pattern}")
            else:
                reasons.append("High-risk transaction sequence detected")

        score = (
            (flow_score * 30)
            + (behavioral_score * 20)
            + (graph_score * 20)
            + (context_score * 10)
            + (baseline_score * 12)
            + (sequence_score * 8)
        )

        # Escalation logic to avoid under-classifying active drain sequences.
        window_total_usd = flow_features["window_total_usd"]
        if window_total_usd >= (self.settings.large_transfer_usd * 4):
            score += 20
            reasons.append("Abnormal short-window outflow concentration")

        if amount_score >= 1.0 and burst_score >= 0.3 and new_counterparty >= 1.0:
            score += 30
            reasons.append("Likely coordinated drain burst pattern")

        if exposure >= 0.5 and amount_score >= 1.0:
            score += 10
            reasons.append("High-value flow toward tainted cluster path")

        if taint_score >= 0.7 and amount_score >= 0.9:
            score += 10
            reasons.append("High taint destination with large value transfer")

        if sequence_score >= 0.8 and amount_score >= 1.0:
            score += 12
            reasons.append("Sequence and amount jointly indicate active exploitation")

        if bridge_hop >= 0.8 and exposure >= 0.5:
            score += 10
            reasons.append("Bridge laundering pattern toward risky cluster")

        score = round(min(100.0, score), 2)
        severity = _severity_from_score(score)

        confidence = _compute_confidence(
            amount_score=amount_score,
            burst_score=burst_score,
            exposure=exposure,
            taint_score=taint_score,
            sequence_score=sequence_score,
            baseline_score=baseline_score,
            sample_count=sample_count,
            has_contract=bool(event.contract_address),
        )

        signals = RiskSignals(
            flow_score=round(flow_score, 4),
            behavioral_score=round(behavioral_score, 4),
            graph_score=round(graph_score, 4),
            context_score=round(context_score, 4),
            baseline_deviation_score=round(baseline_score, 4),
            sequence_score=round(sequence_score, 4),
            amount_score=round(amount_score, 4),
            burst_score=round(burst_score, 4),
            new_counterparty_score=round(new_counterparty, 4),
            exposure_score=round(exposure, 4),
            confidence=round(confidence, 4),
        )

        if not reasons:
            reasons.append("No major anomaly detected")

        return RiskAssessment(
            score=score,
            severity=severity,
            confidence=round(confidence, 4),
            reasons=reasons,
            signals=signals,
        )


def _severity_from_score(score: float) -> Severity:
    if score >= 85:
        return Severity.critical
    if score >= 65:
        return Severity.high
    if score >= 40:
        return Severity.medium
    return Severity.low


def _compute_confidence(
    *,
    amount_score: float,
    burst_score: float,
    exposure: float,
    taint_score: float,
    sequence_score: float,
    baseline_score: float,
    sample_count: float,
    has_contract: bool,
) -> float:
    strong_signals = sum(
        [
            1 if amount_score >= 0.9 else 0,
            1 if burst_score >= 0.3 else 0,
            1 if exposure >= 0.5 else 0,
            1 if taint_score >= 0.5 else 0,
            1 if sequence_score >= 0.7 else 0,
            1 if baseline_score >= 0.6 else 0,
        ]
    )

    confidence = 0.3 + (strong_signals * 0.1)
    if sample_count >= 10:
        confidence += 0.1
    if has_contract:
        confidence += 0.08

    return _clamp01(confidence)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))
