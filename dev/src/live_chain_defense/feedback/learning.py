from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from live_chain_defense.config import Settings
from live_chain_defense.models import Alert, AnalystLabel, LabelVerdict


class AnalystFeedbackLoop:
    """Stores analyst labels and recalibrates thresholds."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.labels: list[AnalystLabel] = []
        self.recalibration_history: list[dict] = []

    def add_label(self, alert_id: str, verdict: LabelVerdict, notes: str = "") -> AnalystLabel:
        label = AnalystLabel(alert_id=alert_id, verdict=verdict, notes=notes)
        self.labels.append(label)
        return label

    def summary(self) -> dict:
        counts = Counter(label.verdict.value for label in self.labels)
        total = len(self.labels)
        precision_proxy = (counts.get(LabelVerdict.true_positive.value, 0) / total) if total else 0.0
        return {
            "labels_total": total,
            "counts": dict(counts),
            "precision_proxy": round(precision_proxy, 4),
            "recalibrations": len(self.recalibration_history),
        }

    def recalibrate_weekly(self, recent_alerts: list[Alert]) -> dict:
        now = datetime.now(timezone.utc)
        old_threshold = self.settings.alert_score_threshold

        if len(self.labels) < self.settings.weekly_recalibration_min_labels:
            outcome = {
                "updated": False,
                "reason": "insufficient_labels",
                "labels": len(self.labels),
                "threshold": old_threshold,
                "timestamp": now.isoformat(),
            }
            self.recalibration_history.append(outcome)
            return outcome

        counts = Counter(label.verdict for label in self.labels)
        tp = counts.get(LabelVerdict.true_positive, 0)
        fp = counts.get(LabelVerdict.false_positive, 0)
        total_labeled = max(1, tp + fp)
        precision = tp / total_labeled

        new_threshold = old_threshold
        if precision < 0.65:
            new_threshold = min(90.0, old_threshold + 5.0)
        elif precision > 0.85 and any(alert.severity.value == "critical" for alert in recent_alerts):
            new_threshold = max(50.0, old_threshold - 3.0)

        self.settings.alert_score_threshold = round(new_threshold, 2)

        outcome = {
            "updated": round(new_threshold, 2) != round(old_threshold, 2),
            "old_threshold": round(old_threshold, 2),
            "new_threshold": round(new_threshold, 2),
            "precision_proxy": round(precision, 4),
            "labeled_count": len(self.labels),
            "timestamp": now.isoformat(),
        }
        self.recalibration_history.append(outcome)
        return outcome

    def recent_labels(self, limit: int = 200) -> list[AnalystLabel]:
        return self.labels[-limit:][::-1]
