from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from threading import RLock

from live_chain_defense.models import Alert, Incident, Severity


class InMemoryStore:
    """In-memory data store for local development and simulation."""

    def __init__(self, max_events: int = 5_000, max_alerts: int = 2_000) -> None:
        self._lock = RLock()
        self.events: deque[dict] = deque(maxlen=max_events)
        self.alerts: deque[Alert] = deque(maxlen=max_alerts)
        self.incidents: dict[str, Incident] = {}

    def add_event(self, event: dict) -> None:
        with self._lock:
            self.events.append(event)

    def add_alert(self, alert: Alert) -> Incident:
        with self._lock:
            self.alerts.append(alert)
            return self._upsert_incident(alert)

    def _upsert_incident(self, alert: Alert) -> Incident:
        key = alert.campaign_id or f"{alert.event.chain}:{alert.event.from_address.lower()}"
        incident = self.incidents.get(key)

        if incident is None:
            summary = f"Potential drain activity from {alert.event.from_address}"
            if alert.campaign_id:
                summary = f"Campaign {alert.campaign_id}: potential coordinated drain activity"

            incident = Incident(
                chain=alert.event.chain,
                campaign_id=alert.campaign_id,
                root_tx_hash=alert.event.tx_hash,
                summary=summary,
                max_severity=alert.severity,
            )
            self.incidents[key] = incident

        incident.alerts.append(alert)
        incident.updated_at = datetime.now(timezone.utc)
        incident.max_severity = _max_severity(incident.max_severity, alert.severity)
        incident.related_addresses = sorted(
            set(incident.related_addresses)
            | {alert.event.from_address.lower(), alert.event.to_address.lower()}
        )
        if alert.event.contract_address:
            incident.related_addresses = sorted(
                set(incident.related_addresses) | {alert.event.contract_address.lower()}
            )
        return incident

    def list_alerts(self, limit: int = 100) -> list[Alert]:
        with self._lock:
            return list(self.alerts)[-limit:][::-1]

    def list_incidents(self, active_within_hours: int = 24) -> list[Incident]:
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=active_within_hours)
            incidents = [i for i in self.incidents.values() if i.updated_at >= cutoff]
            return sorted(incidents, key=lambda i: i.updated_at, reverse=True)


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b
