from __future__ import annotations

from statistics import mean

from live_chain_defense.config import Settings
from live_chain_defense.models import ServiceSLOSnapshot


class SLOMonitor:
    """Tracks pipeline latency and uptime/failover metrics."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.processed_events = 0
        self.preconfirm_events = 0
        self.latency_ms_samples: list[float] = []
        self.total_runtime_seconds = 0.0
        self.total_downtime_seconds = 0.0
        self.failover_drills: list[dict] = []

    def record_confirmed(self, latency_ms: float) -> None:
        self.processed_events += 1
        self.latency_ms_samples.append(latency_ms)
        self.total_runtime_seconds += max(0.001, latency_ms / 1000.0)

    def record_preconfirm(self, latency_ms: float) -> None:
        self.preconfirm_events += 1
        self.latency_ms_samples.append(latency_ms)
        self.total_runtime_seconds += max(0.001, latency_ms / 1000.0)

    def register_outage(self, seconds: float) -> None:
        self.total_downtime_seconds += max(0.0, seconds)

    def run_failover_drill(self) -> dict:
        drill = {
            "drill_id": f"drill-{len(self.failover_drills)+1}",
            "simulated_rto_seconds": 8.5,
            "simulated_rpo_seconds": 1.2,
            "passed": True,
        }
        self.failover_drills.append(drill)
        return drill

    def snapshot(self) -> ServiceSLOSnapshot:
        uptime_ratio = 1.0
        total = self.total_runtime_seconds + self.total_downtime_seconds
        if total > 0:
            uptime_ratio = max(0.0, 1.0 - (self.total_downtime_seconds / total))

        avg_latency = mean(self.latency_ms_samples) if self.latency_ms_samples else 0.0

        return ServiceSLOSnapshot(
            processed_events=self.processed_events,
            preconfirm_events=self.preconfirm_events,
            avg_pipeline_latency_ms=round(avg_latency, 3),
            uptime_ratio=round(uptime_ratio, 6),
            target_uptime_ratio=self.settings.slo_target_uptime_ratio,
            target_latency_ms=self.settings.slo_target_latency_ms,
        )

    def status(self) -> dict:
        snap = self.snapshot()
        return {
            **snap.model_dump(mode="json"),
            "latency_target_met": snap.avg_pipeline_latency_ms <= snap.target_latency_ms,
            "uptime_target_met": snap.uptime_ratio >= snap.target_uptime_ratio,
            "failover_drills": len(self.failover_drills),
        }

    def recent_failover_drills(self, limit: int = 50) -> list[dict]:
        return self.failover_drills[-limit:][::-1]
