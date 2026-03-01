from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EventType(str, Enum):
    transfer = "transfer"
    approval = "approval"
    privileged_call = "privileged_call"
    bridge = "bridge"
    pending_tx = "pending_tx"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ChainEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    chain: str = Field(min_length=1, max_length=64)
    timestamp: datetime = Field(default_factory=utc_now)
    block_number: int | None = None
    tx_hash: str = Field(min_length=1, max_length=256)
    from_address: str = Field(min_length=1, max_length=128)
    to_address: str = Field(min_length=1, max_length=128)
    contract_address: str | None = None
    method: str | None = None
    asset_symbol: str = "UNKNOWN"
    amount: float = 0.0
    amount_usd: float = 0.0
    event_type: EventType = EventType.transfer
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskSignals(BaseModel):
    flow_score: float = 0.0
    behavioral_score: float = 0.0
    graph_score: float = 0.0
    context_score: float = 0.0
    baseline_deviation_score: float = 0.0
    sequence_score: float = 0.0
    amount_score: float = 0.0
    burst_score: float = 0.0
    new_counterparty_score: float = 0.0
    exposure_score: float = 0.0
    confidence: float = 0.0


class RiskAssessment(BaseModel):
    score: float
    severity: Severity
    confidence: float
    reasons: list[str] = Field(default_factory=list)
    signals: RiskSignals


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    severity: Severity
    risk_score: float
    confidence: float = 0.0
    campaign_id: str | None = None
    message: str
    event: ChainEvent
    reasons: list[str] = Field(default_factory=list)


class ActionStatus(str, Enum):
    suggested = "suggested"
    executed = "executed"
    failed = "failed"


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    action_type: str
    status: ActionStatus = ActionStatus.suggested
    description: str
    payload: dict[str, Any] = Field(default_factory=dict)


class IncidentStatus(str, Enum):
    open = "open"
    monitoring = "monitoring"
    closed = "closed"


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    opened_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    status: IncidentStatus = IncidentStatus.open
    chain: str
    campaign_id: str | None = None
    root_tx_hash: str
    summary: str
    max_severity: Severity
    related_addresses: list[str] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    actions: list[ResponseAction] = Field(default_factory=list)


class PendingTx(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    pending_id: str = Field(default_factory=lambda: str(uuid4()))
    chain: str = Field(min_length=1, max_length=64)
    seen_at: datetime = Field(default_factory=utc_now)
    tx_hash: str = Field(min_length=1, max_length=256)
    from_address: str = Field(min_length=1, max_length=128)
    to_address: str = Field(min_length=1, max_length=128)
    method: str | None = None
    value_usd: float = 0.0
    gas_price_gwei: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PreconfirmAssessment(BaseModel):
    risk_score: float
    severity: Severity
    confidence: float
    reasons: list[str] = Field(default_factory=list)
    pending_tx: PendingTx


class RelayMode(str, Enum):
    public_mempool = "public_mempool"
    private_relay = "private_relay"
    bundle = "bundle"


class GuardedExecutionResult(BaseModel):
    action_id: str
    allowed: bool
    mode: RelayMode
    reason: str
    relay_submission_id: str | None = None


class LabelVerdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    uncertain = "uncertain"


class AnalystLabel(BaseModel):
    label_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    alert_id: str
    verdict: LabelVerdict
    notes: str = ""


class BacktestResult(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    scenarios: int
    alerts_triggered: int
    critical_alerts: int
    avg_detection_latency_seconds: float
    estimated_loss_prevented_usd: float


class ServiceSLOSnapshot(BaseModel):
    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    processed_events: int
    preconfirm_events: int
    avg_pipeline_latency_ms: float
    uptime_ratio: float
    target_uptime_ratio: float = 0.999
    target_latency_ms: float = 10_000.0


class NotificationProvider(str, Enum):
    in_app = "in_app"
    slack = "slack"
    pagerduty = "pagerduty"
    telegram = "telegram"
    email = "email"
    webhook = "webhook"


class NotificationChannel(BaseModel):
    channel_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    provider: NotificationProvider
    destination: str = Field(min_length=1, max_length=256)
    min_severity: Severity = Severity.high
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class NotificationDispatch(BaseModel):
    dispatch_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utc_now)
    channel_id: str
    provider: NotificationProvider
    destination: str
    severity: Severity
    message: str
    risk_score: float
    campaign_id: str | None = None
    tx_hash: str = ""
    chain: str = ""
    status: str = "queued"
