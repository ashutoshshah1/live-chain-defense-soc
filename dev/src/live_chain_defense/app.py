from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from live_chain_defense.config import Settings, settings
from live_chain_defense.models import ChainEvent, LabelVerdict, NotificationProvider, PendingTx, Severity
from live_chain_defense.pipeline import DefensePipeline
from live_chain_defense.security import SecurityOptions, install_security_middlewares
from live_chain_defense.store import InMemoryStore
from live_chain_defense.stream.simulator import (
    generate_sample_attack_scenario,
    generate_sample_mempool_scenario,
    load_events_from_jsonl,
    load_pending_from_jsonl,
)


logger = logging.getLogger("live_chain_defense.api")


class SimulationRequest(BaseModel):
    source: str = Field(default="generated", description="generated or jsonl path")
    path: str | None = Field(default=None)


class LabelRequest(BaseModel):
    verdict: LabelVerdict
    notes: str = ""


class OutageRequest(BaseModel):
    seconds: float = Field(ge=0, description="simulated outage duration")


class MempoolSimulationRequest(BaseModel):
    source: str = Field(default="generated", description="generated or jsonl path")
    path: str | None = Field(default=None)


class NotificationChannelRequest(BaseModel):
    provider: NotificationProvider = NotificationProvider.in_app
    destination: str = Field(min_length=1, max_length=256)
    min_severity: Severity = Severity.high
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class NotificationTestRequest(BaseModel):
    channel_id: str | None = None
    message: str = Field(default="Test notification from Live Chain Defense", min_length=1, max_length=512)


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    cfg = custom_settings or settings

    docs_enabled = cfg.enable_docs and cfg.environment != "production"
    openapi_enabled = cfg.enable_openapi and cfg.environment != "production"

    app = FastAPI(
        title=cfg.app_name,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if openapi_enabled else None,
    )

    if cfg.environment == "production" and cfg.auth_required and not cfg.api_keys:
        raise RuntimeError("Production mode requires at least one API key (LCD_API_KEYS)")

    if cfg.trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(cfg.trusted_hosts))

    if cfg.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cfg.cors_allowed_origins),
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID"],
        )

    security_options = SecurityOptions(
        environment=cfg.environment,
        auth_required=cfg.auth_required,
        api_keys=cfg.api_keys,
        exempt_paths=cfg.exempt_auth_paths,
        rate_limit_per_minute=cfg.rate_limit_per_minute,
        rate_limit_exempt_paths=cfg.rate_limit_exempt_paths,
    )
    install_security_middlewares(app, security_options)

    app.state.settings = cfg
    app.state.store = InMemoryStore()
    app.state.pipeline = DefensePipeline(settings=cfg, store=app.state.store)
    web_dir = Path(__file__).resolve().parent / "web"
    app.mount("/web", StaticFiles(directory=web_dir), name="web")

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:  # type: ignore[override]
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception("Unhandled error", extra={"request_id": request_id, "path": request.url.path})
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "internal server error", "request_id": request_id},
        )

    @app.get("/health/live")
    def health_live() -> dict:
        return {"status": "ok"}

    @app.get("/")
    def dashboard_home() -> FileResponse:
        return FileResponse(web_dir / "index.html")

    @app.get("/health/ready")
    def health_ready(request: Request) -> dict:
        cfg_local: Settings = request.app.state.settings
        ready = True
        reasons: list[str] = []

        if cfg_local.environment == "production" and cfg_local.auth_required and not cfg_local.api_keys:
            ready = False
            reasons.append("missing API keys")

        return {
            "status": "ready" if ready else "not_ready",
            "reasons": reasons,
        }

    @app.get("/health")
    def health(request: Request) -> dict:
        store: InMemoryStore = request.app.state.store
        pipeline: DefensePipeline = request.app.state.pipeline
        cfg_local: Settings = request.app.state.settings
        return {
            "status": "ok",
            "app": cfg_local.app_name,
            "environment": cfg_local.environment,
            "events_buffered": len(store.events),
            "alerts_buffered": len(store.alerts),
            "incidents_open": len(store.incidents),
            "runtime": pipeline.runtime_stats(),
        }

    @app.post("/events")
    def ingest_event(event: ChainEvent, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.process_event(event)

    @app.post("/pending")
    def ingest_pending_tx(pending_tx: PendingTx, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.process_pending_tx(pending_tx)

    @app.post("/simulate/run")
    def run_simulation(request: Request, request_payload: SimulationRequest | None = None) -> dict:
        req = request_payload or SimulationRequest()
        pipeline: DefensePipeline = request.app.state.pipeline
        cfg_local: Settings = request.app.state.settings

        _ensure_simulation_enabled(cfg_local)

        if req.source == "jsonl":
            path = _resolve_jsonl_path(req.path, cfg_local)
            events = load_events_from_jsonl(path)
        else:
            default_path = Path(__file__).resolve().parents[2] / "data" / "sample_events.jsonl"
            events = load_events_from_jsonl(default_path) if default_path.exists() else generate_sample_attack_scenario()

        replay_result = pipeline.replay_events(events)
        replay_result["campaigns_tracked"] = len(pipeline.campaigns.campaigns)
        return replay_result

    @app.post("/simulate/mempool")
    def run_mempool_simulation(request: Request, request_payload: MempoolSimulationRequest | None = None) -> dict:
        req = request_payload or MempoolSimulationRequest()
        pipeline: DefensePipeline = request.app.state.pipeline
        cfg_local: Settings = request.app.state.settings

        _ensure_simulation_enabled(cfg_local)

        if req.source == "jsonl":
            path = _resolve_jsonl_path(req.path, cfg_local)
            pending_txs = load_pending_from_jsonl(path)
        else:
            pending_txs = generate_sample_mempool_scenario()

        outputs = [pipeline.process_pending_tx(tx) for tx in pending_txs]
        return {
            "processed": len(outputs),
            "alerts_created": sum(1 for o in outputs if o["alerted"]),
            "critical_alerts": sum(1 for o in outputs if o["severity"] == "critical"),
            "last": outputs[-1] if outputs else None,
        }

    @app.get("/alerts")
    def list_alerts(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100) -> list[dict]:
        store: InMemoryStore = request.app.state.store
        return [alert.model_dump(mode="json") for alert in store.list_alerts(limit=limit)]

    @app.get("/incidents")
    def list_incidents(
        request: Request,
        active_within_hours: Annotated[int, Query(ge=1, le=168)] = 24,
    ) -> list[dict]:
        store: InMemoryStore = request.app.state.store
        incidents = store.list_incidents(active_within_hours=active_within_hours)
        return [incident.model_dump(mode="json") for incident in incidents]

    @app.get("/campaigns")
    def list_campaigns(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100) -> list[dict]:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.list_campaigns(limit=limit)

    @app.get("/intel/bridge-links")
    def list_bridge_links(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100) -> list[dict]:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.list_bridge_links(limit=limit)

    @app.get("/intel/malicious-seeds")
    def list_malicious_seeds(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        seeds = pipeline.list_malicious_seeds()
        return {"count": len(seeds), "seeds": seeds}

    @app.post("/intel/malicious-seeds/{address}")
    def add_malicious_seed(address: str, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        pipeline.add_malicious_seed(address)
        return {"status": "ok", "added": address.lower(), "count": len(pipeline.list_malicious_seeds())}

    @app.delete("/intel/malicious-seeds/{address}")
    def remove_malicious_seed(address: str, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        pipeline.remove_malicious_seed(address)
        return {"status": "ok", "removed": address.lower(), "count": len(pipeline.list_malicious_seeds())}

    @app.get("/intel/critical-contracts")
    def list_critical_contracts(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        contracts = pipeline.list_critical_contracts()
        return {"count": len(contracts), "contracts": contracts}

    @app.post("/intel/critical-contracts/{address}")
    def add_critical_contract(address: str, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        pipeline.add_critical_contract(address)
        return {"status": "ok", "added": address.lower(), "count": len(pipeline.list_critical_contracts())}

    @app.delete("/intel/critical-contracts/{address}")
    def remove_critical_contract(address: str, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        pipeline.remove_critical_contract(address)
        return {"status": "ok", "removed": address.lower(), "count": len(pipeline.list_critical_contracts())}

    @app.get("/notifications/channels")
    def list_notification_channels(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        channels = pipeline.list_notification_channels()
        return {"count": len(channels), "channels": channels}

    @app.post("/notifications/channels")
    def configure_notification_channel(payload: NotificationChannelRequest, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        channel = pipeline.add_notification_channel(
            provider=payload.provider.value,
            destination=payload.destination,
            min_severity=payload.min_severity.value,
            enabled=payload.enabled,
            metadata=payload.metadata,
        )
        return {"status": "ok", "channel": channel}

    @app.delete("/notifications/channels/{channel_id}")
    def remove_notification_channel(channel_id: str, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        removed = pipeline.remove_notification_channel(channel_id=channel_id)
        if not removed:
            raise HTTPException(status_code=404, detail="notification channel not found")
        return {"status": "ok", "removed": channel_id}

    @app.get("/notifications/messages")
    def list_notification_messages(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        messages = pipeline.list_notification_messages(limit=limit)
        return {"count": len(messages), "messages": messages}

    @app.post("/notifications/test")
    def send_test_notification(payload: NotificationTestRequest, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        dispatches = pipeline.test_notification(channel_id=payload.channel_id, message=payload.message)
        if payload.channel_id and not dispatches:
            raise HTTPException(status_code=404, detail="notification channel not found or disabled")
        return {"status": "ok", "count": len(dispatches), "dispatches": dispatches}

    @app.get("/replay/reorgs")
    def list_reorgs(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100) -> list[dict]:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.recent_reorgs(limit=limit)

    @app.get("/relay/submissions")
    def list_relay_submissions(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 100) -> list[dict]:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.recent_relay_submissions(limit=limit)

    @app.post("/feedback/labels/{alert_id}")
    def add_feedback_label(alert_id: str, payload: LabelRequest, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.add_analyst_label(alert_id=alert_id, verdict=payload.verdict.value, notes=payload.notes)

    @app.get("/feedback/labels")
    def list_feedback_labels(request: Request, limit: Annotated[int, Query(ge=1, le=1000)] = 200) -> list[dict]:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.recent_labels(limit=limit)

    @app.get("/feedback/summary")
    def feedback_summary(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.feedback.summary()

    @app.post("/feedback/recalibrate")
    def feedback_recalibrate(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.recalibrate_from_feedback()

    @app.post("/simulation/backtest")
    def run_backtest(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.run_backtest()

    @app.get("/ops/slo")
    def get_slo_status(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.slo.status()

    @app.post("/ops/failover-drill")
    def run_failover_drill(request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        return pipeline.run_failover_drill()

    @app.post("/ops/outage")
    def report_outage(payload: OutageRequest, request: Request) -> dict:
        pipeline: DefensePipeline = request.app.state.pipeline
        pipeline.report_outage(payload.seconds)
        return {"status": "ok", "recorded_outage_seconds": payload.seconds}

    return app


def _ensure_simulation_enabled(cfg: Settings) -> None:
    if cfg.enable_simulation_endpoints:
        return
    raise HTTPException(status_code=403, detail="simulation endpoints are disabled")


def _resolve_jsonl_path(raw_path: str | None, cfg: Settings) -> Path:
    if not raw_path:
        raise HTTPException(status_code=400, detail="path is required for jsonl source")

    base_dir = (Path(__file__).resolve().parents[2] / cfg.simulation_data_dir).resolve()
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    resolved = candidate.resolve()

    # In locked mode, only allow files under configured simulation dir.
    if not cfg.allow_local_file_simulation:
        if not _is_relative_to(resolved, base_dir):
            raise HTTPException(status_code=400, detail="path outside allowed simulation directory")

    if resolved.suffix.lower() != ".jsonl":
        raise HTTPException(status_code=400, detail="only .jsonl files are allowed")

    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    return resolved


def _is_relative_to(path: Path, base_dir: Path) -> bool:
    try:
        path.relative_to(base_dir)
        return True
    except ValueError:
        return False


app = create_app()


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("LCD_HOST", "127.0.0.1")
    port = int(os.getenv("LCD_PORT", "8000"))
    uvicorn.run("live_chain_defense.app:app", host=host, port=port)
