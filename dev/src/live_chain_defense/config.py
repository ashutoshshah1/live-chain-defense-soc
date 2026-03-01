from typing import Literal

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    environment: Literal["development", "production"] = "development"
    app_name: str = "live-chain-defense"
    auth_required: bool = True
    api_keys: tuple[str, ...] = ()
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    cors_allowed_origins: tuple[str, ...] = ()
    rate_limit_per_minute: int = 600
    enable_docs: bool = True
    enable_openapi: bool = True
    enable_simulation_endpoints: bool = True
    allow_local_file_simulation: bool = False
    simulation_data_dir: str = "data"
    alert_score_threshold: float = 65.0
    critical_score_threshold: float = 85.0
    large_transfer_usd: float = 500_000.0
    burst_window_seconds: int = 90
    burst_tx_threshold: int = 4
    baseline_history_size: int = 60
    sequence_window_seconds: int = 180
    campaign_merge_window_seconds: int = 7_200
    mempool_alert_score_threshold: float = 65.0
    reorg_confirmation_depth: int = 6
    replay_dedup_enabled: bool = True
    max_auto_actions_per_incident: int = 4
    require_manual_approval_for_pause: bool = True
    relay_default_mode: str = "private_relay"
    weekly_recalibration_min_labels: int = 20
    slo_target_uptime_ratio: float = 0.999
    slo_target_latency_ms: float = 10_000.0
    high_risk_methods: tuple[str, ...] = (
        "upgradeTo",
        "upgradeToAndCall",
        "setImplementation",
        "transferOwnership",
        "setAdmin",
        "sweep",
        "emergencyWithdraw",
    )
    default_malicious_seeds: tuple[str, ...] = (
        "0xknownmixer1",
        "0xknownmixer2",
        "0xknownexploitwallet",
    )
    critical_contracts: tuple[str, ...] = ()
    response_mode: str = "dry_run"

    model_config = {
        "env_prefix": "LCD_",
        "case_sensitive": False,
    }

    @computed_field(return_type=tuple[str, ...])
    @property
    def exempt_auth_paths(self) -> tuple[str, ...]:
        return ("/", "/favicon.ico", "/web/*", "/health", "/health/live", "/health/ready")

    @computed_field(return_type=tuple[str, ...])
    @property
    def rate_limit_exempt_paths(self) -> tuple[str, ...]:
        return ("/", "/favicon.ico", "/web/*", "/health", "/health/live", "/health/ready")

    @field_validator("api_keys", "trusted_hosts", "cors_allowed_origins", mode="before")
    @classmethod
    def _split_csv_tuple(cls, value):  # type: ignore[no-untyped-def]
        if value is None:
            return ()
        if isinstance(value, str):
            parts = [item.strip() for item in value.split(",") if item.strip()]
            return tuple(parts)
        return value


settings = Settings()
