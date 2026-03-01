from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from live_chain_defense.models import (
    Alert,
    NotificationChannel,
    NotificationDispatch,
    NotificationProvider,
    Severity,
)


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class Notifier:
    """Notification adapter with pluggable destination channels.

    Non-webhook providers are currently queued for external delivery.
    """

    def __init__(self) -> None:
        self.channels: dict[str, NotificationChannel] = {}
        self.sent: list[NotificationDispatch] = []
        self.configure_channel(
            provider=NotificationProvider.in_app,
            destination="dashboard",
            min_severity=Severity.low,
            metadata={"default": True},
        )

    def configure_channel(
        self,
        *,
        provider: NotificationProvider | str,
        destination: str,
        min_severity: Severity | str = Severity.high,
        enabled: bool = True,
        metadata: dict[str, Any] | None = None,
        channel_id: str | None = None,
    ) -> NotificationChannel:
        channel = NotificationChannel(
            channel_id=channel_id or str(uuid4()),
            provider=NotificationProvider(provider),
            destination=destination.strip(),
            min_severity=Severity(min_severity),
            enabled=enabled,
            metadata=metadata or {},
        )
        self.channels[channel.channel_id] = channel
        return channel

    def remove_channel(self, channel_id: str) -> bool:
        return self.channels.pop(channel_id, None) is not None

    def list_channels(self) -> list[NotificationChannel]:
        return sorted(self.channels.values(), key=lambda channel: channel.created_at, reverse=True)

    def list_sent(self, limit: int = 100) -> list[NotificationDispatch]:
        if limit <= 0:
            return []
        return self.sent[-limit:][::-1]

    def send_test(self, channel_id: str | None = None, message: str = "Test notification") -> list[NotificationDispatch]:
        channels = self._enabled_channels()
        if channel_id:
            channels = [channel for channel in channels if channel.channel_id == channel_id]
            if not channels:
                return []

        if not channels:
            fallback = NotificationDispatch(
                channel_id="implicit-in-app",
                provider=NotificationProvider.in_app,
                destination="dashboard",
                severity=Severity.high,
                message=message,
                risk_score=0.0,
                campaign_id="test",
                tx_hash="test-tx",
                chain="testnet",
                status="delivered",
            )
            self.sent.append(fallback)
            return [fallback]

        dispatches: list[NotificationDispatch] = []
        for channel in channels:
            dispatch = self._dispatch(
                channel=channel,
                severity=Severity.high,
                message=message,
                risk_score=0.0,
                campaign_id="test",
                tx_hash="test-tx",
                chain="testnet",
            )
            self.sent.append(dispatch)
            dispatches.append(dispatch)
        return dispatches

    def send(self, alert: Alert) -> list[NotificationDispatch]:
        enabled_channels = self._enabled_channels()
        matching = [channel for channel in enabled_channels if self._passes_severity(alert.severity, channel.min_severity)]

        if not matching and not enabled_channels:
            fallback = NotificationDispatch(
                channel_id="implicit-in-app",
                provider=NotificationProvider.in_app,
                destination="dashboard",
                severity=alert.severity,
                message=alert.message,
                risk_score=alert.risk_score,
                campaign_id=alert.campaign_id,
                tx_hash=alert.event.tx_hash,
                chain=alert.event.chain,
                status="delivered",
            )
            self.sent.append(fallback)
            return [fallback]

        dispatches: list[NotificationDispatch] = []
        for channel in matching:
            dispatch = self._dispatch(
                channel=channel,
                severity=alert.severity,
                message=alert.message,
                risk_score=alert.risk_score,
                campaign_id=alert.campaign_id,
                tx_hash=alert.event.tx_hash,
                chain=alert.event.chain,
            )
            self.sent.append(dispatch)
            dispatches.append(dispatch)
        return dispatches

    def _enabled_channels(self) -> list[NotificationChannel]:
        return [channel for channel in self.channels.values() if channel.enabled]

    def _passes_severity(self, actual: Severity, required: Severity) -> bool:
        return SEVERITY_ORDER[actual] >= SEVERITY_ORDER[required]

    def _dispatch(
        self,
        *,
        channel: NotificationChannel,
        severity: Severity,
        message: str,
        risk_score: float,
        campaign_id: str | None,
        tx_hash: str,
        chain: str,
    ) -> NotificationDispatch:
        payload = {
            "channel_id": channel.channel_id,
            "provider": channel.provider.value,
            "destination": channel.destination,
            "severity": severity.value,
            "message": message,
            "risk_score": risk_score,
            "campaign_id": campaign_id,
            "tx_hash": tx_hash,
            "chain": chain,
        }

        status = "queued_external"
        if channel.provider == NotificationProvider.in_app:
            status = "delivered"
        elif channel.provider == NotificationProvider.webhook:
            status = self._deliver_webhook(channel.destination, payload)

        return NotificationDispatch(
            channel_id=channel.channel_id,
            provider=channel.provider,
            destination=channel.destination,
            severity=severity,
            message=message,
            risk_score=risk_score,
            campaign_id=campaign_id,
            tx_hash=tx_hash,
            chain=chain,
            status=status,
        )

    def _deliver_webhook(self, destination: str, payload: dict[str, Any]) -> str:
        if not destination.startswith(("http://", "https://")):
            return "failed_invalid_destination"

        request = Request(
            destination,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=3) as response:
                code = getattr(response, "status", 200)
                if 200 <= code < 300:
                    return "delivered"
                return f"failed_http_{code}"
        except HTTPError as exc:
            return f"failed_http_{exc.code}"
        except URLError:
            return "failed_network"
        except Exception:
            return "failed_internal"
