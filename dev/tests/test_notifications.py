from fastapi.testclient import TestClient

from live_chain_defense.app import create_app
from live_chain_defense.config import Settings
from live_chain_defense.models import Alert, ChainEvent, NotificationProvider, Severity
from live_chain_defense.response.notifier import Notifier


def _alert(severity: Severity = Severity.high) -> Alert:
    event = ChainEvent(
        chain="ethereum",
        tx_hash="0xabc123",
        from_address="0xA",
        to_address="0xB",
        amount_usd=250_000,
    )
    return Alert(
        severity=severity,
        risk_score=85.0 if severity in {Severity.high, Severity.critical} else 40.0,
        confidence=0.9,
        campaign_id="camp-1",
        message="test alert",
        event=event,
    )


def test_notifier_channel_severity_filtering_and_fallback() -> None:
    notifier = Notifier()
    default_channels = notifier.list_channels()
    for channel in default_channels:
        notifier.remove_channel(channel.channel_id)

    channel = notifier.configure_channel(
        provider=NotificationProvider.in_app,
        destination="soc-room",
        min_severity=Severity.medium,
    )

    dispatches = notifier.send(_alert(Severity.high))
    assert len(dispatches) == 1
    assert dispatches[0].channel_id == channel.channel_id
    assert dispatches[0].status == "delivered"

    filtered = notifier.send(_alert(Severity.low))
    assert filtered == []

    notifier.remove_channel(channel.channel_id)
    fallback = notifier.send(_alert(Severity.high))
    assert len(fallback) == 1
    assert fallback[0].channel_id == "implicit-in-app"


def test_notification_api_channel_crud_and_test() -> None:
    client = TestClient(
        create_app(
            Settings(
                environment="production",
                auth_required=True,
                api_keys=("secret-key",),
                trusted_hosts=("testserver",),
            )
        )
    )
    headers = {"x-api-key": "secret-key"}

    initial = client.get("/notifications/channels", headers=headers)
    assert initial.status_code == 200
    initial_count = initial.json()["count"]

    created = client.post(
        "/notifications/channels",
        headers=headers,
        json={
            "provider": "email",
            "destination": "secops@example.com",
            "min_severity": "critical",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    channel_id = created.json()["channel"]["channel_id"]

    listing = client.get("/notifications/channels", headers=headers)
    assert listing.status_code == 200
    body = listing.json()
    assert body["count"] == initial_count + 1
    assert any(c["channel_id"] == channel_id for c in body["channels"])

    tested = client.post(
        "/notifications/test",
        headers=headers,
        json={"channel_id": channel_id, "message": "api test notification"},
    )
    assert tested.status_code == 200
    assert tested.json()["count"] == 1
    assert tested.json()["dispatches"][0]["channel_id"] == channel_id

    removed = client.delete(f"/notifications/channels/{channel_id}", headers=headers)
    assert removed.status_code == 200

    removed_missing = client.delete(f"/notifications/channels/{channel_id}", headers=headers)
    assert removed_missing.status_code == 404

    missing_test = client.post(
        "/notifications/test",
        headers=headers,
        json={"channel_id": channel_id, "message": "should fail"},
    )
    assert missing_test.status_code == 404
