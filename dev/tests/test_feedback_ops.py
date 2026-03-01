from live_chain_defense.config import Settings
from live_chain_defense.feedback.learning import AnalystFeedbackLoop
from live_chain_defense.models import Alert, ChainEvent, LabelVerdict, Severity
from live_chain_defense.ops.slo import SLOMonitor


def _alert(alert_id: str) -> Alert:
    event = ChainEvent(
        chain="ethereum",
        tx_hash=f"0x{alert_id}",
        from_address="0xA",
        to_address="0xB",
        amount_usd=1000,
    )
    return Alert(
        alert_id=alert_id,
        severity=Severity.high,
        risk_score=70,
        confidence=0.8,
        message="test",
        event=event,
    )


def test_feedback_recalibration_adjusts_threshold() -> None:
    settings = Settings(alert_score_threshold=65, weekly_recalibration_min_labels=4)
    loop = AnalystFeedbackLoop(settings)

    loop.add_label("a1", LabelVerdict.false_positive)
    loop.add_label("a2", LabelVerdict.false_positive)
    loop.add_label("a3", LabelVerdict.true_positive)
    loop.add_label("a4", LabelVerdict.false_positive)

    outcome = loop.recalibrate_weekly([_alert("a1")])
    assert outcome["updated"] is True
    assert outcome["new_threshold"] > outcome["old_threshold"]


def test_slo_monitor_tracks_failover_and_outage() -> None:
    monitor = SLOMonitor(Settings())
    monitor.record_confirmed(12.0)
    monitor.record_preconfirm(8.0)
    monitor.register_outage(2.0)
    drill = monitor.run_failover_drill()

    status = monitor.status()
    assert drill["passed"] is True
    assert status["processed_events"] == 1
    assert status["preconfirm_events"] == 1
    assert status["failover_drills"] == 1
