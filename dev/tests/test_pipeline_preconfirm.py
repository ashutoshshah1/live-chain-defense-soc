from live_chain_defense.config import Settings
from live_chain_defense.models import PendingTx
from live_chain_defense.pipeline import DefensePipeline
from live_chain_defense.store import InMemoryStore


def test_pipeline_preconfirm_alert_and_prevention_action() -> None:
    settings = Settings(
        mempool_alert_score_threshold=60,
        response_mode="dry_run",
        require_manual_approval_for_pause=False,
    )
    pipeline = DefensePipeline(settings=settings, store=InMemoryStore())

    pending = PendingTx(
        chain="ethereum",
        tx_hash="0xpending1",
        from_address="0xTreasury",
        to_address="0xAttacker",
        method="transfer",
        value_usd=2_000_000,
        gas_price_gwei=120,
    )

    result = pipeline.process_pending_tx(pending)

    assert result["alerted"] is True
    action_types = {a["action_type"] for a in result["actions"]}
    assert "submit_preconfirm_block" in action_types
