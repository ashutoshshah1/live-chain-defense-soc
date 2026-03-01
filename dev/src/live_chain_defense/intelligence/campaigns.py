from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from live_chain_defense.models import ChainEvent


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class CampaignStats:
    campaign_id: str
    first_seen: datetime = field(default_factory=_utc_now)
    last_seen: datetime = field(default_factory=_utc_now)
    chains: set[str] = field(default_factory=set)
    addresses: set[str] = field(default_factory=set)
    tx_hashes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "chain_count": len(self.chains),
            "chains": sorted(self.chains),
            "address_count": len(self.addresses),
            "addresses": sorted(self.addresses),
            "tx_count": len(self.tx_hashes),
            "recent_txs": self.tx_hashes[-20:],
        }


class CampaignCorrelator:
    """Groups related events into campaigns using address overlap and recency."""

    def __init__(self, merge_window_seconds: int = 7_200) -> None:
        self.merge_window = timedelta(seconds=merge_window_seconds)
        self.address_to_campaign: dict[str, str] = {}
        self.campaigns: dict[str, CampaignStats] = {}

    def assign(self, event: ChainEvent) -> dict[str, int | str]:
        now = event.timestamp
        addresses = [event.from_address.lower(), event.to_address.lower()]
        if event.contract_address:
            addresses.append(event.contract_address.lower())

        candidates: list[str] = []
        for address in addresses:
            campaign_id = self.address_to_campaign.get(address)
            if not campaign_id:
                continue
            stats = self.campaigns.get(campaign_id)
            if not stats:
                continue
            if now - stats.last_seen <= self.merge_window:
                candidates.append(campaign_id)

        if candidates:
            primary = candidates[0]
            for campaign_id in candidates[1:]:
                if campaign_id != primary:
                    self._merge_campaigns(primary, campaign_id)
            campaign_id = primary
        else:
            campaign_id = f"cmp-{uuid4().hex[:12]}"
            self.campaigns[campaign_id] = CampaignStats(campaign_id=campaign_id, first_seen=now, last_seen=now)

        stats = self.campaigns[campaign_id]
        stats.last_seen = now
        stats.chains.add(event.chain)
        stats.tx_hashes.append(event.tx_hash)

        for address in addresses:
            stats.addresses.add(address)
            self.address_to_campaign[address] = campaign_id

        return {
            "campaign_id": campaign_id,
            "chain_count": len(stats.chains),
            "address_count": len(stats.addresses),
            "tx_count": len(stats.tx_hashes),
        }

    def list_campaigns(self, limit: int = 100) -> list[dict]:
        items = sorted(self.campaigns.values(), key=lambda item: item.last_seen, reverse=True)
        return [item.to_dict() for item in items[:limit]]

    def _merge_campaigns(self, primary_id: str, secondary_id: str) -> None:
        primary = self.campaigns.get(primary_id)
        secondary = self.campaigns.get(secondary_id)
        if not primary or not secondary:
            return

        primary.last_seen = max(primary.last_seen, secondary.last_seen)
        primary.first_seen = min(primary.first_seen, secondary.first_seen)
        primary.chains.update(secondary.chains)
        primary.addresses.update(secondary.addresses)
        primary.tx_hashes.extend(secondary.tx_hashes)

        for address in secondary.addresses:
            self.address_to_campaign[address] = primary_id

        del self.campaigns[secondary_id]
