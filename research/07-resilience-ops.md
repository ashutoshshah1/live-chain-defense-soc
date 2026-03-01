# 07 - Resilience and Operations

## Reorg-Safe and Replayable Ingestion
- Deterministic canonical IDs for confirmed/pending events.
- Dedup at ingestion layer to prevent replay amplification.
- Reorg detector for same-height block-hash changes.

## High Availability Model
- Stateless API workers behind LB.
- Shared durable queue for event ingestion and replay.
- Active-passive failover with tested RTO and RPO.

## SLO Targets
- Uptime target: `>= 99.9%`.
- Detection latency target: `< 10 seconds` for critical drains.
- Replay correctness target: zero duplicate incidents for identical canonical events.

## Operational Drills
- Weekly failover drill.
- Monthly reorg/replay chaos drill.
- Quarterly incident tabletop for protocol + custody + exchange escalation.
