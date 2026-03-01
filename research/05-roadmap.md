# 05 - Strategy C Roadmap

## Phase 0 (Week 1-2): Foundations
- Unified event schema for multi-chain transfers/calls.
- Risk-scoring core with deterministic rules.
- Alert channel integration and incident storage.
- Deterministic replay IDs and duplicate suppression.

## Phase 1 (Week 3-5): Graph Intelligence
- Address graph service (streaming edge updates).
- Seed list ingestion (malicious addresses/clusters).
- Exposure scoring and cluster contamination features.
- Entity clustering and taint propagation across bridge hops.

## Phase 2 (Week 6-8): Automated Response
- Policy engine and playbook execution framework.
- Protocol adapters for pause/rate-limit/role revoke.
- Dry-run and staged rollout for automation.
- Guardrail-enforced auto-response executor.
- Private relay / bundled defense submission path.

## Phase 3 (Week 9-12): Threat Intelligence Network
- Cross-chain attacker identity linking.
- Sequence-level predictive model (continuation likelihood).
- SOC dashboard with timeline replay and forensic export.
- Mempool pre-confirmation sentinel and preconfirm playbooks.

## Phase 4 (Production Hardening)
- HA deployment, replay-capable event bus, SLOs/SLIs.
- On-call runbooks, chaos drills, and red-team simulations.
- Analyst labeling program and weekly threshold recalibration.
- Release gates backed by red-team backtesting metrics.
