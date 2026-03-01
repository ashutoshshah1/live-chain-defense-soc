# 06 - Pre-Confirmation Defense

## Objective
Detect and counter drain attempts before confirmation by monitoring pending transactions and responding with low-latency guard actions.

## Architecture
1. **Mempool sentinel**
- Watches pending transactions for high-value outflows, high-risk methods, gas racing, and burst patterns.
- Produces pre-confirmation risk score with confidence.

2. **Pre-confirmation response path**
- Creates `PRECONFIRM` alerts with campaign correlation.
- Triggers guarded actions such as `submit_preconfirm_block`.

3. **Private execution path**
- Use private relay by default for on-chain defensive transactions.
- Use bundled submission for multi-action emergency mitigation.

## Risks & Controls
- False positives in mempool can create unnecessary defense tx costs.
- Guardrails must enforce severity thresholds and manual approvals for high-impact actions.
- Relay health fallback required to avoid single-point execution dependency.
