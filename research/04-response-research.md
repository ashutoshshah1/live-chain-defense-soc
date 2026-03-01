# 04 - Response Research

## Response Ladder
1. **Detect**: classify and enrich incident.
2. **Notify**: route alert based on severity and asset ownership.
3. **Constrain**: trigger protocol guardrails (pause/rate-limit).
4. **Contain**: revoke roles, blocklist recipients, halt bridging.
5. **Recover**: forensic package and legal/exchange escalation.

## Playbook Types
- `TREASURY_DRAIN`: pause treasury outflows + require multisig escalation.
- `LP_POOL_DRAIN`: halt pool operations + disable vulnerable path.
- `SIGNER_COMPROMISE`: rotate keys + suspend affected signer roles.
- `APPROVAL_ABUSE`: broadcast revoke recommendations + UI warning flags.

## Operational Requirements
- Every automated action must be logged with reason and rollback plan.
- Actions should be policy-gated (dry-run, suggest-only, enforce mode).
- Human override must remain available for all critical actions.
- High-impact actions (pause, withdrawal limits) require explicit guardrails/manual approval policy.
- Private relay/bundle path should be preferred for defensive on-chain transactions.
