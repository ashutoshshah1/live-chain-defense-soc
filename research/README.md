# Research Workstream: Live Chain Attack Defense (Strategy C)

This directory contains all analysis, modeling, and threat-intelligence planning for a full-scale on-chain drain defense platform.

## Start Here (Easy)
If you want the quickest practical onboarding:
1. Read client-friendly overview:
   - `09-client-site-guide.md`
2. Run the app with simple setup:
   - `/home/bratwork/Desktop/useful/live-chain-attack/dev/SETUP_WORKFLOW.md`
3. See runnable app summary:
   - `/home/bratwork/Desktop/useful/live-chain-attack/dev/README.md`

## Files
- `01-problem-framing.md`: scope, goals, and measurable success criteria.
- `02-threat-model.md`: attacker behavior model and kill chains.
- `03-detection-research.md`: feature hypotheses and signal quality expectations.
- `04-response-research.md`: response automation and operational runbooks.
- `05-roadmap.md`: staged rollout plan from pilot to production.
- `06-preconfirmation-defense.md`: mempool sentinel and private relay strategy.
- `07-resilience-ops.md`: replay safety, reorg handling, HA and SLO design.
- `08-feedback-backtesting.md`: analyst feedback loop and red-team validation.
- `09-client-site-guide.md`: simple client-facing explanation of what the website and platform do.

## Working Principles
- Separate hypothesis from implementation details.
- Prioritize detection precision for high-value wallets/contracts.
- Favor response paths that are reversible and auditable.
