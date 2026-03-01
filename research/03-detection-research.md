# 03 - Detection Research

## Signal Families
1. **Flow signals**
   - Outflow ratio over rolling windows.
   - Net treasury delta (1m/5m/15m).
   - Fan-out degree and transfer burst.

2. **Behavioral signals**
   - First-seen destination score.
   - Privileged method anomaly score.
   - Approval-to-drain lag indicator.

3. **Graph intelligence signals**
   - Distance to known malicious seeds.
   - Cluster contamination score.
   - Bridge-hop sequence risk.

4. **Context signals**
   - Contract criticality score.
   - Asset liquidity sensitivity.
   - Incident overlap with external threat intel.

5. **Adaptive signals**
   - Per-wallet baseline deviation (historical median vs current outflow).
   - Sequence-pattern score (`approval -> transfer`, `privileged_call -> transfer`).
   - Detection confidence score (signal agreement + historical sample quality).

## Initial Risk Model
Composite score range `0-100`:
- 40% flow anomalies
- 25% behavioral anomalies
- 25% graph intelligence
- 10% context/asset criticality

Severity mapping:
- `0-39`: Low
- `40-64`: Medium
- `65-84`: High
- `85-100`: Critical

## Campaign Intelligence Layer
- Correlate events into campaign IDs using address overlap + time windows.
- Track campaign expansion across chains and linked addresses.
- Prioritize multi-chain campaigns for faster SOC escalation and coordinated freeze workflows.

## Pre-Confirmation Layer
- Score pending transactions before confirmation (value, method, gas race, taint destination).
- Trigger preconfirm alerts and blocking strategies before full drain finality.

## Reliability Layer
- Deterministic event IDs for replay safety and deduplication.
- Reorg detection for same-height block hash divergence.

## Research Backlog
- Precision comparison: rule-only vs hybrid ML.
- False positive reduction for high-frequency operational wallets.
- Destination-cluster refresh cadence.
- Adaptive thresholds by volatility regime.
- Evaluate campaign-linking quality against historical exploit datasets.
- Validate preconfirm model lead time against real mempool traces.
