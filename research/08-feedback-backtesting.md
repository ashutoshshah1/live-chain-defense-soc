# 08 - Feedback and Backtesting

## Analyst Feedback Loop
- Analysts label alerts as true positive / false positive / uncertain.
- Weekly threshold recalibration adjusts alert sensitivity.
- Maintain calibration history for governance and auditability.

## Red-Team Backtesting
- Replay synthetic and historical exploit traces.
- Measure detection latency, severity quality, and estimated loss prevented.
- Track precision/recall trend over releases.

## Governance
- Threshold changes require policy review when adjustment exceeds configured bounds.
- Backtest metrics are release gates for production promotion.
