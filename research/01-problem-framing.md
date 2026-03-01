# 01 - Problem Framing

## Core Problem
Protocol funds are often drained quickly through multi-step attacker paths (compromised key, malicious upgrade, approval abuse, flashloan exploit, bridge laundering). Traditional monitoring catches incidents late.

## Mission
Build a 24x7 live threat-intelligence network that:
1. Observes cross-chain value movement in near real time.
2. Detects drain patterns within seconds.
3. Predicts continuation risk (likelihood of full drain).
4. Activates response playbooks early enough to reduce losses.

## Success Metrics
- `MTTD` (mean time to detect) < 15 seconds on monitored assets.
- `P1 precision` > 90% for severe drain alerts.
- `Loss prevented` ratio > 50% in simulated incidents.
- `Coverage` across configured chains and critical contracts > 99.9% uptime.

## Scope Assumptions
- Initial target: EVM chains (Ethereum, Base, Arbitrum, BNB, Polygon).
- Admin response capability exists (pause, rate-limit, role revoke, emergency upgrade, off-chain exchange escalation).
- System integrates with incident channels (Slack, PagerDuty, Telegram, SIEM).
