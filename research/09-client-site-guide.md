# 09 - Client Site Guide (Simple Manual)

## What This Product Is
Live Chain Defense is a 24/7 monitoring and response platform for crypto drain threats.

It does four things:
1. Ingests on-chain and pending transaction activity.
2. Scores risk in real time.
3. Creates alerts and grouped incidents.
4. Helps security teams trigger response actions quickly.

## Quick Demo in 5 Minutes
1. Start app:
   ```bash
   cd /home/bratwork/Desktop/useful/live-chain-attack/dev
   ./scripts/start_local.sh
   ```
2. Open `http://127.0.0.1:8000/`.
3. Click **Run Demo**.
4. Review alerts, incidents, campaigns, and notification channels.

## What Client Sees on Website
- **Environment / Uptime / Latency**: system health.
- **Latest Alerts**: risk severity, score, tx context.
- **Active Incidents**: grouped suspicious behavior.
- **Campaign Watch**: linked activity across addresses/chains.
- **SLO Posture**: reliability targets.
- **Notification Channels**: where alerts are delivered.

## Data Flow (Easy)
1. **Input**:
   - `POST /events` for confirmed transactions/events.
   - `POST /pending` for mempool transactions.
2. **Detection**:
   - large outflow checks,
   - burst/sequence behavior,
   - tainted entity proximity,
   - campaign correlation.
3. **Output**:
   - Alert with severity + reasons.
   - Incident grouping for SOC workflow.
   - Notification dispatch records.

## Notification Setup
In dashboard:
1. Open **Notification Channels**.
2. Select provider + destination + min severity.
3. Click **Add Channel**.
4. Click **Test Channels**.

Provider behavior:
- `webhook`: direct HTTP delivery from app.
- `in_app`: local delivery record.
- `email/slack/telegram/pagerduty`: queued for external integration workers.

## API Key Meaning
API key is backend access control only.

It is:
- Not a wallet secret.
- Not used to sign blockchain transactions.
- Required on protected endpoints as `X-API-Key`.

## What We Deliver to Client
1. Dashboard web app.
2. Detection and correlation engine.
3. Alert + incident APIs.
4. Notification routing configuration.
5. Production hardening checklist and runbook.

## What We Need from Client
1. Chains to monitor.
2. Critical wallets/contracts.
3. Escalation channels (webhook URLs, on-call systems).
4. Allowed automatic response actions.
5. Production environment values (API keys, hosts, TLS, monitoring).

## Rollout Success Criteria
- Alert appears within seconds of suspicious activity.
- Response team receives actionable alert context.
- Mean time to detect/respond is reduced.
- Platform maintains expected uptime and latency targets.
