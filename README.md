# Live Chain Defense SOC

Live Chain Defense SOC is a real-time security platform to detect crypto drain threats, raise high-confidence alerts, and help response teams act faster.

## What It Does
- Monitors confirmed and pending transaction activity.
- Scores risk using behavioral, graph, and campaign intelligence.
- Creates alerts and active incidents with reasons.
- Supports notification routing for incident escalation.
- Provides a SOC-style dashboard for live operations.

## Quick Start (Recommended)
```bash
cd /home/bratwork/Desktop/useful/live-chain-attack/dev
./scripts/start_local.sh
```

Open:
- Dashboard: `http://127.0.0.1:8000/`
- Health: `http://127.0.0.1:8000/health`

## 2-Minute Demo
1. Open the dashboard.
2. Click **Run Demo**.
3. Watch alerts, incidents, campaigns, and SLO metrics populate.
4. Configure **Notification Channels** and run a test alert.

## Notification Setup
From dashboard:
1. Go to **Notification Channels**.
2. Choose provider + destination + min severity.
3. Click **Add Channel**.
4. Click **Test Channels**.

Current delivery behavior:
- `webhook`: direct HTTP POST delivery.
- `in_app`: local delivery record.
- `email/slack/telegram/pagerduty`: queued for external worker integrations.

## API Quick Check
```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/simulate/run
curl -X POST http://127.0.0.1:8000/simulate/mempool
curl http://127.0.0.1:8000/alerts
curl http://127.0.0.1:8000/incidents
curl http://127.0.0.1:8000/notifications/channels
```

## Project Structure
- `dev/`: runnable application, APIs, dashboard, tests, and operational docs.
- `research/`: threat model, detection research, response strategy, and client guide.

## Documentation
- Dev quick guide: `dev/README.md`
- Step-by-step setup: `dev/SETUP_WORKFLOW.md`
- Production hardening checklist: `dev/PRODUCTION_CHECKLIST.md`
- Client-facing simple manual: `research/09-client-site-guide.md`

## Production Readiness
Before deploying for clients:
1. Configure `LCD_API_KEYS` and `LCD_TRUSTED_HOSTS`.
2. Disable docs/openapi/simulation endpoints.
3. Set TLS and external monitoring.
4. Complete `dev/PRODUCTION_CHECKLIST.md`.

## Audience
Built for SOC teams, protocol security teams, and incident responders who need continuous on-chain threat visibility.
