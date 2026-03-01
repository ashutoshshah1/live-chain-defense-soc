# Live Chain Defense (Dev)

This folder contains the runnable app and API for the live drain-defense dashboard.

## Fastest Setup (Recommended)
Run everything with one command:

```bash
cd /home/bratwork/Desktop/useful/live-chain-attack/dev
./scripts/start_local.sh
```

Then open:
- Dashboard: `http://127.0.0.1:8000/`
- Health: `http://127.0.0.1:8000/health`

To see data immediately:
1. Open dashboard.
2. Click **Run Demo**.
3. Alerts/incidents/campaigns will populate.

## Manual Setup (If You Prefer)
```bash
cd /home/bratwork/Desktop/useful/live-chain-attack/dev
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m uvicorn live_chain_defense.app:app --host 127.0.0.1 --port 8000 --reload
```

## Notification Setup
Use the **Notification Channels** section in the dashboard:
1. Choose provider (`in_app`, `webhook`, `email`, `slack`, `telegram`, `pagerduty`).
2. Enter destination.
3. Select minimum severity.
4. Click **Add Channel** and then **Test Channels**.

API endpoints:
- `GET /notifications/channels`
- `POST /notifications/channels`
- `DELETE /notifications/channels/{channel_id}`
- `POST /notifications/test`
- `GET /notifications/messages`

## API Quick Check
```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/alerts
curl http://127.0.0.1:8000/incidents
curl http://127.0.0.1:8000/campaigns
curl http://127.0.0.1:8000/notifications/channels
```

## Production Notes
Before client deployment:
1. Set strong API keys (`LCD_API_KEYS`).
2. Set trusted hosts (`LCD_TRUSTED_HOSTS`).
3. Disable docs/openapi/simulation in production.
4. Enable TLS and external monitoring.

Use this checklist:
- [PRODUCTION_CHECKLIST.md](/home/bratwork/Desktop/useful/live-chain-attack/dev/PRODUCTION_CHECKLIST.md)

Detailed setup and workflow:
- [SETUP_WORKFLOW.md](/home/bratwork/Desktop/useful/live-chain-attack/dev/SETUP_WORKFLOW.md)
