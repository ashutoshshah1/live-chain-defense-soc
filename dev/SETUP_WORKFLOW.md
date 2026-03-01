# Setup Workflow (Simple)

This is the easiest way to run and understand the app.

## 1) Start in 60 seconds
```bash
cd /home/bratwork/Desktop/useful/live-chain-attack/dev
./scripts/start_local.sh
```

Open:
- Dashboard: `http://127.0.0.1:8000/`
- Health: `http://127.0.0.1:8000/health`

## 2) Show working data
If dashboard is empty, click **Run Demo** once.

This loads sample confirmed + pending transactions so alerts and incidents appear.

## 3) Configure notifications
In **Notification Channels**:
1. Pick provider.
2. Add destination.
3. Pick min severity.
4. Click **Add Channel**.
5. Click **Test Channels**.

Current behavior:
- `webhook`: sends real HTTP POST.
- `email/slack/telegram/pagerduty`: queued as external dispatch records.
- `in_app`: local in-dashboard delivery record.

## 4) Understand API key
`API key` in the UI is for backend authorization only.

It is:
- Not a wallet private key.
- Not used to sign blockchain transactions.
- Only used as `X-API-Key` for protected API endpoints.

## 5) Basic API usage
```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/simulate/run
curl -X POST http://127.0.0.1:8000/simulate/mempool
curl http://127.0.0.1:8000/alerts
curl http://127.0.0.1:8000/incidents
curl http://127.0.0.1:8000/notifications/channels
```

## 6) Send real chain data
Use these two endpoints from your indexer or websocket collector:
- `POST /events` (confirmed data)
- `POST /pending` (mempool data)

Example:
```bash
curl -X POST http://127.0.0.1:8000/events \
  -H 'Content-Type: application/json' \
  -d '{
    "chain":"ethereum",
    "tx_hash":"0xlive1",
    "from_address":"0xTreasury",
    "to_address":"0xReceiver",
    "amount_usd":1200000,
    "event_type":"transfer"
  }'
```

## 7) Common problems
### App not opening
- Check server is running on port `8000`.
- Re-run `./scripts/start_local.sh`.

### Dashboard has zeros
- Click **Run Demo**.
- Or ingest real data to `/events` and `/pending`.

### Unauthorized errors
- Add valid API key in dashboard input.
- Or call APIs with `X-API-Key`.

### Notifications not reaching Slack/Email yet
- This version queues those providers for external workers.
- Use `webhook` provider for direct HTTP delivery from this app.

## 8) What to hand over to client
1. Dashboard URL and API URL.
2. API key(s).
3. Notification channel setup.
4. Chain ingestion adapter details.
5. Production checklist completion proof.
