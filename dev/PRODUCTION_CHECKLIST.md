# Production Readiness Checklist

## Security Controls
- [ ] `LCD_ENVIRONMENT=production`
- [ ] `LCD_AUTH_REQUIRED=true`
- [ ] `LCD_API_KEYS` set to strong rotated secrets
- [ ] `LCD_TRUSTED_HOSTS` restricted to deployed hostnames
- [ ] `LCD_ENABLE_DOCS=false` and `LCD_ENABLE_OPENAPI=false`
- [ ] `LCD_ENABLE_SIMULATION_ENDPOINTS=false`
- [ ] TLS termination enabled at ingress/load balancer

## Runtime Safety
- [ ] Replay dedup enabled (`LCD_REPLAY_DEDUP_ENABLED=true`)
- [ ] Reorg depth tuned per chain (`LCD_REORG_CONFIRMATION_DEPTH`)
- [ ] Guardrails configured (`LCD_REQUIRE_MANUAL_APPROVAL_FOR_PAUSE=true`)
- [ ] `LCD_RESPONSE_MODE` set deliberately (`dry_run` or `enforce`)

## Observability
- [ ] `/health/live` and `/health/ready` monitored
- [ ] `/ops/slo` scraped and alerted
- [ ] Failover drill run weekly (`/ops/failover-drill`)
- [ ] Incident alert channels integrated with PagerDuty/Slack

## Data and Reliability
- [ ] Persistent storage added for alerts/incidents/labels/replay state
- [ ] Backtest run before release (`/simulation/backtest`)
- [ ] Label feedback loop active and recalibration governed

## Final Verification Commands
```bash
# tests
cd dev && python -m pytest

# health
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready

# auth check (expected 401)
curl http://127.0.0.1:8000/alerts

# auth success
curl -H "X-API-Key: <key>" http://127.0.0.1:8000/alerts
```
