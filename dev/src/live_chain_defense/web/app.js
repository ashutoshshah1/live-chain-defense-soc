const REFRESH_MS = 9000;
const API_KEY_STORAGE = "lcd_api_key";

const el = {
  apiKey: document.getElementById("api-key"),
  saveKey: document.getElementById("save-key"),
  runDemo: document.getElementById("run-demo"),
  authStatus: document.getElementById("auth-status"),
  lastRefresh: document.getElementById("last-refresh"),
  dashboardStatus: document.getElementById("dashboard-status"),
  statEnv: document.getElementById("stat-env"),
  statUptime: document.getElementById("stat-uptime"),
  statLatency: document.getElementById("stat-latency"),
  statIncidents: document.getElementById("stat-incidents"),
  statAlerts: document.getElementById("stat-alerts"),
  statCampaigns: document.getElementById("stat-campaigns"),
  alertsBody: document.getElementById("alerts-body"),
  incidentsList: document.getElementById("incidents-list"),
  campaignsList: document.getElementById("campaigns-list"),
  alertsMeta: document.getElementById("alerts-meta"),
  incidentsMeta: document.getElementById("incidents-meta"),
  campaignsMeta: document.getElementById("campaigns-meta"),
  sloMeta: document.getElementById("slo-meta"),
  sloLatencyTarget: document.getElementById("slo-latency-target"),
  sloUptimeTarget: document.getElementById("slo-uptime-target"),
  sloDrills: document.getElementById("slo-drills"),
  notificationsMeta: document.getElementById("notifications-meta"),
  notificationsList: document.getElementById("notifications-list"),
  notifyForm: document.getElementById("notify-form"),
  notifyProvider: document.getElementById("notify-provider"),
  notifyDestination: document.getElementById("notify-destination"),
  notifySeverity: document.getElementById("notify-severity"),
  notifyTestAll: document.getElementById("notify-test-all"),
};

function getApiKey() {
  return window.localStorage.getItem(API_KEY_STORAGE) || "";
}

function setApiKey(value) {
  if (!value) {
    window.localStorage.removeItem(API_KEY_STORAGE);
    return;
  }
  window.localStorage.setItem(API_KEY_STORAGE, value);
}

function setAuthText(msg, tone = "neutral") {
  el.authStatus.textContent = msg;
  if (tone === "ok") {
    el.authStatus.style.color = "#9bf5d4";
    return;
  }
  if (tone === "warn") {
    el.authStatus.style.color = "#ffd6a0";
    return;
  }
  el.authStatus.style.color = "";
}

async function apiGet(path, { optionalAuth = false } = {}) {
  const headers = {};
  const key = getApiKey();
  if (key) {
    headers["X-API-Key"] = key;
  }

  const response = await fetch(path, { headers });
  if (response.status === 401 && optionalAuth) {
    return { unauthorized: true };
  }

  if (!response.ok) {
    const details = await safeJson(response);
    const msg = details?.detail || `Request failed with status ${response.status}`;
    throw new Error(msg);
  }

  return safeJson(response);
}

async function apiPost(path, body = undefined, { optionalAuth = false } = {}) {
  const headers = {};
  const key = getApiKey();
  if (key) {
    headers["X-API-Key"] = key;
  }
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(path, {
    method: "POST",
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (response.status === 401 && optionalAuth) {
    return { unauthorized: true };
  }

  if (!response.ok) {
    const details = await safeJson(response);
    const msg = details?.detail || `Request failed with status ${response.status}`;
    throw new Error(msg);
  }

  return safeJson(response);
}

async function apiDelete(path, { optionalAuth = false } = {}) {
  const headers = {};
  const key = getApiKey();
  if (key) {
    headers["X-API-Key"] = key;
  }

  const response = await fetch(path, { method: "DELETE", headers });
  if (response.status === 401 && optionalAuth) {
    return { unauthorized: true };
  }

  if (!response.ok) {
    const details = await safeJson(response);
    const msg = details?.detail || `Request failed with status ${response.status}`;
    throw new Error(msg);
  }

  return safeJson(response);
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function shortAddr(value) {
  if (!value) return "-";
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function severityClass(severity) {
  if (severity === "critical") return "sev-critical";
  if (severity === "high") return "sev-high";
  if (severity === "medium") return "sev-medium";
  return "sev-low";
}

function fmtNumber(value) {
  if (value === null || value === undefined) return "-";
  return new Intl.NumberFormat("en-US").format(value);
}

function fmtLatency(ms) {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms.toFixed(0)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function fmtPct(v) {
  if (v === null || v === undefined) return "-";
  return `${(v * 100).toFixed(3)}%`;
}

function renderAlerts(alerts) {
  el.alertsBody.textContent = "";
  if (!alerts || alerts.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.textContent = "No alerts yet.";
    td.className = "muted";
    tr.appendChild(td);
    el.alertsBody.appendChild(tr);
    return;
  }

  alerts.slice(0, 8).forEach((alert) => {
    const tr = document.createElement("tr");

    const sevTd = document.createElement("td");
    const sev = document.createElement("span");
    sev.className = `sev ${severityClass(alert.severity)}`;
    sev.textContent = alert.severity;
    sevTd.appendChild(sev);

    const riskTd = document.createElement("td");
    riskTd.textContent = `${alert.risk_score}`;

    const chainTd = document.createElement("td");
    chainTd.textContent = alert.event?.chain || "-";

    const fromTd = document.createElement("td");
    fromTd.className = "code";
    fromTd.textContent = shortAddr(alert.event?.from_address);

    const msgTd = document.createElement("td");
    msgTd.textContent = alert.message || "-";

    tr.append(sevTd, riskTd, chainTd, fromTd, msgTd);
    el.alertsBody.appendChild(tr);
  });
}

function renderIncidents(incidents) {
  el.incidentsList.textContent = "";
  if (!incidents || incidents.length === 0) {
    const item = document.createElement("li");
    item.className = "item";
    item.textContent = "No active incidents.";
    el.incidentsList.appendChild(item);
    return;
  }

  incidents.slice(0, 6).forEach((incident) => {
    const li = document.createElement("li");
    li.className = "item";

    const title = document.createElement("p");
    title.className = "item-title";
    title.textContent = incident.summary || "Incident";

    const meta = document.createElement("p");
    meta.className = "item-meta code";
    meta.textContent = `${incident.max_severity} | ${incident.chain} | alerts: ${incident.alerts?.length || 0}`;

    li.append(title, meta);
    el.incidentsList.appendChild(li);
  });
}

function renderCampaigns(campaigns) {
  el.campaignsList.textContent = "";
  if (!campaigns || campaigns.length === 0) {
    const item = document.createElement("li");
    item.className = "item";
    item.textContent = "No campaign data yet.";
    el.campaignsList.appendChild(item);
    return;
  }

  campaigns.slice(0, 6).forEach((campaign) => {
    const li = document.createElement("li");
    li.className = "item";

    const title = document.createElement("p");
    title.className = "item-title code";
    title.textContent = campaign.campaign_id || "-";

    const meta = document.createElement("p");
    meta.className = "item-meta";
    meta.textContent = `chains: ${campaign.chain_count || 0} | addresses: ${campaign.address_count || 0} | tx: ${campaign.tx_count || 0}`;

    li.append(title, meta);
    el.campaignsList.appendChild(li);
  });
}

function renderNotificationChannels(channels) {
  el.notificationsList.textContent = "";
  if (!channels || channels.length === 0) {
    const item = document.createElement("li");
    item.className = "notification-item";
    item.textContent = "No channels configured. Alerts remain in local in-app fallback mode.";
    el.notificationsList.appendChild(item);
    return;
  }

  channels.forEach((channel) => {
    const li = document.createElement("li");
    li.className = "notification-item";

    const head = document.createElement("div");
    head.className = "notification-head";

    const main = document.createElement("div");
    main.className = "notification-main";

    const provider = document.createElement("span");
    provider.className = "notification-provider";
    provider.textContent = channel.provider || "-";

    const destination = document.createElement("span");
    destination.className = "code";
    destination.textContent = channel.destination || "-";

    main.append(provider, destination);

    const actions = document.createElement("div");
    actions.className = "notification-actions";

    const testButton = document.createElement("button");
    testButton.className = "secondary-btn button-small";
    testButton.type = "button";
    testButton.textContent = "Test";
    testButton.addEventListener("click", async () => {
      await sendChannelTest(channel.channel_id);
    });

    const deleteButton = document.createElement("button");
    deleteButton.className = "button-small";
    deleteButton.type = "button";
    deleteButton.textContent = "Delete";
    deleteButton.addEventListener("click", async () => {
      await deleteNotificationChannel(channel.channel_id);
    });

    actions.append(testButton, deleteButton);
    head.append(main, actions);

    const meta = document.createElement("p");
    meta.className = "notification-meta";
    meta.textContent = `min severity: ${channel.min_severity} | enabled: ${channel.enabled ? "yes" : "no"}`;

    li.append(head, meta);
    el.notificationsList.appendChild(li);
  });
}

function applyHealth(health) {
  el.statEnv.textContent = health.environment || "-";
  const runtime = health.runtime || {};
  const slo = runtime.slo || {};

  el.statUptime.textContent = fmtPct(slo.uptime_ratio);
  el.statLatency.textContent = fmtLatency(slo.avg_pipeline_latency_ms);
  el.statIncidents.textContent = fmtNumber(health.incidents_open);
  el.statAlerts.textContent = fmtNumber(health.alerts_buffered);
  el.statCampaigns.textContent = fmtNumber(runtime.campaign_count);

  el.sloMeta.textContent = slo.uptime_target_met ? "on target" : "attention needed";
  el.sloLatencyTarget.textContent = `${fmtLatency(slo.avg_pipeline_latency_ms)} / ${fmtLatency(slo.target_latency_ms)}`;
  el.sloUptimeTarget.textContent = `${fmtPct(slo.uptime_ratio)} / ${fmtPct(slo.target_uptime_ratio)}`;
  el.sloDrills.textContent = fmtNumber(slo.failover_drills);
}

async function refreshNotifications() {
  const notifications = await apiGet("/notifications/channels", { optionalAuth: true });
  if (notifications?.unauthorized) {
    return false;
  }

  const channels = notifications.channels || [];
  renderNotificationChannels(channels);
  el.notificationsMeta.textContent = `${channels.length} channels`;
  return true;
}

async function sendChannelTest(channelId = null) {
  try {
    const payload = {
      channel_id: channelId,
      message: "Test notification from Live Chain Defense dashboard",
    };
    const result = await apiPost("/notifications/test", payload, { optionalAuth: true });
    if (result?.unauthorized) {
      setAuthText("Notification test requires valid API key.", "warn");
      return;
    }
    setAuthText(`Test notification sent (${result.count || 0} dispatches).`, "ok");
  } catch (error) {
    setAuthText(`Notification test failed: ${error.message}`, "warn");
  }
}

async function deleteNotificationChannel(channelId) {
  try {
    const result = await apiDelete(`/notifications/channels/${channelId}`, { optionalAuth: true });
    if (result?.unauthorized) {
      setAuthText("Deleting channel requires valid API key.", "warn");
      return;
    }
    setAuthText("Notification channel removed.", "ok");
    await refreshNotifications();
  } catch (error) {
    setAuthText(`Channel removal failed: ${error.message}`, "warn");
  }
}

async function refreshDashboard() {
  try {
    const health = await apiGet("/health");
    applyHealth(health);

    const [alerts, incidents, campaigns, notifications] = await Promise.all([
      apiGet("/alerts?limit=30", { optionalAuth: true }),
      apiGet("/incidents?active_within_hours=24", { optionalAuth: true }),
      apiGet("/campaigns?limit=20", { optionalAuth: true }),
      apiGet("/notifications/channels", { optionalAuth: true }),
    ]);

    if (alerts?.unauthorized || incidents?.unauthorized || campaigns?.unauthorized || notifications?.unauthorized) {
      setAuthText("Protected data unavailable. Add valid API key.", "warn");
      el.dashboardStatus.textContent = "Status: limited access";
      return;
    }

    renderAlerts(alerts || []);
    renderIncidents(incidents || []);
    renderCampaigns(campaigns || []);
    renderNotificationChannels(notifications.channels || []);

    el.alertsMeta.textContent = `${alerts.length} records`;
    el.incidentsMeta.textContent = `${incidents.length} records`;
    el.campaignsMeta.textContent = `${campaigns.length} records`;
    el.notificationsMeta.textContent = `${notifications.count || 0} channels`;
    el.dashboardStatus.textContent = "Status: live";

    if (getApiKey()) {
      setAuthText("Authenticated and receiving protected telemetry.", "ok");
    }
  } catch (error) {
    el.dashboardStatus.textContent = `Status: error (${error.message})`;
  } finally {
    el.lastRefresh.textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
  }
}

function bootstrap() {
  const existing = getApiKey();
  if (existing) {
    el.apiKey.value = existing;
    setAuthText("API key loaded from secure local storage.", "ok");
  }

  el.saveKey.addEventListener("click", () => {
    const key = el.apiKey.value.trim();
    setApiKey(key);
    if (key) {
      setAuthText("API key saved. Reconnecting...", "ok");
    } else {
      setAuthText("API key removed. Public mode only.", "warn");
    }
    refreshDashboard();
  });

  el.runDemo.addEventListener("click", async () => {
    try {
      el.dashboardStatus.textContent = "Status: loading demo data";
      const tx = await apiPost("/simulate/run", undefined, { optionalAuth: true });
      const mp = await apiPost("/simulate/mempool", undefined, { optionalAuth: true });

      if (tx?.unauthorized || mp?.unauthorized) {
        setAuthText("Demo run needs valid API key in secured mode.", "warn");
        el.dashboardStatus.textContent = "Status: demo blocked (unauthorized)";
        return;
      }

      setAuthText("Demo data ingested successfully.", "ok");
      el.dashboardStatus.textContent = "Status: demo data loaded";
      await refreshDashboard();
    } catch (error) {
      setAuthText(`Demo run failed: ${error.message}`, "warn");
      el.dashboardStatus.textContent = "Status: demo run failed";
    }
  });

  el.notifyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const destination = el.notifyDestination.value.trim();
    if (!destination) {
      setAuthText("Destination is required for notification channel.", "warn");
      return;
    }

    try {
      const payload = {
        provider: el.notifyProvider.value,
        destination,
        min_severity: el.notifySeverity.value,
        enabled: true,
      };
      const result = await apiPost("/notifications/channels", payload, { optionalAuth: true });
      if (result?.unauthorized) {
        setAuthText("Adding channels requires valid API key.", "warn");
        return;
      }
      el.notifyDestination.value = "";
      setAuthText("Notification channel saved.", "ok");
      await refreshNotifications();
    } catch (error) {
      setAuthText(`Unable to save channel: ${error.message}`, "warn");
    }
  });

  el.notifyTestAll.addEventListener("click", async () => {
    await sendChannelTest(null);
  });

  refreshDashboard();
  window.setInterval(refreshDashboard, REFRESH_MS);
}

bootstrap();
