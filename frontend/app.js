// === CONFIG ===
const BACKEND_URL = "https://neosecure-enterprise.onrender.com"; // change if needed

// === CLOCK ===
function updateClock() {
  const el = document.getElementById("system-time");
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// Set backend URL label
const backendUrlEl = document.getElementById("backend-url");
if (backendUrlEl) backendUrlEl.textContent = BACKEND_URL;

// === NAVIGATION ===
const pages = document.querySelectorAll(".page");
const navItems = document.querySelectorAll(".nav-item");

navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.getAttribute("data-page");
    // nav active
    navItems.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    // page active
    pages.forEach((p) => p.classList.remove("page-active"));
    const pageEl = document.getElementById(`page-${target}`);
    if (pageEl) pageEl.classList.add("page-active");
  });
});

// === STATS LOADING ===
async function loadStats() {
  const statusText = document.getElementById("engine-status-text");
  const healthIndicator = document.getElementById("engine-health-indicator");
  const healthLabel = document.getElementById("engine-health-label");
  const lastSyncEl = document.getElementById("last-sync");

  const totalEl = document.getElementById("metric-total");
  const blockedEl = document.getElementById("metric-blocked");
  const ratioEl = document.getElementById("metric-ratio");

  try {
    const res = await fetch(`${BACKEND_URL}/stats`);
    if (!res.ok) throw new Error("Stats request failed");
    const data = await res.json();

    // These names are flexible: try multiple options to match your backend.
    const total =
      data.total_events ??
      data.total ??
      data.events_total ??
      data.count ??
      0;

    const attacks =
      data.attack_count ??
      data.attacks_blocked ??
      data.blocked_healed ??
      data.attacks ??
      0;

    let ratio =
      data.attack_ratio ??
      (total > 0 ? (attacks / total) * 100 : 0);

    ratio = Number(ratio) || 0;

    // Update DOM
    if (totalEl) totalEl.textContent = total.toLocaleString();
    if (blockedEl) blockedEl.textContent = attacks.toLocaleString();
    if (ratioEl) ratioEl.textContent = `${ratio.toFixed(1)}%`;

    const lastEvent =
      data.last_event_at || data.last_sync || data.last_seen || null;
    if (lastSyncEl) {
      lastSyncEl.textContent = lastEvent
        ? new Date(lastEvent).toLocaleTimeString()
        : "—";
    }

    const engineOnline =
      data.engine_online ??
      data.engine_status ??
      data.online ??
      true;

    if (statusText) {
      statusText.textContent = engineOnline
        ? "Engine online"
        : "Engine offline";
    }

    if (healthIndicator && healthLabel) {
      if (engineOnline) {
        healthIndicator.style.borderColor = "#22c55e";
        healthIndicator.style.boxShadow =
          "0 0 16px rgba(34, 197, 94, 0.9)";
        healthLabel.textContent = "Healthy";
      } else {
        healthIndicator.style.borderColor = "#fb7185";
        healthIndicator.style.boxShadow =
          "0 0 16px rgba(248, 113, 113, 0.9)";
        healthLabel.textContent = "Degraded";
      }
    }
  } catch (err) {
    console.error("Error loading stats:", err);
    if (statusText) statusText.textContent = "Engine unreachable";
    if (healthIndicator) {
      healthIndicator.style.borderColor = "#fb7185";
      healthIndicator.style.boxShadow =
        "0 0 10px rgba(248, 113, 113, 0.8)";
    }
    if (healthLabel) healthLabel.textContent = "Error";
    if (lastSyncEl) lastSyncEl.textContent = "—";
  }
}

loadStats();
setInterval(loadStats, 5000);

// === ALERTS LOADING ===
async function loadAlerts() {
  const tbody = document.getElementById("alerts-body");
  if (!tbody) return;

  try {
    const res = await fetch(`${BACKEND_URL}/alerts?limit=50`);
    if (!res.ok) throw new Error("Alerts request failed");

    const alerts = await res.json();

    if (!Array.isArray(alerts) || alerts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">
            No alerts yet – send traffic to <code>POST /ingest</code> and events will appear here.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = "";

    alerts.forEach((a) => {
      const tr = document.createElement("tr");

      const tTime = a.created_at || a.timestamp || a.time;
      const tPath = a.path ?? a.url ?? "/";
      const tMethod = a.method ?? "GET";
      const tIssue = a.issue ?? a.attack_type ?? "—";
      const tAction = a.action ?? a.decision ?? "ALLOW";
      const tSeverity = a.severity ?? "medium";
      const tSource = a.source_ip ?? a.ip ?? "—";

      const severityClass = (() => {
        const s = String(tSeverity).toLowerCase();
        if (s.includes("crit")) return "badge-critical";
        if (s.includes("high")) return "badge-high";
        if (s.includes("low")) return "badge-low";
        return "badge-medium";
      })();

      tr.innerHTML = `
        <td>${tTime ? new Date(tTime).toLocaleTimeString() : "—"}</td>
        <td>${tPath}</td>
        <td>${tMethod}</td>
        <td>${tIssue}</td>
        <td>${tAction}</td>
        <td><span class="badge ${severityClass}">${tSeverity}</span></td>
        <td><span class="source-pill">${tSource}</span></td>
      `;

      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Error loading alerts:", err);
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-state">
          Could not reach backend /alerts. Check that the API is running on ${BACKEND_URL}.
        </td>
      </tr>
    `;
  }
}

loadAlerts();

// Refresh button
const refreshBtn = document.getElementById("refresh-alerts-btn");
if (refreshBtn) {
  refreshBtn.addEventListener("click", () => {
    loadAlerts();
  });
}
