const ALERTS_URL = "/api/alerts/?limit=80";
const STATS_URL = "/api/stats/";
const BLOCK_URL = "/api/block/";
const UNBLOCK_URL = "/api/unblock/";
const MODE_URL = "/api/mode/";
const BLOCKED_IPS_URL = "/api/blocked-ips/?active_only=1&limit=50";

let timelineChart = null;
let donutChart = null;
let allAlerts = [];
let blockedIps = [];
let currentFilter = "";
let lastRenderedIds = new Set();

const DONUT_COLORS = ["#ef4444", "#f97316", "#f59e0b", "#3b82f6", "#8b5cf6", "#06b6d4", "#10b981", "#e879f9"];

function buildSparkline(id, values, peakColor) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = "";
  const max = Math.max(...values, 1);
  values.forEach((value) => {
    const bar = document.createElement("div");
    bar.className = `spark-bar${value === max ? " peak" : ""}`;
    bar.style.height = `${Math.max(4, Math.round((value / max) * 100))}%`;
    if (peakColor && !bar.classList.contains("peak")) bar.style.background = peakColor;
    el.appendChild(bar);
  });
}

function buildSparklines() {
  const now = Date.now();
  const buckets = Array(24).fill(0);
  allAlerts.forEach((alert) => {
    const age = (now - new Date(alert.timestamp).getTime()) / 3600000;
    if (age <= 24) buckets[23 - Math.min(23, Math.floor(age))] += 1;
  });
  buildSparkline("spark1", buckets, "rgba(239,68,68,0.3)");
  buildSparkline("spark3", buckets, "rgba(16,185,129,0.3)");
  buildSparkline("spark2", blockedIps.map((_, index) => (index % 5) + 1).concat(Array(24).fill(0)).slice(0, 24), "rgba(59,130,246,0.3)");
  buildSparkline("spark4", Array(24).fill(1), "rgba(139,92,246,0.3)");
}

function updateSevBars(alerts) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  alerts.forEach((alert) => {
    const key = (alert.severity || "low").toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  });
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0) || 1;
  ["critical", "high", "medium", "low"].forEach((severity) => {
    const bar = document.getElementById(`bar-${severity}`);
    const count = document.getElementById(`count-${severity}`);
    if (bar) bar.style.width = `${Math.round((counts[severity] / total) * 100)}%`;
    if (count) count.textContent = counts[severity];
  });
}

function updateTopThreats(alerts) {
  const counts = {};
  alerts.forEach((alert) => {
    counts[alert.attack_type] = (counts[alert.attack_type] || 0) + 1;
  });
  const rows = Object.entries(counts).sort((left, right) => right[1] - left[1]).slice(0, 6);
  const list = document.getElementById("threatList");
  if (!list) return;
  list.innerHTML = "";
  if (!rows.length) {
    list.innerHTML = '<div class="threat-row"><span class="threat-name" style="color:var(--text-muted)">No attack signatures yet</span></div>';
    return;
  }
  rows.forEach(([name, count], index) => {
    const row = document.createElement("div");
    row.className = "threat-row";
    row.innerHTML = `<span class="threat-num">#${index + 1}</span><span class="threat-name" title="${escapeHTML(name)}">${escapeHTML(name)}</span><span class="threat-count">${count}</span>`;
    list.appendChild(row);
  });
}

function updateBlockedList() {
  const list = document.getElementById("blockedList");
  const badge = document.getElementById("blocked-badge");
  const kpiBlocked = document.getElementById("kpi-blocked");
  if (badge) badge.textContent = blockedIps.length;
  if (kpiBlocked) kpiBlocked.textContent = blockedIps.length;
  if (!list) return;
  list.innerHTML = "";
  if (!blockedIps.length) {
    list.innerHTML = '<li style="color:var(--text-muted);font-size:12px;text-align:center;padding:14px;list-style:none"><i class="fas fa-shield-check" style="color:var(--accent-green)"></i> No IPs blocked</li>';
    return;
  }
  blockedIps.forEach((item) => {
    const li = document.createElement("li");
    li.className = "blocked-item";
    const unblockBtn = document.createElement("button");
    unblockBtn.className = "btn btn-sm btn-ghost";
    unblockBtn.type = "button";
    unblockBtn.textContent = "Unblock";
    unblockBtn.addEventListener("click", () => doUnblock(item.ip));
    li.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:2px;min-width:0">
        <span class="blocked-ip">${escapeHTML(item.ip)}</span>
        <span style="font-size:10px;color:var(--text-muted)">${escapeHTML(item.attack_type || item.reason || "Manual response")} • ${escapeHTML(item.source)}</span>
      </div>`;
    li.appendChild(unblockBtn);
    list.appendChild(li);
  });
}

function renderAlerts(alerts) {
  const tbody = document.getElementById("alertsBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const newIds = new Set(alerts.filter((alert) => !lastRenderedIds.has(alert.id)).map((alert) => alert.id));
  lastRenderedIds = new Set(alerts.map((alert) => alert.id));

  const timeBuckets = {};
  const topTypes = {};

  alerts.forEach((alert) => {
    topTypes[alert.attack_type] = (topTypes[alert.attack_type] || 0) + 1;
    const time = new Date(alert.timestamp);
    const bucket = `${String(time.getHours()).padStart(2, "0")}:${String(time.getMinutes()).padStart(2, "0")}`;
    timeBuckets[bucket] = (timeBuckets[bucket] || 0) + 1;

    const row = document.createElement("tr");
    if (newIds.has(alert.id)) row.classList.add("new-row");

    const actionCell = document.createElement("td");
    if (alert.blocked) {
      actionCell.innerHTML = `<span class="action-block" title="${escapeHTML(alert.response_action || "blocked")}"><i class="fas fa-ban"></i> ${escapeHTML(alert.response_action || "Blocked")}</span>`;
    } else {
      const blockBtn = document.createElement("button");
      blockBtn.className = "btn btn-sm btn-danger-outline";
      blockBtn.type = "button";
      blockBtn.textContent = "Block IP";
      blockBtn.addEventListener("click", () => doBlock(alert.src_ip));
      actionCell.appendChild(blockBtn);
    }

    row.innerHTML = `
      <td><span class="severity ${getSevClass(alert.severity)}">● ${escapeHTML((alert.severity || "low").toUpperCase())}</span></td>
      <td style="font-size:11.5px;font-weight:600" title="${escapeHTML(alert.attack_type || "")}">${escapeHTML(alert.attack_type || "Unknown")}</td>
      <td><span class="ip-addr">${escapeHTML(alert.src_ip || "—")}</span></td>
      <td><span class="ip-addr">${escapeHTML(alert.dest_ip || "—")}</span></td>
      <td><span class="proto">${escapeHTML((alert.protocol || "tcp").toUpperCase())}</span></td>
      <td><span class="time-ago ${isRecent(alert.timestamp) ? "time-now" : ""}">${isRecent(alert.timestamp) ? "just now" : humanTime(alert.timestamp)}</span></td>`;
    row.insertBefore(actionCell, row.lastElementChild);
    tbody.appendChild(row);
  });

  const visibleCount = document.getElementById("visible-count");
  if (visibleCount) visibleCount.textContent = alerts.length;

  updateCharts(timeBuckets, topTypes);
  updateSevBars(alerts);
  updateTopThreats(alerts);
}

Chart.defaults.color = "#94a3b8";
Chart.defaults.borderColor = "rgba(59,130,246,0.06)";

function updateCharts(timeBuckets, topTypes) {
  const timelineLabels = Object.keys(timeBuckets).sort();
  const timelineData = timelineLabels.map((label) => timeBuckets[label]);

  if (!timelineChart) {
    const ctx = document.getElementById("timelineChart");
    if (!ctx) return;
    timelineChart = new Chart(ctx.getContext("2d"), {
      type: "line",
      data: {
        labels: timelineLabels,
        datasets: [{
          label: "Alerts",
          data: timelineData,
          borderColor: "#ef4444",
          borderWidth: 2,
          tension: 0.45,
          fill: true,
          pointRadius: 0,
          backgroundColor: (context) => {
            const gradient = context.chart.ctx.createLinearGradient(0, 0, 0, 170);
            gradient.addColorStop(0, "rgba(239,68,68,0.18)");
            gradient.addColorStop(1, "rgba(239,68,68,0.00)");
            return gradient;
          },
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
      },
    });
  } else {
    timelineChart.data.labels = timelineLabels;
    timelineChart.data.datasets[0].data = timelineData;
    timelineChart.update("none");
  }

  const donutLabels = Object.keys(topTypes).slice(0, 8);
  const donutData = donutLabels.map((label) => topTypes[label]);

  if (!donutChart) {
    const ctx = document.getElementById("donutChart");
    if (!ctx) return;
    donutChart = new Chart(ctx.getContext("2d"), {
      type: "doughnut",
      data: {
        labels: donutLabels,
        datasets: [{
          data: donutData,
          backgroundColor: DONUT_COLORS.slice(0, donutLabels.length).map((color) => `${color}bb`),
          borderColor: DONUT_COLORS.slice(0, donutLabels.length),
          borderWidth: 2,
        }],
      },
      options: {
        responsive: false,
        cutout: "70%",
        plugins: { legend: { display: false } },
      },
    });
  } else {
    donutChart.data.labels = donutLabels;
    donutChart.data.datasets[0].data = donutData;
    donutChart.data.datasets[0].backgroundColor = DONUT_COLORS.slice(0, donutLabels.length).map((color) => `${color}bb`);
    donutChart.data.datasets[0].borderColor = DONUT_COLORS.slice(0, donutLabels.length);
    donutChart.update("none");
  }

  const legend = document.getElementById("donutLegend");
  if (!legend) return;
  legend.innerHTML = "";
  const total = donutData.reduce((sum, value) => sum + value, 0) || 1;
  donutLabels.forEach((label, index) => {
    const row = document.createElement("div");
    row.className = "dl-row";
    row.innerHTML = `
      <span style="display:flex;align-items:center;min-width:0;overflow:hidden">
        <span class="dl-dot" style="background:${DONUT_COLORS[index] || "#888"}"></span>
        <span style="color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHTML(label)}</span>
      </span>
      <span class="dl-count">${Math.round((donutData[index] / total) * 100)}%</span>`;
    legend.appendChild(row);
  });
}

function updateAIInsights(stats, actions = []) {
  const panel = document.getElementById("aiPanel");
  if (!panel) return;

  const items = [];
  const topAttack = stats.top_attacks?.[0];
  if (topAttack) {
    items.push({
      tone: "critical",
      title: `${topAttack.attack_type} leading the queue`,
      text: `${topAttack.count} detections observed in the current dataset. Review whether this signature needs auto-response tuning.`,
      meta: "Threat focus",
    });
  }

  const autoBlocks = stats.auto_blocks || 0;
  items.push({
    tone: autoBlocks > 0 ? "warning" : "info",
    title: autoBlocks > 0 ? "IPS/Hybrid auto-response is active" : "No automatic block yet",
    text: autoBlocks > 0
      ? `${autoBlocks} automatic containment actions have been recorded from the current response engine.`
      : "The dashboard is ready to show automatic containment as soon as IPS or HYBRID rules trigger.",
    meta: `Mode ${stats.mode || "IDS"}`,
  });

  const recentAction = actions[0] || stats.recent_actions?.[0];
  if (recentAction) {
    items.push({
      tone: recentAction.action_type === "BLOCK" ? "critical" : "info",
      title: `${recentAction.action_type.replace("_", " ")} event recorded`,
      text: recentAction.ip
        ? `${recentAction.ip} processed via ${recentAction.source}. ${recentAction.reason || "Response logged successfully."}`
        : recentAction.reason || "A new control-plane action has been logged.",
      meta: humanTime(recentAction.timestamp),
    });
  }

  panel.innerHTML = items.slice(0, 3).map((item) => `
    <div class="insight-item ${safeClassToken(item.tone)}">
      <div class="insight-title">${escapeHTML(item.title)}</div>
      <div class="insight-text">${escapeHTML(item.text)}</div>
      <div class="insight-meta">
        <span class="ai-badge"><i class="fas fa-robot" style="font-size:9px"></i> AI Ready</span>
        <span class="insight-time">${escapeHTML(item.meta)}</span>
      </div>
    </div>`).join("");
}

function applyStats(stats) {
  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };

  setText("kpi-total-alerts", (stats.total_alerts || 0).toLocaleString());
  setText("kpi-last24h", (stats.last_24h || 0).toLocaleString());
  setText("kpi-sub-24", `${stats.last_24h || 0} in last 24h`);
  setText("stat-total2", (stats.total_alerts || 0).toLocaleString());
  setText("stat-last24", (stats.last_24h || 0).toLocaleString());
  setText("stat-blocked", stats.blocked_ips || 0);
  if (typeof window.updateSidebarAlertBadge === "function") window.updateSidebarAlertBadge(stats.total_alerts || 0);
  if (typeof window.updateModeLabels === "function") window.updateModeLabels(stats.mode || "");
  updateAIInsights(stats);
}

function filteredAlerts() {
  const term = currentFilter.trim().toLowerCase();
  if (!term) return allAlerts;
  return allAlerts.filter((alert) =>
    [alert.src_ip, alert.dest_ip, alert.attack_type, alert.severity, alert.protocol, alert.response_action]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(term)),
  );
}

async function fetchAlerts() {
  const response = await fetch(ALERTS_URL, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const payload = await response.json();
  allAlerts = payload.alerts || [];
  renderAlerts(filteredAlerts());
  buildSparklines();
}

async function fetchStats() {
  const response = await fetch(STATS_URL, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const payload = await response.json();
  applyStats(payload);
  return payload;
}

async function fetchBlockedIps() {
  const response = await fetch(BLOCKED_IPS_URL, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const payload = await response.json();
  blockedIps = payload.blocked_ips || [];
  updateBlockedList();
  buildSparklines();
}

async function refreshDashboardData() {
  const [stats] = await Promise.all([fetchStats(), fetchAlerts(), fetchBlockedIps()]);
  updateAIInsights(stats);
}

async function doBlock(ip) {
  if (!confirm(`Block IP: ${ip}?\nAll alerts from this IP will be marked blocked.`)) return;
  try {
    const response = await fetch(BLOCK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrf() },
      body: JSON.stringify({ ip, reason: "Manual block from dashboard" }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    showToast(payload.sync?.message || `Blocked ${ip}`, payload.sync?.success === false ? "red" : (payload.sync?.configured ? "green" : "yellow"));
    await refreshDashboardData();
  } catch (error) {
    console.error("doBlock:", error);
    showToast(`Failed to block ${ip}`, "red");
  }
}

async function doUnblock(ip) {
  if (!confirm(`Unblock ${ip}?`)) return;
  try {
    const response = await fetch(UNBLOCK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrf() },
      body: JSON.stringify({ ip }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    showToast(payload.sync?.message || `Unblocked ${ip}`, payload.sync?.success === false ? "red" : (payload.sync?.configured ? "green" : "yellow"));
    await refreshDashboardData();
  } catch (error) {
    console.error("doUnblock:", error);
    showToast(`Failed to unblock ${ip}`, "red");
  }
}

async function setMode(mode) {
  try {
    const response = await fetch(MODE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrf() },
      body: JSON.stringify({ mode }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    if (typeof window.updateModeLabels === "function") window.updateModeLabels(payload.mode);
    const select = document.getElementById("modeSelect");
    if (select) select.value = payload.mode;
    showToast(`Mode switched to ${payload.mode}`, payload.mode === "IDS" ? "green" : "blue");
    await refreshDashboardData();
  } catch (error) {
    console.error("setMode:", error);
    showToast("Failed to switch mode", "red");
  }
}

function exportCSV() {
  document.getElementById("exportMenu")?.classList.remove("open");
  if (!allAlerts.length) {
    showToast("No alerts to export", "blue");
    return;
  }

  const rows = [
    ["ID", "Timestamp", "Severity", "Attack Type", "Source IP", "Dest IP", "Protocol", "Mode", "Response", "Blocked"],
    ...allAlerts.map((alert) => [
      alert.id,
      humanDate(alert.timestamp),
      (alert.severity || "low").toUpperCase(),
      `"${(alert.attack_type || "").replace(/"/g, '""')}"`,
      alert.src_ip || "",
      alert.dest_ip || "",
      alert.protocol || "",
      alert.mode_at_detection || "",
      alert.response_action || "",
      alert.blocked ? "YES" : "NO",
    ]),
  ];

  const blob = new Blob([rows.map((row) => row.join(",")).join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
  link.href = url;
  link.download = `dashboard-alerts-${stamp}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast(`Exported ${allAlerts.length} alerts as CSV`, "green");
}

async function exportPDF() {
  document.getElementById("exportMenu")?.classList.remove("open");
  if (!allAlerts.length) {
    showToast("No alerts to export", "blue");
    return;
  }

  if (typeof window.jspdf === "undefined" && typeof jspdf === "undefined") {
    showToast("PDF library not loaded.", "red");
    return;
  }

  const { jsPDF } = window.jspdf || jspdf;
  const doc = new jsPDF({ orientation: "landscape", unit: "mm", format: "a4" });
  doc.setFillColor(8, 13, 26);
  doc.rect(0, 0, 297, 210, "F");
  doc.setTextColor(59, 130, 246);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("AIBased IDS/IPS Dashboard Report", 14, 16);
  doc.setTextColor(148, 163, 184);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`Generated ${new Date().toLocaleString()} | Alerts ${allAlerts.length} | Active Blocks ${blockedIps.length}`, 14, 23);

  doc.autoTable({
    startY: 30,
    head: [["#", "Time", "Severity", "Attack", "Source", "Destination", "Protocol", "Mode", "Response"]],
    body: allAlerts.slice(0, 150).map((alert, index) => [
      index + 1,
      humanDate(alert.timestamp),
      (alert.severity || "low").toUpperCase(),
      alert.attack_type || "Unknown",
      alert.src_ip || "—",
      alert.dest_ip || "—",
      (alert.protocol || "tcp").toUpperCase(),
      alert.mode_at_detection || "IDS",
      alert.response_action || "alerted",
    ]),
    styles: {
      fillColor: [17, 28, 53],
      textColor: [226, 232, 240],
      lineColor: [30, 50, 90],
      lineWidth: 0.3,
      fontSize: 7.5,
    },
    headStyles: {
      fillColor: [11, 21, 40],
      textColor: [148, 163, 184],
      fontStyle: "bold",
      fontSize: 7,
    },
    alternateRowStyles: { fillColor: [13, 21, 40] },
  });

  doc.save(`dashboard-alerts-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.pdf`);
  showToast("PDF exported", "green");
}

window.doBlock = doBlock;
window.doUnblock = doUnblock;
window.exportCSV = exportCSV;
window.exportPDF = exportPDF;

document.addEventListener("DOMContentLoaded", async () => {
  const select = document.getElementById("modeSelect");
  if (select) select.value = document.getElementById("kpi-mode")?.textContent?.trim() || "IDS";

  document.getElementById("filterInput")?.addEventListener("input", (event) => {
    currentFilter = event.target.value;
    renderAlerts(filteredAlerts());
  });

  document.getElementById("clearFilter")?.addEventListener("click", () => {
    currentFilter = "";
    const input = document.getElementById("filterInput");
    if (input) input.value = "";
    renderAlerts(filteredAlerts());
  });

  document.getElementById("setModeBtn")?.addEventListener("click", () => {
    const mode = document.getElementById("modeSelect")?.value || "IDS";
    setMode(mode);
  });

  document.getElementById("panicBtn")?.addEventListener("click", () => {
    if (confirm("PANIC will switch the engine to IDS mode. Continue?")) setMode("IDS");
  });

  try {
    await refreshDashboardData();
  } catch (error) {
    console.error("refreshDashboardData:", error);
    showToast("Failed to load dashboard data", "red");
  }

  if (typeof window.startLiveFeed === "function") {
    window.startLiveFeed({
      interval: 1200,
      onData(payload) {
        if (payload.stats) applyStats(payload.stats);
        if ((payload.alerts || []).length || (payload.actions || []).length) {
          fetchAlerts().catch((error) => console.error("live fetchAlerts:", error));
          fetchBlockedIps().catch((error) => console.error("live fetchBlockedIps:", error));
          updateAIInsights(payload.stats || {}, payload.actions || []);
        }
      },
    });
  }
});
