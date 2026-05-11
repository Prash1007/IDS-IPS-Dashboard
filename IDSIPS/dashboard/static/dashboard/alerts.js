const ALERTS_PAGE_URL = "/api/alerts/?limit=all";
const ALERTS_BLOCKED_URL = "/api/blocked-ips/?limit=80";
const ALERTS_ACTIONS_URL = "/api/actions/?limit=60";
const ALERTS_STATS_URL = "/api/stats/";
const ALERTS_BLOCK_URL = "/api/block/";
const ALERTS_UNBLOCK_URL = "/api/unblock/";

let alertsData = [];
let blockedRegistry = [];
let actionData = [];
let alertsSearch = "";

function alertResponseClass(value) {
  return (value || "alerted").toLowerCase();
}

function setKpi(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function renderAlertsStream() {
  const tbody = document.getElementById("alertsStreamBody");
  if (!tbody) return;

  const severityFilter = document.getElementById("alertsSeverityFilter")?.value || "";
  const responseFilter = document.getElementById("alertsResponseFilter")?.value || "";

  const filtered = alertsData.filter((alert) => {
    if (severityFilter && alert.severity !== severityFilter) return false;
    if (responseFilter && alert.response_action !== responseFilter) return false;
    if (alertsSearch) {
      const haystack = [
        alert.src_ip,
        alert.dest_ip,
        alert.attack_type,
        alert.response_action,
        alert.mode_at_detection,
        alert.protocol,
      ].join(" ").toLowerCase();
      if (!haystack.includes(alertsSearch)) return false;
    }
    return true;
  });

  tbody.innerHTML = "";
  const fragment = document.createDocumentFragment();
  filtered.forEach((alert) => {
    const row = document.createElement("tr");
    const actionButton = document.createElement("button");
    actionButton.className = alert.blocked ? "btn btn-sm btn-ghost" : "btn btn-sm btn-danger-outline";
    actionButton.type = "button";
    actionButton.textContent = alert.blocked ? "Unblock" : "Block";
    actionButton.addEventListener("click", () => (alert.blocked ? alertsUnblock(alert.src_ip) : alertsBlock(alert.src_ip)));
    row.innerHTML = `
      <td><span class="severity ${getSevClass(alert.severity)}">● ${escapeHTML((alert.severity || "low").toUpperCase())}</span></td>
      <td title="${escapeHTML(alert.description || "")}">${escapeHTML(alert.attack_type || "Unknown")}</td>
      <td><span class="ip-addr">${escapeHTML(alert.src_ip || "—")}</span></td>
      <td><span class="ip-addr">${escapeHTML(alert.dest_ip || "—")}</span></td>
      <td><span class="proto">${escapeHTML((alert.protocol || "tcp").toUpperCase())}</span></td>
      <td><span class="proto">${escapeHTML(alert.mode_at_detection || "IDS")}</span></td>
      <td><span class="alerts-response ${safeClassToken(alertResponseClass(alert.response_action))}">${escapeHTML(alert.response_action || "alerted")}</span></td>
      <td><span class="time-ago">${humanDate(alert.timestamp)}</span></td>
      <td></td>`;
    row.querySelector("td:last-child")?.appendChild(actionButton);
    fragment.appendChild(row);
  });
  tbody.appendChild(fragment);
}

function renderBlockedRegistry() {
  const list = document.getElementById("alertsBlockedList");
  if (!list) return;
  document.getElementById("alertsBlockedBadge").textContent = blockedRegistry.length;
  list.innerHTML = "";

  if (!blockedRegistry.length) {
    list.innerHTML = '<div class="alerts-block-item"><div class="alerts-meta">No blocked IP history found yet.</div></div>';
    return;
  }

  blockedRegistry.forEach((item) => {
    const wrapper = document.createElement("div");
    wrapper.className = "alerts-block-item";
    wrapper.innerHTML = `
      <div class="alerts-block-top">
        <span class="alerts-block-ip">${escapeHTML(item.ip)}</span>
        <span class="alerts-pill ${item.active ? "active" : "inactive"}">${item.active ? "ACTIVE" : "RELEASED"}</span>
      </div>
      <div class="alerts-meta">
        ${escapeHTML(item.attack_type || "Manual response")} • ${escapeHTML(item.severity || "low")} severity • ${escapeHTML(item.source)}<br>
        ${escapeHTML(item.reason || "No reason captured")}<br>
        Last block: ${item.last_blocked_at ? humanDate(item.last_blocked_at) : "—"} • Count: ${item.block_count}
      </div>
    `;
    list.appendChild(wrapper);
  });
}

function renderActions() {
  const list = document.getElementById("alertsActionList");
  if (!list) return;
  list.innerHTML = "";

  if (!actionData.length) {
    list.innerHTML = '<div class="alerts-action-item"><div class="alerts-meta">No control-plane actions have been logged yet.</div></div>';
    return;
  }

  actionData.forEach((action) => {
    const wrapper = document.createElement("div");
    wrapper.className = "alerts-action-item";
    wrapper.innerHTML = `
      <div class="alerts-action-top">
        <span class="alerts-action-label">${escapeHTML(action.action_type.replace("_", " "))}</span>
        <span class="alerts-pill ${action.status === "success" ? "inactive" : "active"}">${escapeHTML(action.source)}</span>
      </div>
      <div class="alerts-meta">
        ${action.ip ? `<span class="ip-addr">${escapeHTML(action.ip)}</span><br>` : ""}
        ${escapeHTML(action.reason || "No reason captured")}<br>
        ${action.mode ? `Mode: ${escapeHTML(action.mode)} • ` : ""}${humanDate(action.timestamp)}
      </div>
    `;
    list.appendChild(wrapper);
  });
}

async function fetchAlertsPageData() {
  const [alertsResp, blockedResp, actionsResp, statsResp] = await Promise.all([
    fetch(ALERTS_PAGE_URL, { cache: "no-store" }),
    fetch(ALERTS_BLOCKED_URL, { cache: "no-store" }),
    fetch(ALERTS_ACTIONS_URL, { cache: "no-store" }),
    fetch(ALERTS_STATS_URL, { cache: "no-store" }),
  ]);

  if (!alertsResp.ok || !blockedResp.ok || !actionsResp.ok || !statsResp.ok) {
    throw new Error("Failed to load alerts page data");
  }

  const alertsPayload = await alertsResp.json();
  const blockedPayload = await blockedResp.json();
  const actionsPayload = await actionsResp.json();
  const statsPayload = await statsResp.json();

  alertsData = alertsPayload.alerts || [];
  blockedRegistry = blockedPayload.blocked_ips || [];
  actionData = actionsPayload.actions || [];

  setKpi("alerts-total", (statsPayload.total_alerts || 0).toLocaleString());
  setKpi("alerts-last24", (statsPayload.last_24h || 0).toLocaleString());
  setKpi("alerts-active-blocks", statsPayload.blocked_ips || 0);
  setKpi("alerts-auto-blocks", statsPayload.auto_blocks || 0);
  if (typeof window.updateSidebarAlertBadge === "function") window.updateSidebarAlertBadge(statsPayload.total_alerts || 0);
  if (typeof window.updateModeLabels === "function") window.updateModeLabels(statsPayload.mode || "IDS");

  renderAlertsStream();
  renderBlockedRegistry();
  renderActions();
}

async function alertsBlock(ip) {
  try {
    const response = await fetch(ALERTS_BLOCK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrf() },
      body: JSON.stringify({ ip, reason: "Manual block from alerts page" }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    showToast(payload.sync?.message || `Blocked ${ip}`, payload.sync?.success === false ? "red" : (payload.sync?.configured ? "green" : "yellow"));
    await fetchAlertsPageData();
  } catch (error) {
    console.error("alertsBlock:", error);
    showToast("Block request failed", "red");
  }
}

async function alertsUnblock(ip) {
  try {
    const response = await fetch(ALERTS_UNBLOCK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrf() },
      body: JSON.stringify({ ip }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    showToast(payload.sync?.message || `Unblocked ${ip}`, payload.sync?.success === false ? "red" : (payload.sync?.configured ? "green" : "yellow"));
    await fetchAlertsPageData();
  } catch (error) {
    console.error("alertsUnblock:", error);
    showToast("Unblock request failed", "red");
  }
}

function exportCSV() {
  const rows = [
    ["ID", "Time", "Severity", "Attack", "Attack Source IP", "Target IP", "Protocol", "Mode", "Response"],
    ...alertsData.map((alert) => [
      alert.id,
      humanDate(alert.timestamp),
      alert.severity,
      `"${(alert.attack_type || "").replace(/"/g, '""')}"`,
      alert.src_ip || "",
      alert.dest_ip || "",
      alert.protocol || "",
      alert.mode_at_detection || "",
      alert.response_action || "",
    ]),
  ];
  const blob = new Blob([rows.map((row) => row.join(",")).join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `alerts-stream-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function exportPDF() {
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
  doc.text("Alerts Response Ledger", 14, 16);
  doc.setTextColor(148, 163, 184);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`Generated ${new Date().toLocaleString()} | Alerts ${alertsData.length} | Blocks ${blockedRegistry.length}`, 14, 23);
  doc.autoTable({
    startY: 30,
    head: [["#", "Time", "Severity", "Attack", "Attack Source IP", "Target IP", "Mode", "Response"]],
    body: alertsData.slice(0, 140).map((alert, index) => [
      index + 1,
      humanDate(alert.timestamp),
      alert.severity,
      alert.attack_type,
      alert.src_ip,
      alert.dest_ip || "—",
      alert.mode_at_detection || "IDS",
      alert.response_action || "alerted",
    ]),
    styles: { fillColor: [17, 28, 53], textColor: [226, 232, 240], lineColor: [30, 50, 90], lineWidth: 0.3, fontSize: 7.5 },
    headStyles: { fillColor: [11, 21, 40], textColor: [148, 163, 184], fontStyle: "bold", fontSize: 7 },
    alternateRowStyles: { fillColor: [13, 21, 40] },
  });
  doc.save(`alerts-stream-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.pdf`);
}

window.alertsBlock = alertsBlock;
window.alertsUnblock = alertsUnblock;
window.exportCSV = exportCSV;
window.exportPDF = exportPDF;

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("alertsSeverityFilter")?.addEventListener("change", renderAlertsStream);
  document.getElementById("alertsResponseFilter")?.addEventListener("change", renderAlertsStream);
  document.getElementById("filterInput")?.addEventListener("input", (event) => {
    alertsSearch = event.target.value.trim().toLowerCase();
    renderAlertsStream();
  });
  document.getElementById("clearFilter")?.addEventListener("click", () => {
    alertsSearch = "";
    renderAlertsStream();
  });

  try {
    await fetchAlertsPageData();
  } catch (error) {
    console.error("fetchAlertsPageData:", error);
    showToast("Failed to load alerts page", "red");
  }

  if (typeof window.startLiveFeed === "function") {
    window.startLiveFeed({
      interval: 1200,
      onData(payload) {
        if ((payload.alerts || []).length || (payload.actions || []).length) {
          fetchAlertsPageData().catch((error) => console.error("alerts live refresh:", error));
        }
      },
    });
  }
});
