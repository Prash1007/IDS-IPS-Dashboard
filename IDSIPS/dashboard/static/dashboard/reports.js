const REPORTS_API_URL = "/api/reports/";

let reportsDailyChart = null;
let reportsActionChart = null;
let reportsPayload = null;

function reportsSet(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function renderReportsStats(summary) {
  reportsSet("reportsTotalAlerts", (summary.total_alerts || 0).toLocaleString());
  reportsSet("reportsLast24", (summary.last_24h || 0).toLocaleString());
  reportsSet("reportsActiveBlocks", summary.active_blocks || 0);
  reportsSet("reportsAutoBlocks", summary.auto_blocks || 0);
  if (typeof window.updateModeLabels === "function") window.updateModeLabels(summary.mode || "IDS");
}

function renderReportsLists() {
  const queue = document.getElementById("reportsAutomationQueue");
  const actions = document.getElementById("reportsRecentActions");
  const blocked = document.getElementById("reportsBlockedIps");
  if (!queue || !actions || !blocked || !reportsPayload) return;

  queue.innerHTML = "";
  (reportsPayload.automation_queue || []).forEach((item) => {
    const row = document.createElement("div");
    row.className = "reports-item";
    row.innerHTML = `
      <div class="reports-item-top">
        <span class="reports-item-title">${escapeHTML(item.title)}</span>
        <span class="reports-pill ${safeClassToken(item.status)}">${escapeHTML(item.type)}</span>
      </div>
      <div class="reports-item-meta">${escapeHTML(item.detail)}</div>`;
    queue.appendChild(row);
  });

  actions.innerHTML = "";
  (reportsPayload.recent_actions || []).forEach((item) => {
    const row = document.createElement("div");
    row.className = "reports-item";
    row.innerHTML = `
      <div class="reports-item-top">
        <span class="reports-item-title">${escapeHTML(item.action_type.replace("_", " "))}</span>
        <span class="reports-pill watch">${escapeHTML(item.source)}</span>
      </div>
      <div class="reports-item-meta">${item.ip ? `${escapeHTML(item.ip)}<br>` : ""}${escapeHTML(item.reason || "No reason captured")}<br>${humanDate(item.timestamp)}</div>`;
    actions.appendChild(row);
  });

  blocked.innerHTML = "";
  (reportsPayload.blocked_ips || []).slice(0, 8).forEach((item) => {
    const row = document.createElement("div");
    row.className = "reports-item";
    row.innerHTML = `
      <div class="reports-item-top">
        <span class="reports-item-title">${escapeHTML(item.ip)}</span>
        <span class="reports-pill pending">x${item.block_count}</span>
      </div>
      <div class="reports-item-meta">${escapeHTML(item.attack_type || item.reason || "Manual response")}<br>${item.active ? "Active block" : "Released"} • ${escapeHTML(item.source)}</div>`;
    blocked.appendChild(row);
  });
}

function renderReportsCharts() {
  if (!reportsPayload) return;
  const dailyLabels = (reportsPayload.daily_alerts || []).map((item) => item.label);
  const dailyData = (reportsPayload.daily_alerts || []).map((item) => item.count);

  if (!reportsDailyChart) {
    const ctx = document.getElementById("reportsDailyChart");
    if (!ctx) return;
    reportsDailyChart = new Chart(ctx.getContext("2d"), {
      type: "bar",
      data: {
        labels: dailyLabels,
        datasets: [{
          label: "Alerts",
          data: dailyData,
          borderRadius: 10,
          backgroundColor: "rgba(59,130,246,0.45)",
          borderColor: "#3b82f6",
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
      },
    });
  } else {
    reportsDailyChart.data.labels = dailyLabels;
    reportsDailyChart.data.datasets[0].data = dailyData;
    reportsDailyChart.update("none");
  }

  const actionLabels = (reportsPayload.action_breakdown || []).map((item) => item.label);
  const actionData = (reportsPayload.action_breakdown || []).map((item) => item.count);
  const colors = ["#ef4444", "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6", "#06b6d4"];

  if (!reportsActionChart) {
    const ctx = document.getElementById("reportsActionChart");
    if (!ctx) return;
    reportsActionChart = new Chart(ctx.getContext("2d"), {
      type: "doughnut",
      data: {
        labels: actionLabels,
        datasets: [{
          data: actionData,
          backgroundColor: colors.slice(0, actionLabels.length).map((color) => `${color}bb`),
          borderColor: colors.slice(0, actionLabels.length),
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: { legend: { position: "bottom", labels: { color: "#94a3b8" } } },
      },
    });
  } else {
    reportsActionChart.data.labels = actionLabels;
    reportsActionChart.data.datasets[0].data = actionData;
    reportsActionChart.update("none");
  }
}

async function loadReports() {
  const response = await fetch(REPORTS_API_URL, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  reportsPayload = await response.json();
  renderReportsStats(reportsPayload.summary || {});
  renderReportsLists();
  renderReportsCharts();
}

function exportCSV() {
  if (!reportsPayload) return;
  const rows = [
    ["Section", "Name", "Value", "Detail"],
    ...(reportsPayload.top_attacks || []).map((item) => ["Top Attack", item.attack_type, item.count, ""]),
    ...(reportsPayload.automation_queue || []).map((item) => ["Automation Queue", item.title, item.status, item.detail]),
  ];
  const blob = new Blob([rows.map((row) => row.join(",")).join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `reports-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function exportPDF() {
  if (!reportsPayload) return;
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
  doc.text("Security Reports Summary", 14, 16);
  doc.setTextColor(148, 163, 184);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`Generated ${new Date().toLocaleString()} | Alerts ${reportsPayload.summary?.total_alerts || 0}`, 14, 23);
  doc.autoTable({
    startY: 30,
    head: [["#", "Title", "Type", "Status / Count", "Detail"]],
    body: (reportsPayload.automation_queue || []).slice(0, 80).map((item, index) => [
      index + 1,
      item.title,
      item.type,
      item.status,
      item.detail,
    ]),
    styles: { fillColor: [17, 28, 53], textColor: [226, 232, 240], lineColor: [30, 50, 90], lineWidth: 0.3, fontSize: 7.5 },
    headStyles: { fillColor: [11, 21, 40], textColor: [148, 163, 184], fontStyle: "bold", fontSize: 7 },
    alternateRowStyles: { fillColor: [13, 21, 40] },
  });
  doc.save(`reports-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.pdf`);
}

window.exportCSV = exportCSV;
window.exportPDF = exportPDF;

document.addEventListener("DOMContentLoaded", async () => {
  try {
    await loadReports();
  } catch (error) {
    console.error("loadReports:", error);
    showToast("Failed to load reports", "red");
  }

  if (typeof window.startLiveFeed === "function") {
    window.startLiveFeed({
      interval: 1800,
      onData(payload) {
        if ((payload.alerts || []).length || (payload.actions || []).length) {
          loadReports().catch((error) => console.error("reports live refresh:", error));
        }
      },
    });
  }
});
