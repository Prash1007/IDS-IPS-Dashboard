const THREAT_MAP_API_URL = "/api/threat-map/?limit=all";

const TM = {
  canvas: null,
  ctx: null,
  payload: null,

  init() {
    this.canvas = document.getElementById("tmCanvas");
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");
    this.resize();
    window.addEventListener("resize", () => {
      this.resize();
      this.draw();
    });
    this.load();
    if (typeof window.startLiveFeed === "function") {
      window.startLiveFeed({
        interval: 1600,
        onData(payload) {
          if ((payload.alerts || []).length) TM.load();
        },
      });
    }
  },

  resize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width;
    this.canvas.height = rect.height;
  },

  async load() {
    try {
      const response = await fetch(THREAT_MAP_API_URL, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      this.payload = await response.json();
      this.renderStats();
      this.renderLists();
      this.draw();
    } catch (error) {
      console.error("THREAT_MAP_API_URL:", error);
      showToast("Failed to load threat map", "red");
    }
  },

  renderStats() {
    const summary = this.payload?.summary || {};
    document.getElementById("tmOrigins").textContent = summary.total_origins || 0;
    document.getElementById("tmTargets").textContent = summary.total_targets || 0;
    document.getElementById("tmBlockedOrigins").textContent = summary.blocked_origins || 0;
    document.getElementById("tmPaths").textContent = summary.active_paths || 0;
  },

  renderLists() {
    const hotspots = document.getElementById("tmHotspots");
    const campaigns = document.getElementById("tmCampaigns");
    const corridors = document.getElementById("tmCorridors");
    if (!hotspots || !campaigns || !corridors) return;

    hotspots.innerHTML = "";
    (this.payload?.hotspots || []).forEach((item) => {
      const row = document.createElement("div");
      row.className = "tm-list-item";
      row.innerHTML = `
        <div class="tm-list-top">
          <span class="tm-list-title">${escapeHTML(item.ip)}</span>
          <span class="tm-pill ${item.blocked ? "blocked" : "clear"}">${item.count} alerts</span>
        </div>
        <div class="tm-meta">Attack Source - ${escapeHTML(item.latest_attack || "Unknown activity")} - ${escapeHTML(item.severity || "low")} severity</div>`;
      hotspots.appendChild(row);
    });

    campaigns.innerHTML = "";
    (this.payload?.campaigns || []).forEach((item) => {
      const row = document.createElement("div");
      row.className = "tm-list-item";
      row.innerHTML = `
        <div class="tm-list-top">
          <span class="tm-list-title">${escapeHTML(item.attack_type)}</span>
          <span class="tm-pill clear">${item.count}</span>
        </div>
        <div class="tm-meta">Signature frequency across all active, unarchived alerts.</div>`;
      campaigns.appendChild(row);
    });

    corridors.innerHTML = "";
    (this.payload?.paths || []).slice(0, 12).forEach((path) => {
      const fromPoint = (this.payload.points || []).find((item) => item.id === path.from);
      const toPoint = (this.payload.points || []).find((item) => item.id === path.to);
      const row = document.createElement("div");
      row.className = "tm-corridor-item";
      row.innerHTML = `
        <div class="tm-corridor-top">
          <span class="tm-corridor-title">Attack Source ${escapeHTML(path.source_ip || fromPoint?.ip || "Unknown")} to Target ${escapeHTML(path.target_ip || toPoint?.ip || "Target")}</span>
          <span class="tm-pill ${path.blocked ? "blocked" : "clear"}">${path.count} hits</span>
        </div>
        <div class="tm-meta">${escapeHTML(path.attack_type || "Unknown attack")} • ${escapeHTML(path.severity || "low")} severity</div>`;
      corridors.appendChild(row);
    });
  },

  drawGrid() {
    const { ctx, canvas } = this;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = "rgba(59,130,246,0.05)";
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 48) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 48) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }
  },

  project(point) {
    return {
      x: (point.x / 100) * this.canvas.width,
      y: (point.y / 100) * this.canvas.height,
    };
  },

  draw() {
    if (!this.payload) return;
    this.drawGrid();

    const pointLookup = Object.fromEntries((this.payload.points || []).map((point) => [point.id, point]));
    const { ctx } = this;

    (this.payload.paths || []).forEach((path) => {
      const from = pointLookup[path.from];
      const to = pointLookup[path.to];
      if (!from || !to) return;
      const p1 = this.project(from);
      const p2 = this.project(to);
      const midX = (p1.x + p2.x) / 2;
      const curveY = Math.min(p1.y, p2.y) - 30;

      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.quadraticCurveTo(midX, curveY, p2.x, p2.y);
      ctx.strokeStyle = path.blocked ? "rgba(239,68,68,0.45)" : "rgba(59,130,246,0.25)";
      ctx.lineWidth = Math.min(1 + path.count * 0.25, 4);
      ctx.stroke();
    });

    (this.payload.points || []).forEach((point) => {
      const projected = this.project(point);
      const radius = point.type === "origin" ? 7 : 9;
      const color = point.blocked ? "#ef4444" : point.type === "origin" ? "#3b82f6" : "#10b981";

      ctx.beginPath();
      ctx.arc(projected.x, projected.y, radius + 5, 0, Math.PI * 2);
      ctx.fillStyle = `${color}22`;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(projected.x, projected.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      ctx.font = "600 10px JetBrains Mono, monospace";
      ctx.fillStyle = "#cbd5e1";
      ctx.fillText(point.ip, projected.x + 12, projected.y + 4);
    });
  },
};

function exportCSV() {
  if (!TM.payload) return;
  const rows = [
    ["Attack Source IP", "Target IP", "Count", "Severity", "Attack Type", "Blocked"],
    ...(TM.payload.paths || []).map((path) => {
      const from = TM.payload.points.find((point) => point.id === path.from)?.ip || path.from;
      const to = TM.payload.points.find((point) => point.id === path.to)?.ip || path.to;
      return [path.source_ip || from, path.target_ip || to, path.count, path.severity, path.attack_type, path.blocked ? "YES" : "NO"];
    }),
  ];
  const blob = new Blob([rows.map((row) => row.join(",")).join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `threat-map-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function exportPDF() {
  if (!TM.payload) return;
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
  doc.text("Threat Corridor Map Report", 14, 16);
  doc.setTextColor(148, 163, 184);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`Generated ${new Date().toLocaleString()} | Paths ${(TM.payload.paths || []).length}`, 14, 23);
  doc.autoTable({
    startY: 30,
    head: [["#", "Attack Source IP", "Target IP", "Hits", "Severity", "Attack", "Blocked"]],
    body: (TM.payload.paths || []).slice(0, 120).map((path, index) => {
      const from = TM.payload.points.find((point) => point.id === path.from)?.ip || path.from;
      const to = TM.payload.points.find((point) => point.id === path.to)?.ip || path.to;
      return [index + 1, path.source_ip || from, path.target_ip || to, path.count, path.severity, path.attack_type, path.blocked ? "YES" : "NO"];
    }),
    styles: { fillColor: [17, 28, 53], textColor: [226, 232, 240], lineColor: [30, 50, 90], lineWidth: 0.3, fontSize: 7.5 },
    headStyles: { fillColor: [11, 21, 40], textColor: [148, 163, 184], fontStyle: "bold", fontSize: 7 },
    alternateRowStyles: { fillColor: [13, 21, 40] },
  });
  doc.save(`threat-map-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}.pdf`);
}

window.exportCSV = exportCSV;
window.exportPDF = exportPDF;

document.addEventListener("DOMContentLoaded", () => TM.init());
