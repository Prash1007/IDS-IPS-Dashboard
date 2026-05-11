const NETWORK_TOPOLOGY_URL = "/api/network-topology/?limit=all";

const NT = {
  canvas: null,
  ctx: null,
  wrap: null,
  nodes: [],
  edges: [],
  flows: [],
  nodeLookup: {},
  paused: false,
  zoom: 1,
  panX: 0,
  panY: 0,
  dragging: false,
  dragStart: { x: 0, y: 0 },
  selectedNodeId: null,
  layout: "layered",

  entityTypes: {
    attacker: { icon: "💀", color: "#ef4444", bg: "rgba(239,68,68,0.15)", label: "External Threat", layer: 0 },
    external: { icon: "🌐", color: "#f97316", bg: "rgba(249,115,22,0.15)", label: "External Host", layer: 0 },
    router: { icon: "📡", color: "#06b6d4", bg: "rgba(6,182,212,0.15)", label: "Router", layer: 1 },
    firewall: { icon: "🛡️", color: "#8b5cf6", bg: "rgba(139,92,246,0.15)", label: "Firewall", layer: 2 },
    webserver: { icon: "🖥️", color: "#3b82f6", bg: "rgba(59,130,246,0.15)", label: "Web Server", layer: 3 },
    dbserver: { icon: "🗄️", color: "#f59e0b", bg: "rgba(245,158,11,0.15)", label: "Database", layer: 3 },
    dns: { icon: "📋", color: "#10b981", bg: "rgba(16,185,129,0.15)", label: "DNS Server", layer: 3 },
    mailserver: { icon: "📧", color: "#e879f9", bg: "rgba(232,121,249,0.15)", label: "Mail Server", layer: 3 },
    workstation: { icon: "💻", color: "#94a3b8", bg: "rgba(148,163,184,0.12)", label: "Workstation", layer: 4 },
  },

  init() {
    this.canvas = document.getElementById("ntCanvas");
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");
    this.wrap = document.getElementById("ntCanvasWrap");
    this.resize();
    window.addEventListener("resize", () => {
      this.resize();
      this.layoutNodes(this.layout);
    });
    this.bindEvents();
    this.loop();
    this.fetchData();
    if (typeof window.startLiveFeed === "function") {
      window.startLiveFeed({
        interval: 1400,
        onData(payload) {
          if ((payload.alerts || []).length) NT.fetchData();
        },
      });
    }
  },

  resize() {
    const rect = this.wrap.getBoundingClientRect();
    this.canvas.width = rect.width || 860;
    this.canvas.height = rect.height || 480;
  },

  async fetchData() {
    if (this.paused) return;
    try {
      const response = await fetch(NETWORK_TOPOLOGY_URL, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      this.loadPayload(payload);
      this.updateStats(payload.stats || {});
      this.updateFlowLog();
      if (this.selectedNodeId) this.selectNodeById(this.selectedNodeId);
    } catch (error) {
      console.error("NETWORK_TOPOLOGY_URL:", error);
    }
  },

  loadPayload(payload) {
    this.nodeLookup = {};
    this.nodes = (payload.nodes || []).map((node) => {
      const existing = this.nodeLookup[node.id] || {};
      const hydrated = {
        ...existing,
        ...node,
        x: existing.x || 0,
        y: existing.y || 0,
      };
      this.nodeLookup[hydrated.id] = hydrated;
      return hydrated;
    });
    this.edges = payload.edges || [];
    this.flows = payload.flows || [];
    this.layoutNodes(this.layout);
  },

  layoutNodes(type) {
    const width = this.canvas.width;
    const height = this.canvas.height;
    if (!this.nodes.length) return;

    if (type === "free") {
      this.nodes.forEach((node) => {
        node.x = 80 + Math.random() * (width - 160);
        node.y = 60 + Math.random() * (height - 120);
      });
      return;
    }

    if (type === "star") {
      const centerX = width / 2;
      const centerY = height / 2;
      const firewall = this.nodes.find((node) => node.type === "firewall");
      if (firewall) {
        firewall.x = centerX;
        firewall.y = centerY;
      }
      const others = this.nodes.filter((node) => node.id !== firewall?.id);
      others.forEach((node, index) => {
        const angle = (index / Math.max(others.length, 1)) * Math.PI * 2;
        const radius = Math.min(width, height) * 0.36;
        node.x = centerX + Math.cos(angle) * radius;
        node.y = centerY + Math.sin(angle) * radius;
      });
      return;
    }

    const buckets = {};
    this.nodes.forEach((node) => {
      const layer = this.entityTypes[node.type]?.layer ?? 4;
      buckets[layer] = buckets[layer] || [];
      buckets[layer].push(node);
    });

    Object.entries(buckets).forEach(([layerKey, nodes]) => {
      const layer = Number(layerKey);
      const x = 80 + layer * ((width - 160) / 4);
      nodes.forEach((node, index) => {
        node.x = x;
        node.y = 60 + ((index + 0.5) * (height - 120)) / Math.max(nodes.length, 1);
      });
    });
  },

  bindEvents() {
    const canvas = this.canvas;
    canvas.addEventListener("mousedown", (event) => {
      this.dragging = true;
      this.dragStart = { x: event.clientX - this.panX, y: event.clientY - this.panY };
    });
    canvas.addEventListener("mousemove", (event) => {
      if (this.dragging) {
        this.panX = event.clientX - this.dragStart.x;
        this.panY = event.clientY - this.dragStart.y;
        return;
      }
      const position = this.screenToWorld(event);
      const hit = this.hitTest(position.x, position.y);
      const tooltip = document.getElementById("ntTooltip");
      if (!tooltip) return;
      if (!hit) {
        tooltip.style.display = "none";
        canvas.style.cursor = "grab";
        return;
      }

      const meta = this.entityTypes[hit.type] || this.entityTypes.workstation;
      tooltip.style.display = "block";
      tooltip.style.left = `${event.offsetX + 12}px`;
      tooltip.style.top = `${event.offsetY - 10}px`;
      tooltip.innerHTML = `
        <div style="font-weight:700;color:${meta.color};margin-bottom:4px">${escapeHTML(hit.name)}</div>
        <div style="color:#94a3b8;font-family:'JetBrains Mono',monospace;font-size:11px">${escapeHTML(hit.ip)}</div>
        <div style="color:#475569;font-size:10px;margin-top:4px">${escapeHTML(hit.role_label || meta.label)}</div>`;
      canvas.style.cursor = "pointer";
    });
    canvas.addEventListener("mouseup", (event) => {
      if (!this.dragging) return;
      const movedFar = Math.abs(event.clientX - this.dragStart.x - this.panX) > 4 || Math.abs(event.clientY - this.dragStart.y - this.panY) > 4;
      this.dragging = false;
      if (movedFar) return;
      const position = this.screenToWorld(event);
      const hit = this.hitTest(position.x, position.y);
      if (hit) this.selectNodeById(hit.id);
    });
    canvas.addEventListener("mouseleave", () => {
      this.dragging = false;
      const tooltip = document.getElementById("ntTooltip");
      if (tooltip) tooltip.style.display = "none";
    });
    canvas.addEventListener("wheel", (event) => {
      event.preventDefault();
      this.zoom = Math.max(0.45, Math.min(2.5, this.zoom - event.deltaY * 0.001));
    });
  },

  screenToWorld(event) {
    const rect = this.canvas.getBoundingClientRect();
    return {
      x: (event.clientX - rect.left - this.panX) / this.zoom,
      y: (event.clientY - rect.top - this.panY) / this.zoom,
    };
  },

  hitTest(x, y) {
    return this.nodes.find((node) => Math.hypot(node.x - x, node.y - y) < 30) || null;
  },

  edgeEndpoints(edge) {
    return {
      from: this.nodeLookup[edge.from],
      to: this.nodeLookup[edge.to],
    };
  },

  drawGrid() {
    const { ctx, canvas } = this;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = "rgba(59,130,246,0.04)";
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }
  },

  draw() {
    this.drawGrid();
    const { ctx } = this;
    ctx.save();
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoom, this.zoom);

    this.edges.forEach((edge) => {
      const { from, to } = this.edgeEndpoints(edge);
      if (!from || !to) return;
      const color = edge.type === "blocked"
        ? "rgba(245,158,11,0.35)"
        : edge.type === "attack"
          ? "rgba(239,68,68,0.35)"
          : edge.type === "scan"
            ? "rgba(59,130,246,0.3)"
            : "rgba(16,185,129,0.16)";
      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      const midX = (from.x + to.x) / 2;
      const midY = (from.y + to.y) / 2 - 18;
      ctx.quadraticCurveTo(midX, midY, to.x, to.y);
      ctx.strokeStyle = color;
      ctx.lineWidth = Math.min(1 + edge.count * 0.25, 3.5);
      ctx.setLineDash(edge.type === "normal" ? [4, 6] : []);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    this.nodes.forEach((node) => {
      const meta = this.entityTypes[node.type] || this.entityTypes.workstation;
      const selected = node.id === this.selectedNodeId;
      const radius = 28;

      if (selected) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 5, 0, Math.PI * 2);
        ctx.strokeStyle = meta.color;
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      if (node.blocked || node.alert_count > 0) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 11, 0, Math.PI * 2);
        ctx.strokeStyle = node.blocked ? "rgba(239,68,68,0.24)" : "rgba(59,130,246,0.18)";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = meta.bg;
      ctx.fill();
      ctx.strokeStyle = `${meta.color}88`;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.font = "18px serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(meta.icon, node.x, node.y);

      if (node.blocked) {
        ctx.beginPath();
        ctx.arc(node.x + radius * 0.65, node.y - radius * 0.65, 8, 0, Math.PI * 2);
        ctx.fillStyle = "#ef4444";
        ctx.fill();
        ctx.fillStyle = "#fff";
        ctx.font = "700 9px Arial";
        ctx.fillText("X", node.x + radius * 0.65, node.y - radius * 0.65);
      }

      ctx.font = "600 10px JetBrains Mono, monospace";
      ctx.fillStyle = meta.color;
      ctx.textBaseline = "top";
      ctx.fillText(node.name, node.x, node.y + radius + 5);
      ctx.font = "500 9px JetBrains Mono, monospace";
      ctx.fillStyle = "rgba(148,163,184,0.8)";
      ctx.fillText(node.ip, node.x, node.y + radius + 17);
    });

    ctx.restore();
  },

  loop() {
    this.draw();
    requestAnimationFrame(() => this.loop());
  },

  selectNodeById(id) {
    const node = this.nodeLookup[id];
    if (!node) return;
    this.selectedNodeId = id;
    const meta = this.entityTypes[node.type] || this.entityTypes.workstation;
    const relatedFlows = this.flows.filter((flow) => (flow.src_ip === node.ip || flow.dest_ip === node.ip));
    const relatedEdges = this.edges.filter((edge) => edge.from === id || edge.to === id);

    document.getElementById("ntDetailIcon").innerHTML = `<span style="font-size:22px">${meta.icon}</span>`;
    document.getElementById("ntDetailIcon").style.cssText = `background:${meta.bg};width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center`;
    document.getElementById("ntDetailName").textContent = node.name;
    document.getElementById("ntDetailType").textContent = node.role_label || meta.label;
    document.getElementById("ntDetailBody").innerHTML = `
      <div class="nt-detail-row"><span class="nt-detail-key">IP Address</span><span class="nt-detail-val" style="color:${meta.color}">${escapeHTML(node.ip)}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">Role</span><span class="nt-detail-val">${escapeHTML(node.role_label || meta.label)}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">As Attack Source</span><span class="nt-detail-val">${node.source_count || 0}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">As Target</span><span class="nt-detail-val">${node.target_count || 0}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">Alerts</span><span class="nt-detail-val">${node.alert_count || 0}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">Connections</span><span class="nt-detail-val">${node.connections || 0}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">Status</span><span class="nt-detail-val" style="color:${node.blocked ? "#ef4444" : (node.alert_count ? "#f59e0b" : "#10b981")}">${node.blocked ? "BLOCKED" : (node.alert_count ? "ACTIVE ALERTS" : "CLEAN")}</span></div>
      <div class="nt-detail-row"><span class="nt-detail-key">Recent Attack</span><span class="nt-detail-val">${escapeHTML(node.recent_attack_type || "—")}</span></div>`;

    const connList = document.getElementById("ntConnList");
    const connItems = document.getElementById("ntConnItems");
    connList.style.display = "block";
    connItems.innerHTML = "";
    relatedEdges.slice(0, 10).forEach((edge) => {
      const peerId = edge.from === id ? edge.to : edge.from;
      const peer = this.nodeLookup[peerId];
      if (!peer) return;
      const color = edge.type === "blocked" ? "#f59e0b" : edge.type === "attack" ? "#ef4444" : edge.type === "scan" ? "#3b82f6" : "#10b981";
      connItems.innerHTML += `
        <div class="nt-conn-item">
          <span class="nt-conn-dot" style="background:${color}"></span>
          <span class="nt-conn-ip">${escapeHTML(peer.ip)}</span>
          <span class="nt-conn-proto">${escapeHTML((edge.protocols || []).join("/") || "TCP")}</span>
        </div>`;
    });
    if (!relatedEdges.length) connItems.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:8px 0">No active connections</div>';

    const alertMini = document.getElementById("ntAlertMini");
    const alertItems = document.getElementById("ntAlertMiniItems");
    alertMini.style.display = relatedFlows.length ? "block" : "none";
    alertItems.innerHTML = "";
    relatedFlows.slice(0, 6).forEach((flow) => {
      alertItems.innerHTML += `
        <div class="nt-alert-row ${safeClassToken(flow.severity || "low")}">
          <div class="nt-alert-type">${escapeHTML(flow.attack_type || "Unknown")} - Attack Source ${escapeHTML(flow.src_ip || "-")} to Target ${escapeHTML(flow.dest_ip || "-")}</div>
          <div class="nt-alert-time">${humanDate(flow.timestamp)}</div>
        </div>`;
    });
  },

  updateStats(stats) {
    document.getElementById("nt-total-conn").textContent = stats.active_flows || 0;
    document.getElementById("nt-threat-conn").textContent = stats.threat_flows || 0;
    document.getElementById("nt-clean-conn").textContent = stats.clean_flows || 0;
    document.getElementById("nt-blocked-conn").textContent = stats.blocked_flows || 0;
    document.getElementById("nt-unique-src").textContent = stats.unique_sources || 0;
  },

  updateFlowLog() {
    const container = document.getElementById("ntFlowLog");
    if (!container) return;
    container.innerHTML = "";
    this.flows.slice(0, 10).forEach((flow) => {
      const color = flow.blocked ? "#f59e0b" : ["critical", "high"].includes((flow.severity || "").toLowerCase()) ? "#ef4444" : "#3b82f6";
      const item = document.createElement("div");
      item.className = "nt-flow-item";
      item.innerHTML = `
        <span class="nt-flow-dot" style="background:${color}"></span>
        <span style="color:#94a3b8">Attack Source ${escapeHTML(flow.src_ip || "-")} to Target ${escapeHTML(flow.dest_ip || "-")}</span>
        <span style="padding:1px 6px;border-radius:4px;background:rgba(59,130,246,0.1);color:#3b82f6;font-size:9.5px">${escapeHTML(flow.attack_type)}</span>`;
      container.appendChild(item);
    });
  },
};

function togglePause() {
  NT.paused = !NT.paused;
  const button = document.getElementById("nt-pause-btn");
  if (button) {
    button.innerHTML = NT.paused ? '<i class="fas fa-play"></i> Resume' : '<i class="fas fa-pause"></i> Pause';
    button.classList.toggle("paused", NT.paused);
  }
}

function resetTopology() {
  NT.zoom = 1;
  NT.panX = 0;
  NT.panY = 0;
  NT.layoutNodes(NT.layout);
}

function setLayout(value) {
  NT.layout = value;
  NT.layoutNodes(value);
}

function zoomIn() {
  NT.zoom = Math.min(2.5, NT.zoom + 0.15);
}

function zoomOut() {
  NT.zoom = Math.max(0.45, NT.zoom - 0.15);
}

function zoomReset() {
  NT.zoom = 1;
  NT.panX = 0;
  NT.panY = 0;
}

document.addEventListener("DOMContentLoaded", () => NT.init());
