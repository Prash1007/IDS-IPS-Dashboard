/* dashboard/static/dashboard/base.js */

const SHELL_STATS_URL = "/api/stats/";
const LIVE_FEED_URL = "/api/live-feed/";

let unseenAlertNotifications = 0;
let latestNotifiedAlertId = Number(window.localStorage?.getItem("latestNotifiedAlertId") || 0);

function humanTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function humanDate(iso) {
  return new Date(iso).toLocaleString([], {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function isRecent(iso) {
  return Date.now() - new Date(iso).getTime() < 15000;
}

function getCsrf() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta?.content) return meta.content;
  const match = document.cookie.match(/csrftoken=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

function escapeHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeClassToken(value, fallback = "unknown") {
  const token = String(value ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "-");
  return token || fallback;
}

function getSevClass(sev) {
  const severity = (sev || "").toLowerCase();
  if (severity === "critical") return "sev-critical";
  if (severity === "high") return "sev-high";
  if (severity === "medium") return "sev-medium";
  return "sev-low";
}

function showToast(msg, color = "blue") {
  const colors = {
    blue: "rgba(59,130,246,0.3)",
    green: "rgba(16,185,129,0.3)",
    red: "rgba(239,68,68,0.3)",
    yellow: "rgba(245,158,11,0.3)",
  };
  const icons = {
    blue: "fa-info-circle",
    green: "fa-check-circle",
    red: "fa-times-circle",
    yellow: "fa-triangle-exclamation",
  };
  const iconColors = {
    blue: "#3b82f6",
    green: "#10b981",
    red: "#ef4444",
    yellow: "#f59e0b",
  };

  const toast = document.createElement("div");
  toast.className = "sentinel-toast";
  toast.style.borderColor = colors[color] || colors.blue;

  const icon = document.createElement("i");
  icon.className = `fas ${icons[color] || icons.blue}`;
  icon.style.color = iconColors[color] || iconColors.blue;

  toast.appendChild(icon);
  toast.appendChild(document.createTextNode(msg));
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = "opacity .25s ease";
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

function openSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  if (!sidebar || !overlay) return;
  sidebar.classList.add("open");
  overlay.classList.add("show");
  document.body.style.overflow = "hidden";
}

function closeSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  if (!sidebar || !overlay) return;
  sidebar.classList.remove("open");
  overlay.classList.remove("show");
  document.body.style.overflow = "";
}

function toggleExportMenu() {
  const menu = document.getElementById("exportMenu");
  if (menu) menu.classList.toggle("open");
}

function setSidebarAlertBadge(count) {
  const badge = document.getElementById("sidebar-alert-badge");
  if (badge) badge.textContent = Number.isFinite(count) ? String(count) : "0";
}

function setNotificationState(count) {
  unseenAlertNotifications = Math.max(0, count || 0);
  const dot = document.getElementById("notifDot");
  const badge = document.getElementById("notifCount");
  if (dot) dot.hidden = unseenAlertNotifications === 0;
  if (badge) {
    badge.hidden = unseenAlertNotifications === 0;
    badge.textContent = unseenAlertNotifications > 99 ? "99+" : String(unseenAlertNotifications);
  }
}

function summarizeAlert(alert) {
  const attack = alert.attack_type || "New alert";
  const source = alert.src_ip ? ` from ${alert.src_ip}` : "";
  return `${attack}${source}`;
}

function notifyNewAlerts(alerts) {
  const fresh = (alerts || []).filter((alert) => Number(alert.id || 0) > latestNotifiedAlertId);
  if (!fresh.length) return;

  latestNotifiedAlertId = Math.max(...fresh.map((alert) => Number(alert.id || 0)), latestNotifiedAlertId);
  window.localStorage?.setItem("latestNotifiedAlertId", String(latestNotifiedAlertId));
  setNotificationState(unseenAlertNotifications + fresh.length);

  const newest = fresh[0];
  showToast(fresh.length === 1 ? summarizeAlert(newest) : `${fresh.length} new alerts received`, "yellow");
}

function initNotificationBell() {
  const bell = document.getElementById("notificationBell");
  if (!bell) return;
  bell.addEventListener("click", () => {
    setNotificationState(0);
    if (!window.location.pathname.includes("/alerts")) {
      window.location.href = "/alerts/";
    }
  });
}

function updateModeLabels(mode) {
  if (!mode) return;
  ["currentMode", "modeDisplay", "kpi-mode", "stat-mode"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.textContent = mode;
  });
}

function resolveActiveNav() {
  const bodyNav = document.body.dataset.activeNav;
  if (bodyNav) return bodyNav;

  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  if (path === "/" || path.endsWith("/dashboard")) return "dashboard";
  if (path.includes("/alerts")) return "alerts";
  if (path.includes("/rule-manager")) return "rule-manager";
  if (path.includes("/network-traffic")) return "network-traffic";
  if (path.includes("/threat-map")) return "threat-map";
  if (path.includes("/reports")) return "reports";
  return "";
}

function syncActiveNav() {
  const activeNav = resolveActiveNav();
  document.querySelectorAll(".nav-item[data-nav]").forEach((item) => {
    const isActive = item.dataset.nav === activeNav;
    item.classList.toggle("active", isActive);
    if (isActive) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
}

async function refreshShellStats() {
  try {
    const resp = await fetch(SHELL_STATS_URL, { headers: { Accept: "application/json" } });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    setSidebarAlertBadge(data.total_alerts || 0);
    updateModeLabels(data.mode || "");
  } catch (err) {
    console.error("refreshShellStats:", err);
  }
}

function initTabGroup() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");
    });
  });
}

function updateClock() {
  const el = document.getElementById("last-updated");
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  el.title = now.toLocaleString();
}

function startLiveFeed({ interval = 1500, onData, onError } = {}) {
  let sinceAlertId = 0;
  let sinceActionId = 0;
  let busy = false;
  let initialized = false;

  const poll = async () => {
    if (busy) return;
    busy = true;
    try {
      const response = await fetch(
        `${LIVE_FEED_URL}?since_alert_id=${sinceAlertId}&since_action_id=${sinceActionId}`,
        { cache: "no-store", headers: { Accept: "application/json" } },
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      sinceAlertId = Math.max(sinceAlertId, payload.latest_alert_id || 0);
      sinceActionId = Math.max(sinceActionId, payload.latest_action_id || 0);
      if (initialized) {
        notifyNewAlerts(payload.alerts || []);
      } else {
        latestNotifiedAlertId = Math.max(latestNotifiedAlertId, payload.latest_alert_id || 0);
        window.localStorage?.setItem("latestNotifiedAlertId", String(latestNotifiedAlertId));
        initialized = true;
      }
      if (typeof onData === "function") onData(payload);
      updateClock();
    } catch (error) {
      console.error("startLiveFeed:", error);
      if (typeof onError === "function") onError(error);
    } finally {
      busy = false;
    }
  };

  poll();
  const timer = window.setInterval(poll, interval);
  return {
    stop() {
      window.clearInterval(timer);
    },
  };
}

function initMeshBackground() {
  const canvas = document.getElementById("meshCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const nodes = [];
  const nodeCount = window.innerWidth <= 768 ? 36 : 65;

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function seedNodes() {
    nodes.length = 0;
    for (let i = 0; i < nodeCount; i += 1) {
      nodes.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - 0.5) * 0.38,
        vy: (Math.random() - 0.5) * 0.38,
      });
    }
  }

  function drawMesh() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    nodes.forEach((node) => {
      node.x += node.vx;
      node.y += node.vy;

      if (node.x < 0 || node.x > canvas.width) node.vx *= -1;
      if (node.y < 0 || node.y > canvas.height) node.vy *= -1;
    });

    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        if (distance >= 130) continue;

        ctx.beginPath();
        ctx.moveTo(nodes[i].x, nodes[i].y);
        ctx.lineTo(nodes[j].x, nodes[j].y);
        ctx.strokeStyle = `rgba(59,130,246,${0.06 * (1 - distance / 130)})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }
    }

    nodes.forEach((node) => {
      ctx.beginPath();
      ctx.arc(node.x, node.y, 1.5, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(59,130,246,.2)";
      ctx.fill();
    });

    window.requestAnimationFrame(drawMesh);
  }

  resizeCanvas();
  seedNodes();
  window.addEventListener("resize", resizeCanvas);
  drawMesh();
}

document.addEventListener("click", (event) => {
  const dropdown = document.getElementById("exportDropdown");
  if (!dropdown || dropdown.contains(event.target)) return;

  const menu = document.getElementById("exportMenu");
  if (menu) menu.classList.remove("open");
});

window.addEventListener("resize", () => {
  if (window.innerWidth > 920) closeSidebar();
});

document.addEventListener("DOMContentLoaded", () => {
  syncActiveNav();
  initTabGroup();
  initMeshBackground();
  initNotificationBell();
  updateClock();
  refreshShellStats();

  setInterval(updateClock, 1000);
  setInterval(refreshShellStats, 10000);

  document.querySelectorAll("#sidebar a.nav-item[data-nav]").forEach((link) => {
    link.addEventListener("click", () => {
      if (window.innerWidth <= 920) closeSidebar();
    });
  });
});

window.updateSidebarAlertBadge = setSidebarAlertBadge;
window.updateModeLabels = updateModeLabels;
window.refreshShellStats = refreshShellStats;
window.startLiveFeed = startLiveFeed;
window.updateClock = updateClock;
window.getCsrf = getCsrf;
window.escapeHTML = escapeHTML;
window.safeClassToken = safeClassToken;
window.exportCSV = window.exportCSV || (() => showToast("Export is not available on this page yet.", "blue"));
window.exportPDF = window.exportPDF || (() => showToast("Export is not available on this page yet.", "blue"));
