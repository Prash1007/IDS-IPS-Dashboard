// ════════════════════════════════════════════════════════════
//  dashboard/static/dashboard/main.js  —  FIXED & COMPLETE
//  API Endpoints: /api/alerts/ /api/stats/ /api/block/
//                 /api/unblock/ /api/mode/
// ════════════════════════════════════════════════════════════

const ALERTS_URL  = "/api/alerts/?limit=50";
const STATS_URL   = "/api/stats/";
const BLOCK_URL   = "/api/block/";
const UNBLOCK_URL = "/api/unblock/";
const MODE_URL    = "/api/mode/";

let timelineChart = null;
let donutChart    = null;
let allAlerts     = [];
let prevAlertIds  = new Set();
let currentFilter = '';

const DONUT_COLORS = ['#ef4444','#f97316','#f59e0b','#3b82f6','#8b5cf6','#06b6d4','#10b981','#e879f9'];

/* ────────────────── Utilities ────────────────── */
function humanTime(iso) {
  return new Date(iso).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}
function humanDate(iso) {
  return new Date(iso).toLocaleString([], {
    year:'2-digit', month:'2-digit', day:'2-digit',
    hour:'2-digit', minute:'2-digit', second:'2-digit'
  });
}
function isRecent(iso) { return Date.now() - new Date(iso).getTime() < 15000; }
function getCsrf() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta?.content) return meta.content;
  const m = document.cookie.match(/csrftoken=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}
function getSevClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'sev-critical';
  if (s === 'high')     return 'sev-high';
  if (s === 'medium')   return 'sev-medium';
  return 'sev-low';
}

/* ────────────────── Sparklines ────────────────── */
function buildSparkline(id, values, peakColor) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = '';
  const max = Math.max(...values, 1);
  values.forEach(v => {
    const b = document.createElement('div');
    b.className = 'spark-bar' + (v === max ? ' peak' : '');
    b.style.height = Math.max(4, Math.round(v / max * 100)) + '%';
    if (peakColor && !b.classList.contains('peak')) b.style.background = peakColor;
    el.appendChild(b);
  });
}

function buildSparklines() {
  const now = Date.now();
  const buckets = Array(24).fill(0);
  allAlerts.forEach(a => {
    const age = (now - new Date(a.timestamp).getTime()) / 3600000;
    if (age <= 24) { buckets[23 - Math.min(23, Math.floor(age))]++; }
  });
  buildSparkline('spark1', buckets, 'rgba(239,68,68,0.3)');
  buildSparkline('spark3', buckets, 'rgba(16,185,129,0.3)');
  const bk = Array(24).fill(0).map((_, i) => Math.max(0, Math.floor(Math.sin(i * 0.4) * 3 + 2)));
  buildSparkline('spark2', bk, 'rgba(59,130,246,0.3)');
  buildSparkline('spark4', Array(24).fill(1), 'rgba(139,92,246,0.3)');
}

/* ────────────────── Severity Bars ────────────────── */
function updateSevBars(alerts) {
  const counts = {critical: 0, high: 0, medium: 0, low: 0};
  alerts.forEach(a => {
    const s = (a.severity || 'low').toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
    else counts.low++;
  });
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  ['critical', 'high', 'medium', 'low'].forEach(s => {
    const bar = document.getElementById(`bar-${s}`);
    const cnt = document.getElementById(`count-${s}`);
    if (bar) bar.style.width = Math.round(counts[s] / total * 100) + '%';
    if (cnt) cnt.textContent = counts[s];
  });
}

/* ────────────────── Top Threat Signatures ────────────────── */
function updateTopThreats(alerts) {
  const counts = {};
  alerts.forEach(a => { counts[a.attack_type] = (counts[a.attack_type] || 0) + 1; });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const el = document.getElementById('threatList');
  if (!el) return;
  el.innerHTML = '';
  if (sorted.length === 0) {
    el.innerHTML = '<div class="threat-row"><span class="threat-name" style="color:var(--text-muted)">No data yet</span></div>';
    return;
  }
  sorted.forEach(([name, count], i) => {
    const row = document.createElement('div');
    row.className = 'threat-row';
    row.innerHTML = `<span class="threat-num">#${i + 1}</span><span class="threat-name" title="${escapeHTML(name)}">${escapeHTML(name)}</span><span class="threat-count">${count}</span>`;
    el.appendChild(row);
  });
}

/* ────────────────── Blocked IPs List ────────────────── */
function updateBlockedList(alerts) {
  const blocked = [...new Set(alerts.filter(a => a.blocked).map(a => a.src_ip))];
  const el    = document.getElementById('blockedList');
  const badge = document.getElementById('blocked-badge');
  const kpiBlocked = document.getElementById('kpi-blocked');
  if (badge)      badge.textContent = blocked.length;
  if (kpiBlocked) kpiBlocked.textContent = blocked.length;
  if (!el) return;
  el.innerHTML = '';
  if (blocked.length === 0) {
    el.innerHTML = '<li style="color:var(--text-muted);font-size:12px;text-align:center;padding:14px;list-style:none"><i class="fas fa-shield-check" style="color:var(--accent-green)"></i> No IPs blocked</li>';
    return;
  }
  blocked.forEach(ip => {
    const li = document.createElement('li');
    li.className = 'blocked-item';
    const btn = document.createElement('button');
    btn.className = 'btn btn-sm btn-ghost';
    btn.type = 'button';
    btn.textContent = 'Unblock';
    btn.addEventListener('click', () => doUnblock(ip));
    li.innerHTML = `<span class="blocked-ip">${escapeHTML(ip)}</span>`;
    li.appendChild(btn);
    el.appendChild(li);
  });
}

/* ────────────────── Render Alerts Table ────────────────── */
function renderAlerts(alerts, newIds = new Set()) {
  const tbody = document.getElementById('alertsBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const timeBuckets = {}, topTypes = {};

  alerts.forEach(a => {
    topTypes[a.attack_type] = (topTypes[a.attack_type] || 0) + 1;
    const t = new Date(a.timestamp);
    const bucket = `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
    timeBuckets[bucket] = (timeBuckets[bucket] || 0) + 1;

    const tr = document.createElement('tr');
    if (newIds.has(a.id)) tr.classList.add('new-row');

    const recent = isRecent(a.timestamp);
    const proto  = a.protocol ? `<span class="proto">${escapeHTML(a.protocol)}</span>` : '—';
    const actionCell = document.createElement('td');
    if (a.blocked) {
      actionCell.innerHTML = '<span class="action-block">🛡 Blocked</span>';
    } else {
      const blockBtn = document.createElement('button');
      blockBtn.className = 'btn btn-sm btn-danger-outline';
      blockBtn.type = 'button';
      blockBtn.textContent = 'Block IP';
      blockBtn.addEventListener('click', () => doBlock(a.src_ip));
      actionCell.appendChild(blockBtn);
    }

    const attackDisplay = (a.attack_type || '—').length > 22
      ? (a.attack_type || '—').substring(0, 22) + '…'
      : (a.attack_type || '—');

    tr.innerHTML = `
      <td><span class="severity ${getSevClass(a.severity)}">● ${escapeHTML((a.severity || 'low').toUpperCase())}</span></td>
      <td style="font-size:11.5px;font-weight:600" title="${escapeHTML(a.attack_type || '')}">${escapeHTML(attackDisplay)}</td>
      <td><span class="ip-addr">${escapeHTML(a.src_ip || '—')}</span></td>
      <td><span class="ip-addr">${escapeHTML(a.dest_ip || '—')}</span></td>
      <td>${proto}</td>
      <td><span class="time-ago ${recent ? 'time-now' : ''}">${recent ? 'just now' : humanTime(a.timestamp)}</span></td>`;
    tr.insertBefore(actionCell, tr.lastElementChild);
    tbody.appendChild(tr);
  });

  const badge = document.getElementById('sidebar-alert-badge');
  if (badge) badge.textContent = alerts.length;
  const vc = document.getElementById('visible-count');
  if (vc) vc.textContent = alerts.length;

  updateCharts(timeBuckets, topTypes);
  updateSevBars(alerts);
  updateTopThreats(alerts);
  updateBlockedList(alerts);
}

/* ────────────────── Charts ────────────────── */
Chart.defaults.color       = '#94a3b8';
Chart.defaults.borderColor = 'rgba(59,130,246,0.06)';

function updateCharts(timeBuckets, topTypes) {
  /* Timeline */
  const tLabels = Object.keys(timeBuckets).sort();
  const tData   = tLabels.map(k => timeBuckets[k]);

  if (!timelineChart) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;
    timelineChart = new Chart(ctx.getContext('2d'), {
      type: 'line',
      data: {
        labels: tLabels,
        datasets: [{
          label: 'Alerts',
          data: tData,
          borderColor: '#ef4444',
          borderWidth: 2,
          tension: 0.45,
          fill: true,
          pointRadius: 0,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: '#ef4444',
          backgroundColor: (ctx) => {
            const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 170);
            g.addColorStop(0, 'rgba(239,68,68,0.18)');
            g.addColorStop(1, 'rgba(239,68,68,0.00)');
            return g;
          }
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: {mode: 'index', intersect: false},
        plugins: {
          legend: {display: false},
          tooltip: {
            backgroundColor: '#111c35', borderColor: 'rgba(59,130,246,0.3)', borderWidth: 1,
            titleColor: '#94a3b8', bodyColor: '#e2e8f0', padding: 10
          }
        },
        scales: {
          x: {ticks: {color: '#475569', maxTicksLimit: 10, font: {size: 10}}, grid: {color: 'rgba(255,255,255,0.03)'}},
          y: {ticks: {color: '#475569', precision: 0, font: {size: 10}}, grid: {color: 'rgba(255,255,255,0.03)'}}
        }
      }
    });
  } else {
    timelineChart.data.labels = tLabels;
    timelineChart.data.datasets[0].data = tData;
    timelineChart.update('none');
  }

  /* Donut */
  const dLabels = Object.keys(topTypes).slice(0, 8);
  const dData   = dLabels.map(k => topTypes[k]);

  if (!donutChart) {
    const dCtx = document.getElementById('donutChart');
    if (!dCtx) return;
    donutChart = new Chart(dCtx.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: dLabels,
        datasets: [{
          data: dData,
          backgroundColor: DONUT_COLORS.map(c => c + 'bb'),
          borderColor: DONUT_COLORS,
          borderWidth: 2,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: false, cutout: '70%',
        plugins: {
          legend: {display: false},
          tooltip: {
            backgroundColor: '#111c35', borderColor: 'rgba(59,130,246,0.3)', borderWidth: 1,
            titleColor: '#94a3b8', bodyColor: '#e2e8f0', padding: 10
          }
        }
      }
    });
  } else {
    donutChart.data.labels = dLabels;
    donutChart.data.datasets[0].data = dData;
    donutChart.data.datasets[0].backgroundColor = DONUT_COLORS.slice(0, dLabels.length).map(c => c + 'bb');
    donutChart.data.datasets[0].borderColor = DONUT_COLORS.slice(0, dLabels.length);
    donutChart.update('none');
  }

  /* Donut legend */
  const legendEl = document.getElementById('donutLegend');
  if (legendEl) {
    legendEl.innerHTML = '';
    const total = dData.reduce((a, b) => a + b, 0) || 1;
    dLabels.forEach((l, i) => {
      const row = document.createElement('div');
      row.className = 'dl-row';
      row.innerHTML = `
        <span style="display:flex;align-items:center;min-width:0;overflow:hidden">
          <span class="dl-dot" style="background:${DONUT_COLORS[i] || '#888'}"></span>
          <span style="color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHTML(l)}</span>
        </span>
        <span class="dl-count">${Math.round(dData[i] / total * 100)}%</span>`;
      legendEl.appendChild(row);
    });
  }
}

/* ────────────────── Fetch Alerts ────────────────── */
async function fetchAlerts() {
  try {
    const resp = await fetch(ALERTS_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const fresh = data.alerts || [];
    const newIds = new Set(fresh.filter(a => !prevAlertIds.has(a.id)).map(a => a.id));
    prevAlertIds = new Set(fresh.map(a => a.id));
    allAlerts = fresh;
    applyFilter(newIds);
    buildSparklines();
  } catch (e) {
    console.error('fetchAlerts:', e);
  }
}

/* ────────────────── Fetch Stats ────────────────── */
async function fetchStats() {
  try {
    const resp = await fetch(STATS_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('kpi-total-alerts', (data.total_alerts || 0).toLocaleString());
    set('kpi-last24h',      (data.last_24h || 0).toLocaleString());
    set('kpi-sub-24',       `${data.last_24h || 0} in last 24h`);
    set('stat-total2',      (data.total_alerts || 0).toLocaleString());
    set('stat-last24',      (data.last_24h || 0).toLocaleString());
    set('stat-blocked',     data.blocked_ips || 0);
    // Sync blocked badge/kpi
    const kpiBlocked = document.getElementById('kpi-blocked');
    if (kpiBlocked && !kpiBlocked._localSet) kpiBlocked.textContent = data.blocked_ips || 0;
  } catch (e) {
    console.error('fetchStats:', e);
  }
}

/* ────────────────── Filter ────────────────── */
function applyFilter(newIds = new Set()) {
  const term = currentFilter.toLowerCase();
  const filtered = term
    ? allAlerts.filter(a =>
        (a.src_ip || '').includes(term) ||
        (a.attack_type || '').toLowerCase().includes(term) ||
        (a.dest_ip || '').includes(term) ||
        (a.severity || '').toLowerCase().includes(term) ||
        (a.protocol || '').toLowerCase().includes(term)
      )
    : allAlerts;
  renderAlerts(filtered, newIds);
}

/* ────────────────── Block / Unblock ────────────────── */
async function doBlock(ip) {
  if (!confirm(`Block IP: ${ip}?\nAll alerts from this IP will be marked blocked.`)) return;
  try {
    const resp = await fetch(BLOCK_URL, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrf()},
      body: JSON.stringify({ip, reason: 'Manual block from SentinelAI UI'})
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast(`Blocked ${ip}`, 'red');
    await fetchAlerts();
    await fetchStats();
  } catch (e) {
    console.error('doBlock:', e);
    showToast(`Failed to block ${ip}`, 'red');
  }
}

async function doUnblock(ip) {
  if (!confirm(`Unblock ${ip}?`)) return;
  try {
    const resp = await fetch(UNBLOCK_URL, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrf()},
      body: JSON.stringify({ip})
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast(`Unblocked ${ip}`, 'green');
    await fetchAlerts();
    await fetchStats();
  } catch (e) {
    console.error('doUnblock:', e);
    showToast(`Failed to unblock ${ip}`, 'red');
  }
}
window.doBlock   = doBlock;
window.doUnblock = doUnblock;

/* ────────────────── Mode Switch ────────────────── */
async function setMode(mode) {
  try {
    const resp = await fetch(MODE_URL, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrf()},
      body: JSON.stringify({mode})
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (data.status === 'ok') {
      ['currentMode', 'modeDisplay', 'kpi-mode', 'stat-mode'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = data.mode;
      });
      const sel = document.getElementById('modeSelect');
      if (sel) sel.value = data.mode;
      showToast(`Mode switched to ${data.mode}`, data.mode === 'IPS' ? 'blue' : 'green');
    }
  } catch (e) {
    console.error('setMode:', e);
    showToast('Failed to switch mode', 'red');
  }
}

/* ────────────────── CSV Export ────────────────── */
function exportCSV() {
  document.getElementById('exportMenu').classList.remove('open');
  const data = allAlerts.length > 0 ? allAlerts : [];
  if (data.length === 0) { showToast('No alerts to export', 'blue'); return; }

  const headers = ['ID', 'Timestamp', 'Severity', 'Attack Type', 'Source IP', 'Dest IP', 'Protocol', 'Blocked', 'Action'];
  const rows = data.map(a => [
    a.id || '',
    humanDate(a.timestamp),
    (a.severity || 'low').toUpperCase(),
    `"${(a.attack_type || '').replace(/"/g, '""')}"`,
    a.src_ip || '',
    a.dest_ip || '',
    a.protocol || '',
    a.blocked ? 'YES' : 'NO',
    a.action || ''
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csvContent], {type: 'text/csv;charset=utf-8;'});
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const ts   = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
  link.href = url;
  link.download = `ids-alerts-${ts}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  showToast(`Exported ${data.length} alerts as CSV`, 'green');
}

/* ────────────────── PDF Export ────────────────── */
async function exportPDF() {
  document.getElementById('exportMenu').classList.remove('open');
  const data = allAlerts.length > 0 ? allAlerts : [];
  if (data.length === 0) { showToast('No alerts to export', 'blue'); return; }

  showToast('Generating PDF…', 'blue');

  // Wait for jsPDF to be available
  if (typeof window.jspdf === 'undefined' && typeof jspdf === 'undefined') {
    showToast('PDF library not loaded. Try again.', 'red');
    return;
  }

  try {
    const { jsPDF } = window.jspdf || jspdf;
    const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });

    /* Header */
    doc.setFillColor(8, 13, 26);
    doc.rect(0, 0, 297, 297, 'F');

    doc.setFontSize(18);
    doc.setTextColor(59, 130, 246);
    doc.setFont('helvetica', 'bold');
    doc.text('AIBased IDS/IPS — Security Alert Report', 14, 16);

    doc.setFontSize(9);
    doc.setTextColor(148, 163, 184);
    doc.setFont('helvetica', 'normal');
    const now = new Date().toLocaleString();
    doc.text(`Generated: ${now}   |   Total Alerts: ${data.length}`, 14, 23);

    /* Stats summary bar */
    const counts = {critical: 0, high: 0, medium: 0, low: 0};
    let blockedCount = 0;
    data.forEach(a => {
      const s = (a.severity || 'low').toLowerCase();
      if (counts[s] !== undefined) counts[s]++; else counts.low++;
      if (a.blocked) blockedCount++;
    });

    doc.setFillColor(17, 28, 53);
    doc.roundedRect(14, 27, 269, 14, 3, 3, 'F');
    doc.setFontSize(8.5);
    const cols = [
      {label: 'Critical', val: counts.critical, color: [139, 92, 246]},
      {label: 'High', val: counts.high, color: [239, 68, 68]},
      {label: 'Medium', val: counts.medium, color: [245, 158, 11]},
      {label: 'Low', val: counts.low, color: [16, 185, 129]},
      {label: 'Blocked', val: blockedCount, color: [59, 130, 246]},
    ];
    cols.forEach((c, i) => {
      const x = 22 + i * 54;
      doc.setTextColor(...c.color);
      doc.setFont('helvetica', 'bold');
      doc.text(String(c.val), x, 36);
      doc.setTextColor(148, 163, 184);
      doc.setFont('helvetica', 'normal');
      doc.text(c.label, x + 8, 36);
    });

    /* Table */
    const tableHeaders = [['#', 'Time', 'Severity', 'Attack Type', 'Source IP', 'Dest IP', 'Proto', 'Action']];
    const tableRows = data.slice(0, 200).map((a, i) => [
      i + 1,
      humanDate(a.timestamp),
      (a.severity || 'low').toUpperCase(),
      (a.attack_type || '—').substring(0, 35),
      a.src_ip || '—',
      a.dest_ip || '—',
      a.protocol || '—',
      a.blocked ? 'BLOCKED' : 'ALERT'
    ]);

    doc.autoTable({
      head: tableHeaders,
      body: tableRows,
      startY: 46,
      margin: {left: 14, right: 14},
      styles: {
        fontSize: 7.5,
        cellPadding: 3,
        fillColor: [17, 28, 53],
        textColor: [226, 232, 240],
        lineColor: [30, 50, 90],
        lineWidth: 0.3,
        overflow: 'ellipsize'
      },
      headStyles: {
        fillColor: [11, 21, 40],
        textColor: [148, 163, 184],
        fontStyle: 'bold',
        fontSize: 7,
        halign: 'left'
      },
      alternateRowStyles: {fillColor: [13, 21, 40]},
      columnStyles: {
        0: {cellWidth: 8, halign: 'center'},
        1: {cellWidth: 35},
        2: {cellWidth: 18},
        3: {cellWidth: 65},
        4: {cellWidth: 32},
        5: {cellWidth: 32},
        6: {cellWidth: 16},
        7: {cellWidth: 20}
      },
      didParseCell: function(data) {
        if (data.column.index === 2 && data.section === 'body') {
          const sev = (data.cell.raw || '').toLowerCase();
          if (sev === 'critical') data.cell.styles.textColor = [167, 139, 250];
          else if (sev === 'high') data.cell.styles.textColor = [239, 68, 68];
          else if (sev === 'medium') data.cell.styles.textColor = [245, 158, 11];
          else data.cell.styles.textColor = [16, 185, 129];
        }
        if (data.column.index === 7 && data.section === 'body') {
          if (data.cell.raw === 'BLOCKED') data.cell.styles.textColor = [239, 68, 68];
          else data.cell.styles.textColor = [59, 130, 246];
        }
      }
    });

    /* Footer */
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(7);
      doc.setTextColor(71, 85, 105);
      doc.text(`AIBased IDS/IPS Platform  |  Page ${i} of ${pageCount}  |  CONFIDENTIAL`, 14, doc.internal.pageSize.height - 6);
    }

    const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
    doc.save(`ids-alerts-${ts}.pdf`);
    showToast(`Exported ${Math.min(data.length, 200)} alerts as PDF`, 'green');
  } catch (err) {
    console.error('PDF export error:', err);
    showToast('PDF export failed. Check console.', 'red');
  }
}

window.exportCSV = exportCSV;
window.exportPDF = exportPDF;

/* ────────────────── Toast ────────────────── */
function showToast(msg, color = 'blue') {
  const colors = {blue: 'rgba(59,130,246,0.3)', green: 'rgba(16,185,129,0.3)', red: 'rgba(239,68,68,0.3)'};
  const dots   = {blue: '#3b82f6', green: '#10b981', red: '#ef4444'};
  const el = document.createElement('div');
  el.className = 'sentinel-toast';
  el.style.borderColor = colors[color] || colors.blue;
  const dot = document.createElement('span');
  dot.style.color = dots[color] || dots.blue;
  dot.style.fontSize = '18px';
  dot.textContent = '●';
  el.appendChild(dot);
  el.appendChild(document.createTextNode(String(msg || '')));
  document.body.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .3s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

/* ────────────────── Event Listeners ────────────────── */
document.addEventListener('DOMContentLoaded', function () {
  /* Filter input */
  const fi = document.getElementById('filterInput');
  if (fi) fi.addEventListener('input', e => { currentFilter = e.target.value; applyFilter(); });

  /* Clear filter */
  const cf = document.getElementById('clearFilter');
  if (cf) cf.addEventListener('click', () => {
    currentFilter = '';
    const fi = document.getElementById('filterInput');
    if (fi) fi.value = '';
    applyFilter();
  });

  /* Mode button */
  const mb = document.getElementById('setModeBtn');
  if (mb) mb.addEventListener('click', () => {
    const sel = document.getElementById('modeSelect');
    if (sel) setMode(sel.value);
  });

  /* Panic button */
  const pb = document.getElementById('panicBtn');
  if (pb) pb.addEventListener('click', () => {
    if (confirm('⚠️ PANIC: This will disable IPS mode and switch to IDS (detect only). Continue?'))
      setMode('IDS');
  });

  /* Set mode select to current */
  const cm = document.getElementById('currentMode');
  const ms = document.getElementById('modeSelect');
  if (cm && ms) ms.value = cm.textContent.trim();
});

/* ────────────────── Polling Loop ────────────────── */
async function loop() {
  await fetchAlerts();
  await fetchStats();
}

window.addEventListener('load', () => { loop(); setInterval(loop, 4000); });
