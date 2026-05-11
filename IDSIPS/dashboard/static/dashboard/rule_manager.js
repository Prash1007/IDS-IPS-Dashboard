// dashboard/static/dashboard/rule_manager.js
// ════ RULE MANAGER ENGINE ════
const RM_KNOWN_PROTOCOLS = new Set(['tcp', 'udp', 'icmp', 'ip', 'http', 'dns', 'tls', 'smtp', 'ssh', 'ftp', 'smb']);
const RM_BADGE_PROTOCOLS = new Set(['tcp', 'udp', 'icmp', 'ip', 'http', 'dns', 'tls', 'smtp']);

function rmEl(id) {
  return document.getElementById(id);
}

function setRMText(id, value) {
  const el = rmEl(id);
  if (el) el.textContent = value;
}

function setRMValue(id, value) {
  const el = rmEl(id);
  if (el) el.value = value ?? '';
}

function setRMChecked(id, checked) {
  const el = rmEl(id);
  if (el) el.checked = !!checked;
}

function setRMDisplay(id, display) {
  const el = rmEl(id);
  if (el) el.style.display = display;
}

function cssToken(value, fallback = 'other') {
  const token = String(value || '').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  return token || fallback;
}

function getSelectedProtocol() {
  const select = rmEl('rf-proto');
  if (!select) return 'tcp';
  if (select.value !== '__other__') return select.value || 'tcp';
  return (rmEl('rf-proto-other')?.value || '').trim().toLowerCase() || 'ip';
}

function setProtocolField(proto) {
  const normalized = String(proto || 'tcp').trim().toLowerCase() || 'tcp';
  const select = rmEl('rf-proto');
  if (!select) return;
  if (RM_KNOWN_PROTOCOLS.has(normalized)) {
    select.value = normalized;
    setRMValue('rf-proto-other', '');
    setRMDisplay('rf-proto-other', 'none');
  } else {
    select.value = '__other__';
    setRMValue('rf-proto-other', normalized);
    setRMDisplay('rf-proto-other', 'block');
  }
}

function handleProtocolChange() {
  const isOther = rmEl('rf-proto')?.value === '__other__';
  setRMDisplay('rf-proto-other', isOther ? 'block' : 'none');
  RM.buildPreview();
}

const RM = {
  rules: [],
  editingId: null,
  nextSid: 1000001,
  currentTab: 'builder',

  templates: [
    { name:'ICMP Ping Detect', icon:'🏓', proto:'icmp', action:'alert', srcIp:'any', srcPort:'any', dstIp:'any', dstPort:'any', msg:'ICMP Ping Detected', sid:1000001, classtype:'attempted-recon', desc:'Detects any ICMP ping traffic', tag:'recon' },
    { name:'SSH Connection', icon:'🔑', proto:'tcp', action:'alert', srcIp:'any', srcPort:'any', dstIp:'any', dstPort:'22', msg:'SSH Connection Attempt', sid:1000002, classtype:'attempted-admin', desc:'Alerts on any TCP connection to port 22', tag:'ssh' },
    { name:'SSH Brute Force', icon:'🔨', proto:'tcp', action:'alert', srcIp:'any', srcPort:'any', dstIp:'any', dstPort:'22', msg:'Possible SSH Brute Force', sid:1000003, flags:'S', thresh:true, threshType:'both', threshTrack:'by_src', threshCount:5, threshSecs:60, desc:'Detects rapid SSH connection attempts', tag:'brute-force' },
    { name:'Port Scan', icon:'🔍', proto:'tcp', action:'alert', srcIp:'any', srcPort:'any', dstIp:'$HOME_NET', dstPort:'any', msg:'TCP Port Scan Detected', sid:1000004, flags:'S', classtype:'network-scan', desc:'Detects sequential port scanning', tag:'scan' },
    { name:'HTTP Suspicious UA', icon:'🌐', proto:'http', action:'alert', srcIp:'any', srcPort:'any', dstIp:'$HTTP_SERVERS', dstPort:'$HTTP_PORTS', msg:'Suspicious HTTP User Agent', sid:1000005, content:'sqlmap', classtype:'web-application-attack', desc:'Detects sqlmap in HTTP traffic', tag:'web' },
    { name:'DNS Tunneling', icon:'📋', proto:'udp', action:'alert', srcIp:'$HOME_NET', srcPort:'any', dstIp:'any', dstPort:'53', msg:'Possible DNS Tunneling', sid:1000006, classtype:'trojan-activity', desc:'Detects unusually large DNS queries (potential exfiltration)', tag:'dns' },
    { name:'Telnet Access', icon:'📟', proto:'tcp', action:'drop', srcIp:'any', srcPort:'any', dstIp:'$HOME_NET', dstPort:'23', msg:'Telnet Connection Blocked', sid:1000007, classtype:'policy-violation', desc:'Blocks insecure Telnet connections', tag:'policy' },
    { name:'RDP Brute Force', icon:'🖥️', proto:'tcp', action:'alert', srcIp:'any', srcPort:'any', dstIp:'$HOME_NET', dstPort:'3389', msg:'RDP Brute Force Attempt', sid:1000008, flags:'S', thresh:true, threshType:'both', threshTrack:'by_src', threshCount:10, threshSecs:60, desc:'Detects rapid RDP connection attempts', tag:'brute-force' },
  ],

  init() {
    this.loadRules();
    this.renderTemplates();
    handleProtocolChange();
    this.buildPreview();
  },

  loadRules(options = {}) {
    const silent = options.silent === true;
    // Load from API
    return fetch('/api/rules/', { cache: 'no-store' }).then(parseRMResponse).then(d => {
      this.rules = d.rules || [];
      this.updateNextSid(d.next_sid);
      this.renderRulesList();
      this.updateStats();
      this.refreshSyncBadge();
    }).catch((error) => {
      this.rules = [];
      this.updateNextSid();
      this.renderRulesList();
      this.updateStats();
      if (!silent) showRMToast(getRMErrorMessage(error, 'Rule API not reachable'), 'red');
    });
  },

  updateNextSid(serverNextSid) {
    const maxSid = this.rules.reduce((m, r) => Math.max(m, r.sid || 0), 1000000);
    this.nextSid = Math.max(1000001, serverNextSid || (maxSid + 1));
    const sidEl = document.getElementById('rf-sid');
    if (sidEl && !this.editingId) sidEl.value = this.nextSid;
  },

  updateStats() {
    const total    = this.rules.length;
    const active   = this.rules.filter(r=>r.enabled).length;
    const disabled = this.rules.filter(r=>!r.enabled).length;
    setRMText('rm-total', total);
    setRMText('rm-active', active);
    setRMText('rm-disabled', disabled);
    setRMText('rm-custom', total);
  },

  renderRulesList(filter='', protoFilter='', statusFilter='') {
    const el = document.getElementById('rmRulesList');
    const empty = document.getElementById('rmEmptyState');
    if (!el) return;
    let rules = [...this.rules];
    if (filter)       rules = rules.filter(r => (r.msg || '').toLowerCase().includes(filter.toLowerCase()) || String(r.sid || '').includes(filter));
    if (protoFilter)  rules = rules.filter(r => r.proto === protoFilter);
    if (statusFilter) rules = rules.filter(r => statusFilter==='active' ? r.enabled : !r.enabled);

    el.innerHTML = '';
    if (rules.length === 0) {
      if (empty) {
        el.appendChild(empty);
        empty.style.display = 'flex';
      }
      return;
    }
    if (empty) empty.style.display = 'none';
    rules.forEach(rule => {
      const div = document.createElement('div');
      const protoClass = RM_BADGE_PROTOCOLS.has(rule.proto) ? cssToken(rule.proto) : 'other';
      div.className = `rm-rule-item proto-${protoClass} ${!rule.enabled?'disabled':''} ${this.editingId===rule.id?'selected':''}`;
      div.dataset.id = rule.id;
      div.onclick = () => this.editRule(rule.id);
      const actionBadge = `rm-badge-${cssToken(rule.action)}`;
      const protoBadge  = `rm-badge-${RM_BADGE_PROTOCOLS.has(rule.proto) ? cssToken(rule.proto) : 'other'}`;
      div.innerHTML = `
        <div class="rm-rule-top">
          <div class="rm-rule-msg" title="${escapeHTML(rule.msg)}">${escapeHTML(rule.msg)}</div>
          <div class="rm-rule-badges">
            <span class="rm-badge ${protoBadge}">${escapeHTML(String(rule.proto || '').toUpperCase())}</span>
            <span class="rm-badge ${actionBadge}">${escapeHTML(rule.action)}</span>
            ${!rule.enabled ? '<span class="rm-badge rm-badge-disabled">OFF</span>' : ''}
          </div>
        </div>
        <div class="rm-rule-meta">
          <span>SID: ${rule.sid}</span>
          <span>${escapeHTML(rule.srcIp)}:${escapeHTML(rule.srcPort)} ${escapeHTML(rule.dir||'->')} ${escapeHTML(rule.dstIp)}:${escapeHTML(rule.dstPort)}</span>
        </div>
        <div class="rm-rule-actions"></div>`;
      const actions = div.querySelector('.rm-rule-actions');
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'rm-icon-btn';
      toggleBtn.title = rule.enabled ? 'Disable' : 'Enable';
      toggleBtn.innerHTML = `<i class="fas fa-${rule.enabled ? 'toggle-on' : 'toggle-off'}" style="color:${rule.enabled ? '#10b981' : '#475569'}"></i>`;
      toggleBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        RM.toggleRule(rule.id);
      });
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'rm-icon-btn del';
      deleteBtn.title = 'Delete';
      deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
      deleteBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        RM.deleteRule(rule.id);
      });
      actions?.append(toggleBtn, deleteBtn);
      el.appendChild(div);
    });
  },

  editRule(id) {
    const rule = this.rules.find(r=>r.id===id);
    if (!rule) return;
    this.editingId = id;
    setRMText('rmEditorTitle', 'Edit Rule');
    setRMText('rmSaveBtnText', 'Update Rule');
    // Fill form
    setRMValue('rf-action', rule.action);
    setProtocolField(rule.proto);
    setRMValue('rf-src-ip', rule.srcIp);
    setRMValue('rf-src-port', rule.srcPort);
    setRMValue('rf-dst-ip', rule.dstIp);
    setRMValue('rf-dst-port', rule.dstPort);
    setRMValue('rf-msg', rule.msg);
    setRMValue('rf-sid', rule.sid);
    setRMValue('rf-rev', rule.rev || 1);
    setRMValue('rf-classtype', rule.classtype || '');
    setRMValue('rf-content', rule.content || '');
    setRMValue('rf-flags', rule.flags || '');
    setRMValue('rf-flow', rule.flow || '');
    setRMChecked('rf-enabled', rule.enabled);
    setRMValue('rf-comment', rule.comment || '');
    setRMValue('rf-priority', rule.priority || '');
    setRMValue('rf-ref', rule.ref || '');
    // Direction
    const dirInputs = document.querySelectorAll('input[name="dir"]');
    dirInputs.forEach(inp => { if(inp.value === (rule.dir||'->')) inp.checked = true; });
    // Threshold
    setRMChecked('rf-thresh-en', !!rule.thresh);
    toggleThreshold();
    if (rule.thresh) {
      setRMChecked('rf-thresh-en', true);
      setRMValue('rf-thresh-type', rule.threshType || 'both');
      setRMValue('rf-thresh-track', rule.threshTrack || 'by_src');
      setRMValue('rf-thresh-count', rule.threshCount || 5);
      setRMValue('rf-thresh-secs', rule.threshSecs || 60);
    }
    switchTab('builder', document.querySelector('.rm-tab'));
    this.buildPreview();
    this.renderRulesList(document.getElementById('rmSearch').value);
  },

  deleteRule(id) {
    if (!confirm('Delete this rule permanently?')) return;
    fetch(`/api/rules/${id}/`, { method:'DELETE', headers:{'X-CSRFToken':getCsrf()} })
      .then(parseRMResponse)
      .then(resp => {
        this.rules = this.rules.filter(r=>r.id!==id);
        if (this.editingId === id) this.clearForm();
        this.updateNextSid(resp.next_sid);
        this.renderRulesList();
        this.updateStats();
        this.applySyncFeedback(resp.sync, 'Rule deleted');
        this.loadRules({ silent: true });
      })
      .catch((error) => {
        showRMToast(getRMErrorMessage(error, 'Failed to delete rule'), 'red');
      });
  },

  toggleRule(id) {
    const rule = this.rules.find(r=>r.id===id);
    if (!rule) return;
    fetch(`/api/rules/${id}/`, {
      method:'PATCH',
      headers:{'Content-Type':'application/json','X-CSRFToken':getCsrf()},
      body: JSON.stringify({enabled: !rule.enabled})
    }).then(parseRMResponse)
      .then(resp => {
        const idx = this.rules.findIndex(item => item.id === id);
        if (idx >= 0 && resp.rule) this.rules[idx] = resp.rule;
        this.renderRulesList();
        this.updateStats();
        this.applySyncFeedback(resp.sync, `Rule ${resp.rule?.enabled ? 'enabled' : 'disabled'}`);
        this.loadRules({ silent: true });
      })
      .catch((error) => {
        showRMToast(getRMErrorMessage(error, 'Failed to toggle rule'), 'red');
      });
  },

  buildPreview() {
    const action   = document.getElementById('rf-action')?.value || 'alert';
    const proto    = getSelectedProtocol();
    const srcIp    = document.getElementById('rf-src-ip')?.value.trim() || 'any';
    const srcPort  = document.getElementById('rf-src-port')?.value.trim() || 'any';
    const dstIp    = document.getElementById('rf-dst-ip')?.value.trim() || 'any';
    const dstPort  = document.getElementById('rf-dst-port')?.value.trim() || 'any';
    const dir      = document.querySelector('input[name="dir"]:checked')?.value || '->';
    const msg      = document.getElementById('rf-msg')?.value.trim() || '';
    const sid      = document.getElementById('rf-sid')?.value || this.nextSid;
    const rev      = document.getElementById('rf-rev')?.value || '1';
    const classtype= document.getElementById('rf-classtype')?.value || '';
    const content  = document.getElementById('rf-content')?.value.trim() || '';
    const flags    = document.getElementById('rf-flags')?.value.trim() || '';
    const flow     = document.getElementById('rf-flow')?.value || '';
    const priority = document.getElementById('rf-priority')?.value || '';
    const ref      = document.getElementById('rf-ref')?.value.trim() || '';
    const comment  = document.getElementById('rf-comment')?.value.trim() || '';
    const enabled  = document.getElementById('rf-enabled')?.checked ?? true;
    const threshEn = document.getElementById('rf-thresh-en')?.checked ?? false;

    let options = '';
    if (msg)       options += `msg:"${msg}"; `;
    if (content)   options += `content:"${content}"; `;
    if (flags)     options += `flags:${flags}; `;
    if (flow)      options += `flow:${flow}; `;
    if (threshEn) {
      const tt = document.getElementById('rf-thresh-type')?.value || 'both';
      const tr = document.getElementById('rf-thresh-track')?.value || 'by_src';
      const tc = document.getElementById('rf-thresh-count')?.value || 5;
      const ts = document.getElementById('rf-thresh-secs')?.value || 60;
      options += `threshold:type ${tt}, track ${tr}, count ${tc}, seconds ${ts}; `;
    }
    if (classtype) options += `classtype:${classtype}; `;
    if (priority)  options += `priority:${priority}; `;
    if (ref)       options += `reference:${ref}; `;
    options += `sid:${sid}; rev:${rev};`;

    const rule = `${action} ${proto} ${srcIp} ${srcPort} ${dir} ${dstIp} ${dstPort} (${options})`;
    const lines = [];
    if (comment) {
      const border = '# ' + '-'.repeat(Math.min(50, comment.length + 4));
      lines.push(border);
      lines.push(`# ${comment}`);
      lines.push(border);
    }
    if (!enabled) lines.push(`# DISABLED: ${rule}`);
    else lines.push(rule);
    const finalRule = lines.join('\n');

    // Syntax highlight
    const highlighted = this.highlight(finalRule);
    const pre = document.getElementById('rmPreviewBox');
    if (pre) pre.innerHTML = highlighted;

    // Validation
    this.validatePreview(msg, sid, action, proto);
    return finalRule;
  },

  highlight(text) {
    return escapeHTML(text)
      .replace(/^(alert|drop|reject|pass)/m, '<span class="kw-action">$1</span>')
      .replace(/\b(tcp|udp|icmp|ip|http|dns|tls|smtp|ssh|ftp|smb|modbus|dnp3)\b/, '<span class="kw-proto">$1</span>')
      .replace(/&quot;([^&]|&(?!quot;))*&quot;/g, '<span class="kw-string">$&</span>')
      .replace(/\b(msg|content|flags|flow|sid|rev|classtype|priority|reference|threshold|type|track|count|seconds):(?="[^"]*"|\w)/g, '<span class="kw-option">$1</span>:')
      .replace(/\b(any|\$[A-Z_]+)\b/g, '<span class="kw-ip">$1</span>');
  },

  validatePreview(msg, sid, action, proto) {
    const el = document.getElementById('rmValidation');
    if (!el) return;
    const errors = [];
    if (!msg)  errors.push('Message (msg) is required');
    if (!sid)  errors.push('SID is required');
    if (parseInt(sid, 10) < 1000001) errors.push('SID must be >= 1000001 for custom rules');
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(proto)) errors.push('Protocol must use letters, numbers, underscore, or dash only');
    const dupSid = this.rules.find(r => r.sid == sid && r.id !== this.editingId);
    if (dupSid) errors.push(`SID ${sid} already in use by: "${dupSid.msg}"`);
    if (errors.length > 0) {
      el.innerHTML = errors.map(e=>`<div class="rm-val-err"><i class="fas fa-circle-xmark"></i> ${escapeHTML(e)}</div>`).join('');
    } else {
      el.innerHTML = '<div class="rm-val-ok"><i class="fas fa-circle-check"></i> Rule syntax looks valid</div>';
    }
  },

  getRuleData() {
    return {
      id:          this.editingId || 'r' + Date.now(),
      action:      document.getElementById('rf-action').value,
      proto:       getSelectedProtocol(),
      srcIp:       document.getElementById('rf-src-ip').value.trim(),
      srcPort:     document.getElementById('rf-src-port').value.trim(),
      dir:         document.querySelector('input[name="dir"]:checked')?.value || '->',
      dstIp:       document.getElementById('rf-dst-ip').value.trim(),
      dstPort:     document.getElementById('rf-dst-port').value.trim(),
      msg:         document.getElementById('rf-msg').value.trim(),
      sid:         parseInt(document.getElementById('rf-sid').value),
      rev:         parseInt(document.getElementById('rf-rev').value) || 1,
      classtype:   document.getElementById('rf-classtype').value,
      content:     document.getElementById('rf-content').value.trim(),
      flags:       document.getElementById('rf-flags').value.trim(),
      flow:        document.getElementById('rf-flow').value,
      priority:    document.getElementById('rf-priority').value,
      ref:         document.getElementById('rf-ref').value.trim(),
      comment:     document.getElementById('rf-comment').value.trim(),
      enabled:     document.getElementById('rf-enabled').checked,
      thresh:      document.getElementById('rf-thresh-en').checked,
      threshType:  document.getElementById('rf-thresh-type')?.value || 'both',
      threshTrack: document.getElementById('rf-thresh-track')?.value || 'by_src',
      threshCount: parseInt(document.getElementById('rf-thresh-count')?.value) || 5,
      threshSecs:  parseInt(document.getElementById('rf-thresh-secs')?.value) || 60,
      rawRule:     this.buildPreview(),
    };
  },

  saveRule() {
    const data = this.getRuleData();
    if (!data.msg) { showRMToast('Message (msg) is required', 'red'); return; }
    if (!data.sid) { showRMToast('SID is required', 'red'); return; }
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(data.proto)) { showRMToast('Invalid protocol name', 'red'); return; }
    const isEditing = !!this.editingId;

    const btn = document.getElementById('rmSaveBtn');
    if (btn) {
      btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
      btn.disabled = true;
    }

    const method = this.editingId ? 'PUT' : 'POST';
    const url    = this.editingId ? `/api/rules/${this.editingId}/` : '/api/rules/';

    fetch(url, {
      method,
      headers: {'Content-Type':'application/json','X-CSRFToken':getCsrf()},
      body: JSON.stringify(data)
    }).then(parseRMResponse)
      .then(resp => {
        if (isEditing) {
          const idx = this.rules.findIndex(r=>r.id===this.editingId);
          if (idx >= 0) this.rules[idx] = resp.rule || {...data, id: this.editingId};
        } else {
          this.rules.push(resp.rule || {...data, id: resp.id || data.id});
        }
        this.editingId = null;
        this.updateNextSid(resp.next_sid);
        this.renderRulesList();
        this.updateStats();
        this.clearForm();
        this.applySyncFeedback(resp.sync, isEditing ? 'Rule updated' : 'Rule saved');
        this.loadRules({ silent: true });
      })
      .catch((error) => {
        showRMToast(getRMErrorMessage(error, 'Failed to save rule'), 'red');
      })
      .finally(() => {
        if (btn) {
          btn.innerHTML = '<i class="fas fa-floppy-disk"></i> <span id="rmSaveBtnText">Save Rule</span>';
          btn.disabled = false;
        }
      });
  },

  clearForm() {
    this.editingId = null;
    setRMText('rmEditorTitle', 'New Rule');
    setRMText('rmSaveBtnText', 'Save Rule');
    ['rf-action','rf-classtype','rf-flow'].forEach(id => { const el=document.getElementById(id); if(el) el.value = id==='rf-action'?'alert':''; });
    setProtocolField('tcp');
    ['rf-src-ip','rf-dst-ip'].forEach(id => { const el=document.getElementById(id); if(el) el.value='any'; });
    ['rf-src-port','rf-dst-port'].forEach(id => { const el=document.getElementById(id); if(el) el.value='any'; });
    ['rf-msg','rf-content','rf-flags','rf-comment','rf-priority','rf-ref'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
    setRMValue('rf-sid', this.nextSid);
    setRMValue('rf-rev', '1');
    setRMChecked('rf-enabled', true);
    setRMChecked('rf-thresh-en', false);
    setRMDisplay('rmThreshFields', 'none');
    const dir = document.querySelector('input[name="dir"][value="->"]'); if(dir) dir.checked=true;
    this.buildPreview();
    this.renderRulesList();
  },

  renderTemplates() {
    const grid = document.getElementById('rmTemplatesGrid');
    if (!grid) return;
    grid.innerHTML = '';
    this.templates.forEach(t => {
      const div = document.createElement('div');
      div.className = 'rm-template-card';
      div.innerHTML = `<div class="rm-template-icon">${escapeHTML(t.icon)}</div><div class="rm-template-name">${escapeHTML(t.name)}</div><div class="rm-template-desc">${escapeHTML(t.desc)}</div><div class="rm-template-tag">${escapeHTML(t.tag)}</div>`;
      div.onclick = () => this.applyTemplate(t);
      grid.appendChild(div);
    });
  },

  applyTemplate(t) {
    document.getElementById('rf-action').value   = t.action;
    setProtocolField(t.proto);
    document.getElementById('rf-src-ip').value   = t.srcIp || 'any';
    document.getElementById('rf-src-port').value = t.srcPort || 'any';
    document.getElementById('rf-dst-ip').value   = t.dstIp || 'any';
    document.getElementById('rf-dst-port').value = t.dstPort || 'any';
    document.getElementById('rf-msg').value      = t.msg;
    document.getElementById('rf-sid').value      = this.nextSid;
    document.getElementById('rf-classtype').value= t.classtype || '';
    document.getElementById('rf-content').value  = t.content || '';
    document.getElementById('rf-flags').value    = t.flags || '';
    document.getElementById('rf-comment').value  = t.desc || '';
    setRMChecked('rf-thresh-en', !!t.thresh);
    toggleThreshold();
    if (t.thresh) {
      setRMChecked('rf-thresh-en', true);
      setRMValue('rf-thresh-type', t.threshType || 'both');
      setRMValue('rf-thresh-track', t.threshTrack || 'by_src');
      setRMValue('rf-thresh-count', t.threshCount || 5);
      setRMValue('rf-thresh-secs', t.threshSecs || 60);
    }
    switchTab('builder', document.querySelector('.rm-tab'));
    this.buildPreview();
    showRMToast(`Template "${t.name}" loaded`, 'blue');
  },

  markFileDirty() {
    const badge = document.getElementById('rmFileBadge');
    if (badge) { badge.textContent='Pending Reload'; badge.classList.add('dirty'); }
  },

  markFileSynced(label='Synced') {
    const badge = document.getElementById('rmFileBadge');
    if (badge) {
      badge.textContent = label;
      badge.classList.remove('dirty');
    }
  },

  refreshSyncBadge() {
    if (!this.rules.length) {
      this.markFileSynced('Synced');
      return;
    }
    const statuses = new Set(this.rules.map(rule => rule.syncStatus));
    if (statuses.has('failed')) {
      this.markFileDirty();
      return;
    }
    if (statuses.has('local-only')) {
      this.markFileSynced('Local Only');
      return;
    }
    if (statuses.has('pending')) {
      this.markFileDirty();
      return;
    }
    this.markFileSynced('Synced');
  },

  applySyncFeedback(sync, successLabel='Saved') {
    if (!sync) {
      this.markFileDirty();
      showRMToast(successLabel, 'green');
      return;
    }
    if (!sync.configured) {
      this.markFileSynced('Local Only');
      showRMToast(sync.message || `${successLabel} locally`, 'yellow');
      return;
    }
    if (sync.success) {
      this.markFileSynced(sync.reloaded ? 'Synced' : 'Uploaded');
      showRMToast(sync.message || `${successLabel} and synced`, 'green');
      return;
    }
    this.markFileDirty();
    showRMToast(sync.message || 'Remote sync failed', 'red');
  },

  generateFileContent() {
    const lines = ['# ══════════════════════════════════════════════════════',
                   '# Suricata Custom Rules — Generated by AIBased IDS/IPS',
                   `# Updated: ${new Date().toISOString()}`,
                   '# ══════════════════════════════════════════════════════', ''];
    this.rules.forEach(r => {
      if (r.comment) {
        lines.push('# ' + '─'.repeat(34));
        lines.push(`# ${r.comment}`);
        lines.push('# ' + '─'.repeat(34));
      }
      let opts = `msg:"${r.msg}"; `;
      if (r.content)  opts += `content:"${r.content}"; `;
      if (r.flags)    opts += `flags:${r.flags}; `;
      if (r.flow)     opts += `flow:${r.flow}; `;
      if (r.thresh)   opts += `threshold:type ${r.threshType||'both'}, track ${r.threshTrack||'by_src'}, count ${r.threshCount||5}, seconds ${r.threshSecs||60}; `;
      if (r.classtype)opts += `classtype:${r.classtype}; `;
      if (r.priority) opts += `priority:${r.priority}; `;
      if (r.ref)      opts += `reference:${r.ref}; `;
      opts += `sid:${r.sid}; rev:${r.rev||1};`;
      const rule = `${r.action} ${r.proto} ${r.srcIp} ${r.srcPort} ${r.dir||'->'} ${r.dstIp} ${r.dstPort} (${opts})`;
      lines.push(r.enabled ? rule : `# DISABLED: ${rule}`);
      lines.push('');
    });
    return lines.join('\n');
  }
};

// Controls
function filterRules() {
  RM.renderRulesList(
    document.getElementById('rmSearch').value,
    document.getElementById('rmProtoFilter').value,
    document.getElementById('rmStatusFilter').value
  );
}
function openNewRule() { RM.clearForm(); rmEl('rf-msg')?.focus(); }
function cancelEdit()  { RM.clearForm(); }
function clearForm()   { RM.clearForm(); }
function buildPreview(){ RM.buildPreview(); }
function saveRule()    { RM.saveRule(); }

function switchTab(name, el) {
  RM.currentTab = name;
  document.querySelectorAll('.rm-tab-content').forEach(c=>c.style.display='none');
  document.querySelectorAll('.rm-tab').forEach(t=>t.classList.remove('active'));
  setRMDisplay(`tab-${name}`, 'flex');
  if (el) el.classList.add('active');
  else {
    const tabs = document.querySelectorAll('.rm-tab');
    const names = ['builder','raw','templates'];
    tabs[names.indexOf(name)]?.classList.add('active');
  }
}

function toggleAdvanced() {
  const adv = document.getElementById('rmAdvanced');
  const toggle = document.querySelector('.rm-advanced-toggle');
  if (!adv) return;
  const open = adv.style.display !== 'none';
  adv.style.display = open ? 'none' : 'block';
  toggle?.classList.toggle('open', !open);
}
function toggleThreshold() {
  const en = document.getElementById('rf-thresh-en')?.checked;
  setRMDisplay('rmThreshFields', en ? 'block' : 'none');
  RM.buildPreview();
}
function copyRule() {
  const text = RM.buildPreview();
  navigator.clipboard.writeText(text).then(()=>showRMToast('Rule copied!','green'));
}
function parseRawRule() {
  const raw = document.getElementById('rmRawEditor').value.trim();
  if (!raw) return;
  const m = raw.match(/^(alert|drop|reject|pass)\s+([a-z][a-z0-9_-]{0,31})\s+(\S+)\s+(\S+)\s+(<>|->)\s+(\S+)\s+(\S+)\s+\((.+)\)$/i);
  if (m) {
    document.getElementById('rf-action').value   = m[1];
    setProtocolField(m[2]);
    document.getElementById('rf-src-ip').value   = m[3];
    document.getElementById('rf-src-port').value = m[4];
    document.getElementById('rf-dst-ip').value   = m[6];
    document.getElementById('rf-dst-port').value = m[7];
    const opts = m[8];
    const msgM = opts.match(/msg:"([^"]+)"/);   if(msgM) document.getElementById('rf-msg').value=msgM[1];
    const sidM = opts.match(/sid:(\d+)/);        if(sidM) document.getElementById('rf-sid').value=sidM[1];
    const revM = opts.match(/rev:(\d+)/);        if(revM) document.getElementById('rf-rev').value=revM[1];
    const dir = document.querySelector(`input[name="dir"][value="${m[5]}"]`); if(dir) dir.checked=true;
    switchTab('builder', document.querySelector('.rm-tab'));
    RM.buildPreview();
    showRMToast('Rule parsed into builder', 'green');
  } else {
    showRMToast('Could not parse rule syntax', 'red');
  }
}
function validateRules() {
  const errors = RM.rules.filter(r => !r.msg || !r.sid);
  if (errors.length===0) showRMToast('All rules valid ✓', 'green');
  else showRMToast(`${errors.length} rule(s) have issues`, 'red');
}
function reloadSuricata() {
  fetch('/api/reload/', { method:'POST', headers:{'X-CSRFToken':getCsrf()} })
    .then(parseRMResponse)
    .then(d=>{
      RM.applySyncFeedback({
        configured: d.configured,
        success: d.success,
        message: d.message,
        reloaded: d.reloaded,
      }, 'Reload triggered');
    })
    .catch((error)=>{ showRMToast(getRMErrorMessage(error, 'Reload triggered (check server)'), 'blue'); });
}
function closeFileModal() { setRMDisplay('rmFileModal', 'none'); }
function copyFileContent() {
  navigator.clipboard.writeText(document.getElementById('rmModalContent')?.textContent || '')
    .then(()=>showRMToast('Copied to clipboard','green'));
}
function getCsrf() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta?.content) return meta.content;
  const m=document.cookie.match(/csrftoken=([^;]+)/);
  return m?decodeURIComponent(m[1]):'';
}
function sanitizeRMMessage(text, fallback='Request failed') {
  const compact = String(text || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return compact ? compact.slice(0, 220) : fallback;
}
function parseRMResponse(response) {
  return response.text().then((text) => {
    let payload = {};
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { message: sanitizeRMMessage(text, `Request failed (${response.status})`) };
      }
    }
    if (!response.ok) {
      throw new Error(payload.message || payload.error || `Request failed (${response.status})`);
    }
    return payload;
  });
}
function getRMErrorMessage(error, fallback='Request failed') {
  if (!error) return fallback;
  if (typeof error === 'string') return error;
  return error.message || fallback;
}
function showRMToast(msg, color='blue') {
  const colors={blue:'rgba(59,130,246,0.3)',green:'rgba(16,185,129,0.3)',red:'rgba(239,68,68,0.3)',yellow:'rgba(245,158,11,0.3)'};
  const dots={blue:'#3b82f6',green:'#10b981',red:'#ef4444',yellow:'#f59e0b'};
  const el=document.createElement('div');
  el.className='sentinel-toast';
  el.style.borderColor=colors[color]||colors.blue;
  const dot=document.createElement('span');
  dot.style.color=dots[color]||dots.blue;
  dot.style.fontSize='18px';
  dot.textContent='●';
  el.appendChild(dot);
  el.appendChild(document.createTextNode(String(msg || '')));
  document.body.appendChild(el);
  setTimeout(()=>{el.style.transition='opacity .3s';el.style.opacity='0';setTimeout(()=>el.remove(),300);},3000);
}

document.addEventListener('DOMContentLoaded', () => RM.init());
