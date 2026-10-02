(function () {
  'use strict';

  var base = location.pathname.replace(/\/index\.html$/, '').replace(/\/$/, '');
  var api = base + '/api';

  function $(id) { return document.getElementById(id); }

  // Everything that comes from the network or from a request (URIs, User-Agents, reasons...)
  // is attacker-influenced text. It is ALWAYS passed through esc() before it goes into markup.
  function esc(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  async function j(path, opts) {
    var res = await fetch(api + path, opts);
    if (res.status === 401) throw new Error('Not authorised - reload the page and log in again.');
    if (!res.ok) {
      var text = '';
      try { text = await res.text(); } catch (e) { /* ignore */ }
      throw new Error(res.status + ' ' + text.slice(0, 200));
    }
    var ct = res.headers.get('content-type') || '';
    return ct.indexOf('json') !== -1 ? res.json() : res.text();
  }

  function jsonOpts(method, body) {
    return { method: method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) };
  }

  var toastTimer = null;
  function toast(msg, isError) {
    var el = $('toast');
    el.textContent = msg;
    el.classList.toggle('error', !!isError);
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.hidden = true; }, 3500);
  }

  function fmtTime(iso) { return iso ? new Date(iso).toLocaleTimeString() : ''; }
  function fmtDateTime(iso) { return iso ? new Date(iso).toLocaleString() : ''; }
  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function sevBadge(sev) {
    return '<span class="sev sev-' + esc(sev || 'none') + '">' + esc(sev || '-') + '</span>';
  }

  // ---------- state ----------
  var S = {
    view: 'events',
    events: { rows: [], sort: { key: 'timestamp', dir: 'desc' }, page: 1, pageSize: 50, expanded: {} },
    ips: { rows: [], sort: { key: 'lastSeen', dir: 'desc' } },
    history: { rows: [], kind: 'events', sort: { key: 'timestamp', dir: 'desc' } },
    accessTab: 'allow',
    ip: { current: null, view: 'paths', profile: null, events: [] },
    protectionDirty: false
  };

  // ---------- sorting ----------
  var SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  var DESC_FIRST = { timestamp: 1, threatScore: 1, severity: 1, totalRequests: 1, distinctPaths: 1,
    notFoundRequests: 1, blockedRequests: 1, maxThreatScore: 1, lastSeen: 1, firstSeen: 1, status: 1 };
  var TIME_KEYS = { timestamp: 1, firstSeen: 1, lastSeen: 1 };

  function ipToNumber(ip) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip || '');
    if (!m) return null;
    return (((+m[1]) * 256 + (+m[2])) * 256 + (+m[3])) * 256 + (+m[4]);
  }

  function compareBy(key, a, b) {
    var x = a[key], y = b[key];
    if (key === 'sourceIp' || key === 'ip') {
      var nx = ipToNumber(x), ny = ipToNumber(y);
      if (nx !== null && ny !== null) return nx - ny;
      if (nx !== null) return -1;
      if (ny !== null) return 1;
      return String(x || '').localeCompare(String(y || ''));
    }
    if (TIME_KEYS[key]) return (Date.parse(x) || 0) - (Date.parse(y) || 0);
    if (key === 'severity') return (SEV_RANK[x] || 0) - (SEV_RANK[y] || 0);
    if (typeof x === 'number' || typeof y === 'number') return (Number(x) || 0) - (Number(y) || 0);
    return String(x === null || x === undefined ? '' : x).localeCompare(String(y === null || y === undefined ? '' : y));
  }

  function sortRows(rows, sort) {
    var dir = sort.dir === 'asc' ? 1 : -1;
    return rows.slice().sort(function (a, b) { return dir * compareBy(sort.key, a, b); });
  }

  function markSorted(tableId, sort) {
    var heads = document.querySelectorAll('#' + tableId + ' th[data-sort]');
    Array.prototype.forEach.call(heads, function (th) {
      th.classList.remove('sorted-asc', 'sorted-desc');
      if (th.dataset.sort === sort.key) th.classList.add(sort.dir === 'asc' ? 'sorted-asc' : 'sorted-desc');
    });
  }

  function onSort(th) {
    var table = th.dataset.table, key = th.dataset.sort;
    var st = S[table].sort;
    if (st.key === key) {
      st.dir = st.dir === 'asc' ? 'desc' : 'asc';
    } else {
      st.key = key;
      st.dir = DESC_FIRST[key] ? 'desc' : 'asc';
    }
    if (table === 'events') { S.events.page = 1; renderEvents(); }
    else if (table === 'ips') renderIps();
    else if (table === 'history') renderHistory();
  }

  // ---------- header: mode / stats ----------
  async function refreshStatus() {
    try {
      var s = await j('/status');
      $('modeBadge').textContent = 'Mode: ' + s.protectionMode + ' | Auto-Block: ' + (s.automaticBlocking ? 'ON' : 'OFF') + ' | Rules: ' + s.rulesLoaded;
      // Don't overwrite what the admin is in the middle of choosing.
      if (!S.protectionDirty) {
        $('modeSelect').value = s.protectionMode;
        $('autoBlockToggle').checked = !!s.automaticBlocking;
      }
    } catch (e) { console.error(e); }
  }

  async function saveProtection() {
    var mode = $('modeSelect').value;
    var automaticBlocking = $('autoBlockToggle').checked;
    if (automaticBlocking && !confirm('Enabling Automatic Blocking means CalixSentry may block traffic on its own once thresholds are met. Continue?')) return;
    try {
      await j('/protection', jsonOpts('PUT', { mode: mode, automaticBlocking: automaticBlocking }));
      S.protectionDirty = false;
      toast('Protection settings saved.');
      refreshStatus();
    } catch (e) { toast('Failed to save: ' + e.message, true); }
  }

  async function refreshStats() {
    try {
      var s = await j('/stats');
      var cards = [
        ['Security events', s.securityEventsRetained], ['Blocked requests', s.blockedRequests],
        ['Rate limited', s.rateLimitedRequests], ['Alerts', s.alerts], ['Active blocks', s.activeBlocks]
      ];
      $('statsGrid').innerHTML = cards.map(function (c) {
        return '<div class="stat"><div class="n">' + esc(c[1]) + '</div><div class="l">' + esc(c[0]) + '</div></div>';
      }).join('');
    } catch (e) { console.error(e); }
  }

  // ---------- live events ----------
  async function loadEvents() {
    try {
      var p = new URLSearchParams({ limit: '1000' });
      var q = $('fSearch').value.trim();
      if (q) p.set('q', q);
      if ($('fSeverity').value) p.set('severity', $('fSeverity').value);
      if ($('fAction').value) p.set('action', $('fAction').value);
      if ($('fCategory').value) p.set('category', $('fCategory').value);
      S.events.rows = await j('/events?' + p.toString());

      var sel = $('fCategory');
      var known = {};
      Array.prototype.forEach.call(sel.options, function (o) { known[o.value] = true; });
      S.events.rows.forEach(function (ev) {
        if (ev.category && !known[ev.category]) {
          known[ev.category] = true;
          var opt = document.createElement('option');
          opt.value = ev.category;
          opt.textContent = ev.category;
          sel.appendChild(opt);
        }
      });
      renderEvents();
    } catch (e) { console.error(e); }
  }

  function eventRow(ev) {
    var open = !!S.events.expanded[ev.id];
    var rec = ev.action !== ev.recommendedAction ? ' (rec: ' + esc(ev.recommendedAction) + ')' : '';
    var reasons = (ev.reasons || []).map(function (r) { return '<div>' + esc(r) + '</div>'; }).join('');
    return '<tr class="event-row" data-id="' + esc(ev.id) + '">' +
      '<td>' + esc(fmtTime(ev.timestamp)) + '</td>' +
      '<td><button class="linkbtn" data-action="ip-open" data-ip="' + esc(ev.sourceIp) + '">' + esc(ev.sourceIp) + '</button></td>' +
      '<td>' + esc(ev.method) + '</td>' +
      '<td class="uri"><code>' + esc((ev.uri || '').slice(0, 120)) + '</code></td>' +
      '<td>' + esc(ev.category) + '</td>' +
      '<td>' + esc(ev.threatScore) + '</td>' +
      '<td>' + sevBadge(ev.severity) + '</td>' +
      '<td>' + esc(ev.action) + rec + '</td>' +
      '<td class="actions-cell"><button class="danger" data-action="quick-block" data-ip="' + esc(ev.sourceIp) + '">Block IP</button></td>' +
      '</tr>' +
      '<tr class="row-detail" id="detail-' + esc(ev.id) + '"' + (open ? '' : ' hidden') + '><td colspan="9">' +
      '<div class="reasons">' + reasons + '</div>' +
      '<div class="reasons plain"><div>Full URI: <code>' + esc(ev.uri) + '</code></div>' +
      '<div>Rule: ' + esc(ev.ruleId || '-') + (ev.status ? ' | Backend status: ' + esc(ev.status) : '') + ' | Time: ' + esc(fmtDateTime(ev.timestamp)) + '</div>' +
      '<div>User-Agent: ' + esc(ev.userAgent || '(none)') + '</div></div>' +
      '</td></tr>';
  }

  function renderEvents() {
    var st = S.events;
    var sorted = sortRows(st.rows, st.sort);
    var pages = Math.max(1, Math.ceil(sorted.length / st.pageSize));
    if (st.page > pages) st.page = pages;
    var start = (st.page - 1) * st.pageSize;
    var slice = sorted.slice(start, start + st.pageSize);

    $('eventsBody').innerHTML = slice.length
      ? slice.map(eventRow).join('')
      : '<tr><td colspan="9" class="empty">No events match these filters.</td></tr>';
    $('eventsInfo').textContent = sorted.length
      ? 'Showing ' + (start + 1) + '-' + (start + slice.length) + ' of ' + sorted.length
      : '0 events';
    $('eventsPageLabel').textContent = 'Page ' + st.page + ' / ' + pages;
    markSorted('eventsTable', st.sort);
  }

  function toggleDetail(id) {
    var el = $('detail-' + id);
    if (!el) return;
    el.hidden = !el.hidden;
    if (el.hidden) delete S.events.expanded[id]; else S.events.expanded[id] = true;
  }

  // ---------- IPs ----------
  async function loadIps() {
    try {
      var p = new URLSearchParams({ limit: '2000' });
      var q = $('ipSearch').value.trim();
      if (q) p.set('q', q);
      S.ips.rows = await j('/ips?' + p.toString());
      renderIps();
    } catch (e) { console.error(e); }
  }

  function scoreBadge(score) {
    var sev = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : score > 0 ? 'LOW' : 'none';
    return '<span class="sev sev-' + sev + '">' + esc(score) + '</span>';
  }

  function renderIps() {
    var sorted = sortRows(S.ips.rows, S.ips.sort);
    $('ipsBody').innerHTML = sorted.length ? sorted.map(function (r) {
      return '<tr>' +
        '<td><button class="linkbtn" data-action="ip-open" data-ip="' + esc(r.ip) + '">' + esc(r.ip) + '</button></td>' +
        '<td>' + esc(fmtDateTime(r.firstSeen)) + '</td>' +
        '<td>' + esc(fmtDateTime(r.lastSeen)) + '</td>' +
        '<td>' + esc(r.totalRequests) + '</td>' +
        '<td>' + esc(r.distinctPaths) + '</td>' +
        '<td>' + esc(r.notFoundRequests) + '</td>' +
        '<td>' + esc(r.blockedRequests) + '</td>' +
        '<td>' + scoreBadge(r.maxThreatScore) + '</td>' +
        '<td class="actions-cell">' +
          '<button data-action="ip-open" data-ip="' + esc(r.ip) + '">Investigate</button>' +
          '<button class="danger" data-action="quick-block" data-ip="' + esc(r.ip) + '">Block</button>' +
        '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="empty">No IPs seen yet.</td></tr>';
    markSorted('ipsTable', S.ips.sort);
  }

  // ---------- IP investigation ----------
  async function openIp(ip) {
    S.ip = { current: ip, view: 'paths', profile: null, events: [] };
    $('ipTitle').textContent = 'IP ' + ip;
    $('ipSummary').innerHTML = '';
    $('ipStatusLine').textContent = '';
    $('ipBody').innerHTML = '<div class="empty">Loading...</div>';
    setIpTab('paths');
    $('ipModal').hidden = false;

    try { S.ip.profile = await j('/ips/' + encodeURIComponent(ip)); } catch (e) { S.ip.profile = null; }
    try { S.ip.events = await j('/events?ip=' + encodeURIComponent(ip) + '&limit=500'); } catch (e) { S.ip.events = []; }
    renderIpModal();
  }

  function setIpTab(view) {
    S.ip.view = view;
    Array.prototype.forEach.call(document.querySelectorAll('#ipTabs button'), function (b) {
      b.classList.toggle('active', b.dataset.ipview === view);
    });
  }

  function statCard(label, value, small) {
    return '<div class="stat"><div class="n' + (small ? ' sm' : '') + '">' + esc(value) + '</div><div class="l">' + esc(label) + '</div></div>';
  }

  function renderIpModal() {
    var p = S.ip.profile;
    if (p) {
      var s = p.summary;
      $('ipSummary').innerHTML =
        statCard('Requests', s.totalRequests) + statCard('Distinct paths', s.distinctPaths) +
        statCard('404 responses', s.notFoundRequests) + statCard('Blocked / limited', s.blockedRequests) +
        statCard('Max threat score', s.maxThreatScore) + statCard('First seen', fmtDateTime(s.firstSeen), true) +
        statCard('Last seen', fmtDateTime(s.lastSeen), true);
      var codes = Object.keys(p.statusCounts || {}).map(function (k) { return k + ' x' + p.statusCounts[k]; }).join(', ');
      $('ipStatusLine').textContent = 'Response codes returned to this IP: ' + (codes || 'none yet');
    } else {
      $('ipSummary').innerHTML = statCard('Detections on record', S.ip.events.length);
      $('ipStatusLine').textContent = 'No live activity is held in memory for this IP (memory is cleared on restart and after the idle period). Use "Search history" to look through the daily log files.';
    }

    var html = '';
    if (S.ip.view === 'paths') {
      var paths = p ? p.paths : [];
      html = paths.length ? '<table><thead><tr><th>Path requested</th><th>Times</th><th>Last status</th><th></th></tr></thead><tbody>' +
        paths.map(function (x) {
          return '<tr><td class="uri"><code>' + esc(x.path) + '</code></td><td>' + esc(x.count) + '</td><td>' + esc(x.lastStatus === null ? '-' : x.lastStatus) +
            '</td><td>' + (x.sensitive ? '<span class="tag-sensitive">sensitive path</span>' : '') + '</td></tr>';
        }).join('') + '</tbody></table>' : '<div class="empty">No path data in memory for this IP.</div>';
    } else if (S.ip.view === 'trail') {
      var trail = p ? p.recent : [];
      html = trail.length ? '<table><thead><tr><th>Time</th><th>Method</th><th>URI</th><th>Status</th><th>Action</th><th>Score</th></tr></thead><tbody>' +
        trail.map(function (x) {
          return '<tr><td>' + esc(fmtTime(x.timestamp)) + '</td><td>' + esc(x.method) + '</td><td class="uri"><code>' + esc(x.uri) + '</code></td><td>' +
            esc(x.status === null ? '-' : x.status) + '</td><td>' + esc(x.action) + '</td><td>' + esc(x.score) + '</td></tr>';
        }).join('') + '</tbody></table>' : '<div class="empty">No recent requests in memory for this IP.</div>';
    } else {
      var evs = S.ip.events;
      html = evs.length ? '<table><thead><tr><th>Time</th><th>Category</th><th>Severity</th><th>Score</th><th>Action</th><th>URI</th><th>Why</th></tr></thead><tbody>' +
        evs.map(function (x) {
          return '<tr><td>' + esc(fmtTime(x.timestamp)) + '</td><td>' + esc(x.category) + '</td><td>' + sevBadge(x.severity) + '</td><td>' + esc(x.threatScore) +
            '</td><td>' + esc(x.action) + '</td><td class="uri"><code>' + esc(x.uri) + '</code></td><td><div class="reasons">' +
            (x.reasons || []).map(function (r) { return '<div>' + esc(r) + '</div>'; }).join('') + '</div></td></tr>';
        }).join('') + '</tbody></table>' : '<div class="empty">No detections recorded for this IP in the live window.</div>';
    }
    $('ipBody').innerHTML = html;
  }

  // ---------- blocks ----------
  async function quickBlock(ip) {
    var reason = prompt('Reason for blocking ' + ip + ':', 'Blocked from dashboard');
    if (reason === null) return;
    try {
      await j('/blocks', jsonOpts('POST', { ip: ip, reason: reason, durationSeconds: 600, permanent: false }));
      toast(ip + ' blocked for 10 minutes.');
      loadBlocks();
    } catch (e) { toast('Block failed: ' + e.message, true); }
  }

  async function createBlock() {
    var ip = $('blockIp').value.trim();
    var reason = $('blockReason').value.trim() || 'Manual block via dashboard';
    var duration = $('blockDuration').value;
    if (!ip) { toast('Enter an IP to block.', true); return; }
    var payload = duration === 'permanent'
      ? { ip: ip, reason: reason, permanent: true }
      : { ip: ip, reason: reason, durationSeconds: Number(duration), permanent: false };
    try {
      await j('/blocks', jsonOpts('POST', payload));
      toast(ip + ' blocked.');
      $('blockIp').value = '';
      $('blockReason').value = '';
      loadBlocks();
    } catch (e) { toast('Block failed: ' + e.message, true); }
  }

  async function loadBlocks() {
    try {
      var blocks = await j('/blocks');
      $('blocksBody').innerHTML = blocks.length ? blocks.map(function (b) {
        var perm = b.type === 'TEMPORARY' ? '<button data-action="block-permanent" data-ip="' + esc(b.ip) + '">Make permanent</button>' : '';
        return '<tr><td>' + esc(b.ip) + '</td><td>' + esc((b.reason || '').slice(0, 100)) + '</td><td>' + esc(b.type) + '</td><td>' + esc(b.createdBy) +
          '</td><td>' + (b.expiresAt ? esc(fmtDateTime(b.expiresAt)) : 'Never') + '</td><td class="actions-cell">' +
          '<button data-action="block-extend" data-ip="' + esc(b.ip) + '">Extend +10m</button>' + perm +
          '<button class="danger" data-action="block-unblock" data-ip="' + esc(b.ip) + '">Unblock</button></td></tr>';
      }).join('') : '<tr><td colspan="6" class="empty">No active blocks.</td></tr>';
    } catch (e) { console.error(e); }
  }

  // ---------- rules ----------
  async function loadRules() {
    try {
      var rules = await j('/rules');
      $('rulesList').innerHTML = rules.map(function (r) {
        return '<div class="rule-row"><div class="rule-meta"><div>' + esc(r.name) + ' ' + sevBadge(r.severity) + '</div>' +
          '<div class="rule-id">' + esc(r.ruleId) + ' | ' + esc(r.category) + '</div></div>' +
          '<label class="switch"><input type="checkbox" data-rule="' + esc(r.ruleId) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></div>';
      }).join('');
    } catch (e) { console.error(e); }
  }

  async function toggleRule(ruleId, enabled) {
    try {
      await j('/detection/' + encodeURIComponent(ruleId), jsonOpts('PUT', { enabled: enabled }));
      toast(ruleId + (enabled ? ' enabled.' : ' disabled.'));
    } catch (e) { toast('Toggle failed: ' + e.message, true); loadRules(); }
  }

  // ---------- allow / deny ----------
  function accessPath() { return S.accessTab === 'allow' ? '/allowlist' : '/denylist'; }

  function switchAccessTab(tab) {
    S.accessTab = tab;
    $('tabAllow').classList.toggle('active', tab === 'allow');
    $('tabDeny').classList.toggle('active', tab === 'deny');
    loadAccessList();
  }

  async function loadAccessList() {
    try {
      var list = await j(accessPath());
      $('accessBody').innerHTML = list.length ? list.map(function (e) {
        return '<tr><td>' + esc(e.value) + '</td><td>' + esc(e.reason || '') + '</td><td>' + esc(e.createdBy || '') +
          '</td><td><button class="danger" data-action="access-remove" data-value="' + esc(e.value) + '">Remove</button></td></tr>';
      }).join('') : '<tr><td colspan="4" class="empty">Empty.</td></tr>';
    } catch (e) { console.error(e); }
  }

  async function addAccessEntry() {
    var value = $('accessValue').value.trim();
    var reason = $('accessReason').value.trim() || 'Added via dashboard';
    if (!value) { toast('Enter an IP or CIDR.', true); return; }
    try {
      await j(accessPath(), jsonOpts('POST', { value: value, reason: reason }));
      toast('Added.');
      $('accessValue').value = '';
      $('accessReason').value = '';
      loadAccessList();
    } catch (e) { toast('Failed: ' + e.message, true); }
  }

  async function removeAccessEntry(value) {
    try {
      await j(accessPath() + '?value=' + encodeURIComponent(value), { method: 'DELETE' });
      toast('Removed.');
      loadAccessList();
    } catch (e) { toast('Failed: ' + e.message, true); }
  }

  // ---------- history (daily log files) ----------
  async function loadHistoryDays() {
    var kind = $('hKind').value;
    try {
      var days = await j('/history/' + kind + '/days');
      var sel = $('hDate');
      var previous = sel.value;
      sel.innerHTML = days.length
        ? days.map(function (d) { return '<option value="' + esc(d.date) + '">' + esc(d.date) + ' (' + esc(fmtBytes(d.sizeBytes)) + ')</option>'; }).join('')
        : '<option value="">No log files yet</option>';
      if (previous && days.some(function (d) { return d.date === previous; })) sel.value = previous;
    } catch (e) { toast('Could not list log days: ' + e.message, true); }
  }

  async function searchHistory() {
    var kind = $('hKind').value, date = $('hDate').value;
    if (!date) { toast('There is no log file for this selection yet.', true); return; }
    var p = new URLSearchParams({ limit: $('hLimit').value });
    if ($('hIp').value.trim()) p.set('ip', $('hIp').value.trim());
    if ($('hQ').value.trim()) p.set('q', $('hQ').value.trim());
    try {
      S.history.kind = kind;
      S.history.rows = await j('/history/' + kind + '/' + encodeURIComponent(date) + '?' + p.toString());
      renderHistory();
      var dl = $('hDownload');
      dl.href = api + '/history/' + kind + '/' + encodeURIComponent(date) + '/download';
      dl.hidden = false;
      $('hInfo').textContent = S.history.rows.length + ' rows from ' + date + ' (newest first, most recent matches only).';
    } catch (e) { toast('Search failed: ' + e.message, true); }
  }

  function renderHistory() {
    var kind = S.history.kind;
    var cols = kind === 'events'
      ? [['timestamp', 'Time'], ['sourceIp', 'IP'], ['method', 'Method'], ['uri', 'URI'], ['category', 'Category'], ['threatScore', 'Score'], ['severity', 'Severity'], ['action', 'Action']]
      : [['timestamp', 'Time'], ['sourceIp', 'IP'], ['method', 'Method'], ['uri', 'URI'], ['status', 'Status'], ['action', 'Action'], ['threatScore', 'Score'], ['category', 'Category']];
    $('hHead').innerHTML = '<tr>' + cols.map(function (c) {
      return '<th data-table="history" data-sort="' + c[0] + '">' + c[1] + '</th>';
    }).join('') + '</tr>';

    var sorted = sortRows(S.history.rows, S.history.sort);
    $('hBody').innerHTML = sorted.length ? sorted.map(function (r) {
      return '<tr>' + cols.map(function (c) {
        var v = r[c[0]];
        if (c[0] === 'timestamp') return '<td>' + esc(fmtDateTime(v)) + '</td>';
        if (c[0] === 'sourceIp') return '<td><button class="linkbtn" data-action="history-ip" data-ip="' + esc(v) + '">' + esc(v) + '</button></td>';
        if (c[0] === 'uri') return '<td class="uri"><code>' + esc(v) + '</code></td>';
        if (c[0] === 'severity') return '<td>' + sevBadge(v) + '</td>';
        return '<td>' + esc(v) + '</td>';
      }).join('') + '</tr>';
    }).join('') : '<tr><td colspan="' + cols.length + '" class="empty">No rows.</td></tr>';
    markSorted('hTable', S.history.sort);
  }

  // ---------- navigation ----------
  function switchView(view) {
    S.view = view;
    Array.prototype.forEach.call(document.querySelectorAll('#mainTabs button'), function (b) {
      b.classList.toggle('active', b.dataset.view === view);
    });
    Array.prototype.forEach.call(document.querySelectorAll('section.view'), function (s) {
      s.hidden = s.id !== 'view-' + view;
    });
    if (view === 'events') loadEvents();
    else if (view === 'ips') loadIps();
    else if (view === 'blocks') loadBlocks();
    else if (view === 'rules') loadRules();
    else if (view === 'access') loadAccessList();
    else if (view === 'history') loadHistoryDays();
  }

  function closeModal() { $('ipModal').hidden = true; }

  function handleAction(el) {
    var ip = el.dataset.ip;
    switch (el.dataset.action) {
      case 'save-protection': saveProtection(); break;
      case 'events-apply': S.events.page = 1; loadEvents(); break;
      case 'events-clear':
        $('fSearch').value = ''; $('fSeverity').value = ''; $('fAction').value = ''; $('fCategory').value = '';
        S.events.page = 1; loadEvents(); break;
      case 'events-prev': if (S.events.page > 1) { S.events.page--; renderEvents(); } break;
      case 'events-next': S.events.page++; renderEvents(); break;
      case 'ips-apply': loadIps(); break;
      case 'ip-open': openIp(ip); break;
      case 'quick-block': quickBlock(ip); break;
      case 'block-create': createBlock(); break;
      case 'block-extend':
        j('/blocks/' + encodeURIComponent(ip) + '/extend', jsonOpts('POST', { additionalSeconds: 600 }))
          .then(function () { toast(ip + ' block extended by 10 minutes.'); loadBlocks(); })
          .catch(function (e) { toast('Failed: ' + e.message, true); });
        break;
      case 'block-permanent':
        if (confirm('Make the block on ' + ip + ' permanent?')) {
          j('/blocks/' + encodeURIComponent(ip) + '/permanent', { method: 'POST' })
            .then(function () { toast(ip + ' block made permanent.'); loadBlocks(); })
            .catch(function (e) { toast('Failed: ' + e.message, true); });
        }
        break;
      case 'block-unblock':
        j('/blocks/' + encodeURIComponent(ip), { method: 'DELETE' })
          .then(function () { toast(ip + ' unblocked.'); loadBlocks(); })
          .catch(function (e) { toast('Failed: ' + e.message, true); });
        break;
      case 'access-tab': switchAccessTab(el.dataset.tab); break;
      case 'access-add': addAccessEntry(); break;
      case 'access-remove': removeAccessEntry(el.dataset.value); break;
      case 'history-search': searchHistory(); break;
      case 'history-ip': $('hIp').value = ip; searchHistory(); break;
      case 'modal-close': closeModal(); break;
      case 'ip-block': if (S.ip.current) quickBlock(S.ip.current); break;
      case 'ip-history':
        if (S.ip.current) {
          var target = S.ip.current;
          closeModal();
          switchView('history');
          $('hKind').value = 'access';
          $('hIp').value = target;
          loadHistoryDays().then(searchHistory);
        }
        break;
      default: break;
    }
  }

  document.addEventListener('click', function (e) {
    var th = e.target.closest('th[data-sort]');
    if (th) { onSort(th); return; }

    var act = e.target.closest('[data-action]');
    if (act) { e.preventDefault(); handleAction(act); return; }

    var tab = e.target.closest('#mainTabs button[data-view]');
    if (tab) { switchView(tab.dataset.view); return; }

    var ipTab = e.target.closest('#ipTabs button[data-ipview]');
    if (ipTab) { setIpTab(ipTab.dataset.ipview); renderIpModal(); return; }

    var row = e.target.closest('tr.event-row');
    if (row) { toggleDetail(row.dataset.id); return; }

    if (e.target.id === 'ipModal') closeModal(); // click on the dark backdrop
  });

  document.addEventListener('change', function (e) {
    var t = e.target;
    if (t.matches && t.matches('input[data-rule]')) toggleRule(t.dataset.rule, t.checked);
    else if (t.id === 'modeSelect' || t.id === 'autoBlockToggle') S.protectionDirty = true;
    else if (t.id === 'eventsPageSize') { S.events.pageSize = Number(t.value); S.events.page = 1; renderEvents(); }
    else if (t.id === 'hKind') { $('hDownload').hidden = true; loadHistoryDays(); }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeModal();
    if (e.key === 'Enter') {
      if (e.target.id === 'fSearch') { S.events.page = 1; loadEvents(); }
      else if (e.target.id === 'ipSearch') loadIps();
      else if (e.target.id === 'hIp' || e.target.id === 'hQ') searchHistory();
    }
  });

  // ---------- refresh loop ----------
  function refreshActive() {
    refreshStatus();
    refreshStats();
    if (S.view === 'events') loadEvents();
    else if (S.view === 'ips') loadIps();
    else if (S.view === 'blocks') loadBlocks();
  }

  refreshStatus();
  refreshStats();
  loadEvents();
  setInterval(function () {
    if ($('autoRefresh').checked && !document.hidden) refreshActive();
  }, 5000);
})();
