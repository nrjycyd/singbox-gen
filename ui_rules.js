/* singbox-gen 规则编辑（可视化）：规则集增删改 + DNS/Route 规则拖动排序、向导式添加 */
(function () {
  const $ = (s) => document.querySelector(s);
  let doc = { rule_sets: [], dns_rules: [], route_rules: [] };
  let tab = 'dns_rules';
  let drag = null;

  const ACTIONS = [
    { v: 'route-server', label: 'route → 指定 DNS 服务器（DNS 规则）' },
    { v: 'route-outbound', label: 'route → 指定出口（Route 规则）' },
    { v: 'reject', label: 'reject（拦截）' },
    { v: 'predefined', label: 'predefined（返回固定 rcode）' },
    { v: 'respond', label: 'respond（返回已评估响应）' },
    { v: 'evaluate', label: 'evaluate（发起解析用于响应匹配）' },
    { v: 'resolve', label: 'resolve（解析目的域名）' },
    { v: 'sniff', label: 'sniff（协议/域名嗅探）' },
    { v: 'hijack-dns', label: 'hijack-dns（劫持 DNS）' },
    { v: 'logical', label: 'logical（OR/AND 组合规则）' },
  ];

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function noteOf(r) { return r._note || summarize(r); }
  function summarize(r) {
    const parts = [];
    if (r.rule_set) parts.push('set=' + [].concat(r.rule_set).join(','));
    if (r.ip_cidr) parts.push('ip=' + [].concat(r.ip_cidr).join(','));
    if (r.ip_is_private) parts.push('ip_private');
    if (r.clash_mode) parts.push('mode=' + r.clash_mode);
    if (r.inbound) parts.push('inbound=' + r.inbound);
    if (r.protocol) parts.push('proto=' + r.protocol);
    if (r.query_type) parts.push('qtype=' + [].concat(r.query_type).join(','));
    if (r.action) parts.push('→ ' + r.action);
    if (r.server) parts.push('srv=' + r.server);
    if (r.outbound) parts.push('out=' + r.outbound);
    if (r.rcode) parts.push('rcode=' + r.rcode);
    if (r._if) parts.push('if=' + r._if);
    if (r._scope) parts.push('scope=' + r._scope);
    return parts.join(' ');
  }

  async function load() {
    try {
      const r = await fetch('/api/rules', { headers: { 'X-Token': window.sgenTok ? window.sgenTok() : '' } });
      if (!r.ok) { sgenLog('规则加载失败: ' + r.status, 'err'); return; }
      doc = await r.json();
      doc.rule_sets = doc.rule_sets || []; doc.dns_rules = doc.dns_rules || []; doc.route_rules = doc.route_rules || [];
      render();
    } catch (e) { sgenLog('规则加载异常: ' + e.message, 'err'); }
  }

  async function save() {
    try {
      const r = await fetch('/api/rules', {
        method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Token': window.sgenTok ? window.sgenTok() : '' },
        body: JSON.stringify(doc),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { sgenLog('规则保存失败: ' + (j.error || r.status), 'err'); sgenStatus('规则保存失败', 'err'); return; }
      sgenLog('规则已保存到 homelab.yaml', 'ok'); sgenStatus('规则已保存', 'ok');
      if (window.sgenReloadYaml) window.sgenReloadYaml();
    } catch (e) { sgenLog('规则保存异常: ' + e.message, 'err'); }
  }

  function render() {
    $('#rulesRoot').innerHTML = '';
    $('#rulesRoot').append(renderRuleSets());
    $('#rulesRoot').append(renderTabBar());
    $('#rulesRoot').append(renderRules());
    $('#rulesRoot').append(renderAddForm());
    const bar = el('div', 'rbar');
    const b = el('button', '', '保存规则');
    b.onclick = save;
    bar.append(b);
    $('#rulesRoot').append(bar);
  }

  function renderRuleSets() {
    const box = el('div', 'rcard');
    box.append(el('h4', '', '规则集 rule_sets（可被规则引用）'));
    const list = el('div', 'rlist');
    doc.rule_sets.forEach((rs, i) => {
      const row = el('div', 'rrow');
      row.draggable = true;
      row.ondragstart = () => { drag = { kind: 'rs', from: i }; };
      row.ondragover = (e) => e.preventDefault();
      row.ondrop = () => { if (drag && drag.kind === 'rs') { move(doc.rule_sets, drag.from, i); render(); } };
      const g = el('select'); ['geosite', 'geoip'].forEach((v) => { const o = el('option', '', v); o.value = v; g.append(o); });
      g.value = rs.group; g.onchange = () => { rs.group = g.value; render(); };
      const item = el('input'); item.value = rs.item; item.style.width = '200px';
      item.onchange = () => { rs.item = item.value.trim(); render(); };
      const sc = el('select'); ['both', 'gateway', 'phone'].forEach((v) => { const o = el('option', '', v); o.value = v; sc.append(o); });
      sc.value = rs.scope || 'both'; sc.onchange = () => { rs.scope = sc.value; render(); };
      const tag = el('code', '', 'tag=' + (rs.group || '') + '-' + (rs.item || ''));
      const del = el('button', 'mini', '删除');
      del.onclick = () => { doc.rule_sets.splice(i, 1); render(); };
      row.append(el('span', 'handle', '⋮⋮'), g, item, sc, tag, del);
      list.append(row);
    });
    box.append(list);
    const add = el('button', 'mini', '+ 添加规则集');
    add.onclick = () => { doc.rule_sets.push({ group: 'geosite', item: 'new-item', scope: 'both' }); render(); };
    box.append(add);
    return box;
  }

  function renderTabBar() {
    const bar = el('div', 'rtabs');
    [['dns_rules', 'DNS 规则'], ['route_rules', 'Route 规则']].forEach(([k, label]) => {
      const b = el('button', 'mini' + (tab === k ? ' on' : ''), label + '（' + doc[k].length + '）');
      b.onclick = () => { tab = k; render(); };
      bar.append(b);
    });
    return bar;
  }

  function renderRules() {
    const box = el('div', 'rcard');
    box.append(el('h4', '', (tab === 'dns_rules' ? 'DNS 规则' : 'Route 规则') + '（顺序即优先级，拖动/↑↓ 调整）'));
    const list = el('div', 'rlist');
    doc[tab].forEach((r, i) => {
      const row = el('div', 'rrow' + (r._enabled === false ? ' off' : ''));
      row.draggable = true;
      row.ondragstart = () => { drag = { kind: 'rule', from: i }; };
      row.ondragover = (e) => e.preventDefault();
      row.ondrop = () => { if (drag && drag.kind === 'rule') { move(doc[tab], drag.from, i); render(); } };
      const h = el('span', 'handle', '⋮⋮');
      const txt = el('span', 'rsum', noteOf(r));
      const up = el('button', 'mini', '↑');
      up.onclick = () => { move(doc[tab], i, i - 1); render(); };
      const dn = el('button', 'mini', '↓');
      dn.onclick = () => { move(doc[tab], i, i + 1); render(); };
      const ed = el('button', 'mini', '编辑');
      ed.onclick = () => editRule(i);
      const cp = el('button', 'mini', '复制');
      cp.onclick = () => { doc[tab].splice(i + 1, 0, JSON.parse(JSON.stringify(r))); render(); };
      const del = el('button', 'mini', '删除');
      del.onclick = () => { if (confirm('删除该规则？')) { doc[tab].splice(i, 1); render(); } };
      row.append(h, el('span', 'ridx', String(i + 1)), txt, up, dn, ed, cp, del);
      list.append(row);
    });
    box.append(list);
    return box;
  }

  function move(arr, from, to) {
    if (to < 0 || to >= arr.length || from === to) return;
    const [x] = arr.splice(from, 1);
    arr.splice(to, 0, x);
  }

  function editRule(i) {
    const r = doc[tab][i];
    const box = $('#rulesRoot');
    box.innerHTML = '';
    const card = el('div', 'rcard');
    card.append(el('h4', '', '编辑规则 #' + (i + 1) + '（JSON；键名见 templates/homelab.example.yaml 注释）'));
    const ta = el('textarea', 'rjson');
    ta.value = JSON.stringify(r, null, 2);
    const ok = el('button', '', '应用');
    const cancel = el('button', 'mini', '取消');
    cancel.onclick = render;
    const apply = () => {
      try {
        const v = JSON.parse(ta.value);
        if (typeof v !== 'object' || Array.isArray(v)) throw new Error('规则必须是对象');
        doc[tab][i] = v; render(); sgenLog('规则已更新（记得保存）', 'ok');
      } catch (e) { alert('JSON 无效: ' + e.message); }
    };
    ok.onclick = apply;
    card.append(ta, ok, cancel);
    box.append(card);
  }

  function renderAddForm() {
    const card = el('div', 'rcard');
    card.append(el('h4', '', '添加规则（向导）'));
    const mk = (label, node) => { const w = el('label', 'rf'); w.append(el('span', '', label), node); return w; };
    const sec = el('select'); [['dns_rules', 'DNS 规则'], ['route_rules', 'Route 规则']].forEach(([v, l]) => { const o = el('option', '', l); o.value = v; sec.append(o); });
    sec.value = tab;
    const act = el('select'); ACTIONS.forEach((a) => { const o = el('option', '', a.label); o.value = a.v; act.append(o); });
    const sets = el('input'); sets.placeholder = '规则集 tag，逗号分隔（如 geosite-telegram, geoip-telegram）';
    const cidr = el('input'); cidr.placeholder = 'ip_cidr，逗号分隔（可留空）';
    const extra = el('input'); extra.placeholder = '附加匹配键值，如 clash_mode=Global 或 inbound=fake-in（可留空）';
    const server = el('input'); server.placeholder = 'server（如 {{proxy_dns}} / local-dns / remote-dns / fakeip-dns）';
    const outbound = el('input'); outbound.placeholder = 'outbound（如 proxy / direct / select / gh / 节点 tag）';
    const rcode = el('select'); ['', 'NOERROR', 'NXDOMAIN', 'REFUSED', 'SERVFAIL'].forEach((v) => { const o = el('option', '', v || '（无）'); o.value = v; rcode.append(o); });
    const method = el('select'); ['', 'drop'].forEach((v) => { const o = el('option', '', v || '（默认）'); o.value = v; method.append(o); });
    const note = el('input'); note.placeholder = '注释 _note（可留空）';
    const scope = el('select'); ['', 'both', 'gateway', 'phone'].forEach((v) => { const o = el('option', '', v || '（默认 both）'); o.value = v; scope.append(o); });
    const iff = el('input'); iff.placeholder = '_if 策略开关（可留空：pinned/cn_extra/clash/telegram/gh）';


    function refresh() {
      const a = act.value;
      const isDns = sec.value === 'dns_rules';
      server.parentElement.style.display = (a === 'route-server' || a === 'evaluate') ? '' : 'none';
      outbound.parentElement.style.display = (a === 'route-outbound') ? '' : 'none';
      rcode.parentElement.style.display = (a === 'predefined') ? '' : 'none';
      method.parentElement.style.display = (a === 'reject') ? '' : 'none';
      sets.parentElement.style.display = (a === 'sniff' || a === 'hijack-dns' || a === 'resolve') ? 'none' : '';
      if (a === 'route-server' && sec.value === 'route_rules') sec.value = 'dns_rules';
      if (a === 'route-outbound' && sec.value === 'dns_rules') sec.value = 'route_rules';
    }
    act.onchange = refresh; sec.onchange = refresh;
    const add = el('button', '', '添加到列表末尾');
    add.onclick = () => {
      const r = {};
      const a = act.value;
      const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
      if (a === 'route-server') { r.action = 'route'; r.server = server.value.trim() || '{{local_dns}}'; }
      else if (a === 'route-outbound') { r.action = 'route'; r.outbound = outbound.value.trim() || 'direct'; }
      else if (a === 'reject') { r.action = 'reject'; if (method.value) r.method = method.value; }
      else if (a === 'predefined') { r.action = 'predefined'; r.rcode = rcode.value || 'NXDOMAIN'; }
      else if (a === 'logical') { r.type = 'logical'; r.mode = 'or'; r.rules = []; r.action = 'reject'; }
      else { r.action = a; }
      const s = list(sets.value); if (s.length) r.rule_set = s;
      const c = list(cidr.value); if (c.length) r.ip_cidr = c;
      const ex = extra.value.trim();
      if (ex) ex.split(',').forEach((kv) => {
        const p = kv.split('='); if (p.length === 2) { const k = p[0].trim(); let v = p[1].trim(); if (v === 'true') v = true; else if (v === 'false') v = false; else if (/^\d+$/.test(v)) v = parseInt(v, 10); r[k] = v; }
      });
      if (note.value.trim()) r._note = note.value.trim();
      if (scope.value) r._scope = scope.value;
      if (iff.value.trim()) r._if = iff.value.trim();
      doc[sec.value].push(r);
      tab = sec.value;
      render();
      sgenLog('已添加规则（记得点"保存规则"）', 'ok');
    };
    const wrap = el('div', 'rgrid');
    [mk('目标', sec), mk('动作', act), mk('规则集', sets), mk('ip_cidr', cidr), mk('附加匹配', extra), mk('server', server), mk('outbound', outbound), mk('rcode', rcode), mk('method', method), mk('注释', note), mk('作用端', scope), mk('开关 _if', iff)].forEach((w) => wrap.append(w));
    card.append(wrap, add);
    refresh();
    return card;
  }

  window.rulesInit = function () { load(); };
  window.rulesTab = function (v) { tab = v; };
})();
