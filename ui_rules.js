/* singbox-gen 规则编辑（方案 B）
   布局：规则集栏 | DNS 规则列 | Route 规则列
   行 = 步骤（按 _group / _note 前缀编号配对），拖动整行 = 两侧联动排序；单侧缺失可"补一条"
   规则集可"一键生成规则对"（DNS + Route），并高亮引用它的行 */
(function () {
  const $ = (s) => document.querySelector(s);
  let doc = { rule_sets: [], dns_rules: [], route_rules: [] };
  let open = null;      // {side, index} 行内编辑目标
  let dragKey = null;   // 拖动中的行 key
  let hl = '';          // 高亮的 rule_set tag

  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; };
  const tagOf = (rs) => (rs.group || '') + '-' + (rs.item || '');
  const arrOf = (side) => (side === 'dns_rules' ? doc.dns_rules : doc.route_rules);

  function noteOf(r) {
    if (r._note) return r._note;
    const p = [];
    if (r.rule_set) p.push('set=' + [].concat(r.rule_set).join(','));
    if (r.ip_cidr) p.push('ip=' + [].concat(r.ip_cidr).join(','));
    if (r.ip_is_private) p.push('ip_private');
    if (r.clash_mode) p.push('mode=' + r.clash_mode);
    if (r.inbound) p.push('inbound=' + r.inbound);
    if (r.protocol) p.push('proto=' + r.protocol);
    if (r.query_type) p.push('qtype=' + [].concat(r.query_type).join(','));
    if (r.action) p.push('→ ' + r.action);
    if (r.server) p.push('srv=' + r.server);
    if (r.outbound) p.push('out=' + r.outbound);
    if (r.rcode) p.push('rcode=' + r.rcode);
    return p.join(' ');
  }
  function groupOf(r, side, i) {
    if (r._group !== undefined && r._group !== null && String(r._group).trim() !== '') return String(r._group).trim();
    const m = String(r._note || '').match(/^(\d+[a-z]?)/i);
    return m ? m[1].toLowerCase() : '';
  }
  function ruleRefsTag(r, tag) { return [].concat(r.rule_set || []).indexOf(tag) >= 0; }

  /* ---------- 行模型：行 = 步骤 ---------- */
  function buildRows() {
    const dns = doc.dns_rules, rts = doc.route_rules;
    const groupOrder = [], seen = {};
    const scan = (arr, side) => arr.forEach((r, i) => { const g = groupOf(r, side, i); if (g && !seen[g]) { seen[g] = 1; groupOrder.push(g); } });
    scan(dns, 'dns'); scan(rts, 'route');
    const zoneOf = (arr, side, i) => { for (let k = i + 1; k < arr.length; k++) { const g = groupOf(arr[k], side, k); if (g) return g; } return '@end'; };
    const items = [];
    dns.forEach((r, i) => { const g = groupOf(r, 'dns', i); items.push({ key: g || ('@dns' + i), group: g, side: 'dns', index: i, zone: g || zoneOf(dns, 'dns', i) }); });
    rts.forEach((r, i) => { const g = groupOf(r, 'route', i); items.push({ key: g || ('@route' + i), group: g, side: 'route', index: i, zone: g || zoneOf(rts, 'route', i) }); });
    const zIdx = (z) => { if (z === '@end') return groupOrder.length + 1; const k = groupOrder.indexOf(z); return k < 0 ? groupOrder.length + 1 : k; };
    items.sort((a, b) => {
      const za = zIdx(a.zone), zb = zIdx(b.zone);
      if (za !== zb) return za - zb;
      const ga = a.group ? 0 : 1, gb = b.group ? 0 : 1;   // 同 zone 内：未分组（前置规则）排在本组之前
      if (ga !== gb) return gb - ga;
      if (a.side !== b.side) return a.side === 'dns' ? -1 : 1;
      return a.index - b.index;
    });
    const rows = [], byKey = {};
    for (const it of items) {
      if (it.group) {
        let row = byKey[it.group];
        if (!row) { row = { key: it.group, group: it.group, dns: [], route: [] }; byKey[it.group] = row; rows.push(row); }
        row[it.side].push(it.index);
      } else {
        const row = { key: it.key, group: '', dns: [], route: [] };
        row[it.side].push(it.index);
        rows.push(row);
      }
    }
    return rows;
  }

  function reorder(rows) {
    const d = [], r = [];
    rows.forEach((row) => { row.dns.forEach((i) => d.push(doc.dns_rules[i])); row.route.forEach((i) => r.push(doc.route_rules[i])); });
    doc.dns_rules = d; doc.route_rules = r; open = null;
  }
  function applyOrder(rows) { reorder(rows); render(); }

  /* ---------- 渲染 ---------- */
  function render() {
    const root = $('#rulesRoot');
    root.innerHTML = '';
    root.append(renderRuleSets());
    const board = el('div', 'board');
    board.append(renderBoard());
    root.append(board);
    const bar = el('div', 'rbar');
    const save = el('button', '', '保存规则');
    save.onclick = saveDoc;
    const reload = el('button', 'mini', '放弃改动并重载');
    reload.onclick = load;
    bar.append(save, reload);
    root.append(bar);
  }

  function renderRuleSets() {
    const box = el('div', 'rcard');
    box.append(el('h4', '', '规则集 rule_sets（点标签高亮引用行）'));
    const list = el('div', 'rlist');
    doc.rule_sets.forEach((rs, i) => {
      const row = el('div', 'rrow');
      const g = el('select'); ['geosite', 'geoip'].forEach((v) => { const o = el('option', '', v); o.value = v; g.append(o); });
      g.value = rs.group || 'geosite'; g.onchange = () => { rs.group = g.value; render(); };
      const item = el('input'); item.value = rs.item || ''; item.style.width = '110px';
      item.onchange = () => { rs.item = item.value.trim(); render(); };
      const sc = el('select'); ['both', 'SFL', 'SFA', 'SFI', 'mobile'].forEach((v) => { const o = el('option', '', v); o.value = v; sc.append(o); });
      sc.value = rs.scope || 'both'; sc.onchange = () => { rs.scope = sc.value; render(); };
      const tag = tagOf(rs);
      const n = countRefs(tag);
      const lbl = el('code', 'rslabel' + (hl === tag ? ' on' : ''), tag + ' ×' + n);
      lbl.title = '点击高亮引用该规则集的行';
      lbl.onclick = () => { hl = (hl === tag ? '' : tag); render(); };
      const gen = el('button', 'mini', '生成规则对');
      gen.onclick = () => genPair(rs);
      const del = el('button', 'mini', '删除');
      del.onclick = () => { if (n > 0 && !confirm('仍有 ' + n + ' 条规则引用 ' + tag + '，仍要删除？')) return; doc.rule_sets.splice(i, 1); render(); };
      row.append(el('span', 'handle', '⋮⋮'), g, item, sc, lbl, gen, del);
      list.append(row);
    });
    box.append(list);
    const add = el('button', 'mini', '+ 添加规则集');
    add.onclick = () => { doc.rule_sets.push({ group: 'geosite', item: 'new-item', scope: 'both' }); render(); };
    box.append(add);
    return box;
  }

  function countRefs(tag) {
    let n = 0;
    doc.dns_rules.concat(doc.route_rules).forEach((r) => { if (ruleRefsTag(r, tag)) n++; });
    return n;
  }

  function renderBoard() {
    const col = el('div');
    const head = el('div', 'rchead');
    head.append(el('span', '', '步骤'), el('span', '', 'DNS 规则'), el('span', '', 'Route 规则'));
    col.append(head);
    const rows = buildRows();
    rows.forEach((row) => col.append(renderRow(row, rows)));
    const addBar = el('div', 'rbar');
    const a1 = el('button', 'mini', '+ DNS 规则');
    a1.onclick = () => addRule('dns_rules', '');
    const a2 = el('button', 'mini', '+ Route 规则');
    a2.onclick = () => addRule('route_rules', '');
    addBar.append(a1, a2);
    col.append(addBar);
    return col;
  }

  function renderRow(row, rows) {
    const r = el('div', 'rrow2');
    if (hl && rowHasTag(row, hl)) r.classList.add('hl');
    r.draggable = true;
    r.ondragstart = (e) => { dragKey = row.key; e.dataTransfer.effectAllowed = 'move'; };
    r.ondragover = (e) => e.preventDefault();
    r.ondrop = (e) => {
      e.preventDefault();
      if (!dragKey || dragKey === row.key) return;
      const cur = buildRows();
      const from = cur.findIndex((x) => x.key === dragKey), to = cur.findIndex((x) => x.key === row.key);
      if (from < 0 || to < 0) return;
      const [x] = cur.splice(from, 1); cur.splice(to, 0, x);
      dragKey = null; applyOrder(cur);
    };
    r.append(el('span', 'handle', '⋮⋮'), el('span', 'rgrp', row.group || '—'));
    r.append(renderCell(row, 'dns'), renderCell(row, 'route'));
    if (open && ((open.side === 'dns_rules' && row.dns.indexOf(open.index) >= 0) || (open.side === 'route_rules' && row.route.indexOf(open.index) >= 0))) {
      const side = open.side === 'dns_rules' ? 'dns' : 'route';
      r.append(renderEditor(open.side, open.index));
    }
    return r;
  }

  function rowHasTag(row, tag) {
    const hit = (arr, idxs) => idxs.some((i) => arr[i] && ruleRefsTag(arr[i], tag));
    return hit(doc.dns_rules, row.dns) || hit(doc.route_rules, row.route);
  }

  function renderCell(row, side) {
    const cell = el('div', 'rcell');
    const list = side === 'dns' ? row.dns : row.route;
    const arr = side === 'dns' ? doc.dns_rules : doc.route_rules;
    list.forEach((idx, k) => {
      const rule = arr[idx];
      const chip = el('span', 'chip' + (hl && ruleRefsTag(rule, hl) ? ' hl' : ''));
      const label = el('b', '', noteOf(rule) || '(空)');
      label.onclick = () => { open = { side: side === 'dns' ? 'dns_rules' : 'route_rules', index: idx }; render(); };
      chip.append(label);
      const up = el('span', 'x', '↑'); up.onclick = (e) => { e.stopPropagation(); swapInGroup(arr, idx, -1, side); };
      const dn = el('span', 'x', '↓'); dn.onclick = (e) => { e.stopPropagation(); swapInGroup(arr, idx, +1, side); };
      const del = el('span', 'x', '×'); del.onclick = (e) => { e.stopPropagation(); if (confirm('删除该规则？')) { arr.splice(idx, 1); open = null; render(); } };
      const cp = el('span', 'x', '⧉'); cp.onclick = (e) => { e.stopPropagation(); arr.splice(idx + 1, 0, JSON.parse(JSON.stringify(rule))); render(); };
      chip.append(up, dn, cp, del);
      cell.append(chip);
    });
    if (!list.length) {
      cell.append(el('span', 'rempty', '—'));
      if (side === 'route' && row.dns.length) cell.append(el('span', 'chip warn', '对应缺失'));
    }
    const add = el('button', 'mini', '+');
    add.title = '在本步骤补一条' + (side === 'dns' ? 'DNS' : 'Route') + '规则';
    add.onclick = () => addRule(side === 'dns' ? 'dns_rules' : 'route_rules', row.group);
    cell.append(add);
    return cell;
  }

  function swapInGroup(arr, idx, dir, side) {
    const g = groupOf(arr[idx], side, idx);
    for (let k = idx + dir; k >= 0 && k < arr.length; k += dir) {
      if (groupOf(arr[k], side, k) === g) { const t = arr[idx]; arr[idx] = arr[k]; arr[k] = t; open = null; render(); return; }
    }
  }

  /* ---------- 行内表单 ---------- */
  function renderEditor(side, index) {
    const cur = arrOf(side)[index];
    const box = el('div', 'editor');
    box.append(el('h4', '', '编辑：' + (side === 'dns_rules' ? 'DNS' : 'Route') + ' 规则 #' + (index + 1)));
    const f = el('div', 'rgrid');
    const mk = (label, node) => { const w = el('label', 'rf'); w.append(el('span', '', label), node); return w; };
    const note = el('input'); note.value = cur._note || '';
    const grp = el('input'); grp.value = cur._group || groupOf(cur, side === 'dns_rules' ? 'dns' : 'route', index); grp.placeholder = '步骤编号（如 6 / 8b，留空则按注释前缀推导）';
    const scope = el('select'); ['', 'both', 'SFL', 'SFA', 'SFI', 'mobile'].forEach((v) => { const o = el('option', '', v || '（默认 both）'); o.value = v; scope.append(o); }); scope.value = cur._scope || '';
    const iff = el('input'); iff.value = cur._if || ''; iff.placeholder = 'pinned/cn_extra/clash/telegram/gh（可留空）';
    const fEach = el('input'); fEach.value = cur._for_each || ''; fEach.placeholder = '_for_each（如 pinned_sets）';
    const action = el('select');
    ['', 'route', 'reject', 'predefined', 'respond', 'evaluate', 'resolve', 'sniff', 'hijack-dns', 'logical'].forEach((v) => { const o = el('option', '', v || '（无）'); o.value = v; action.append(o); });
    action.value = cur.action || '';
    const sets = el('input'); sets.value = [].concat(cur.rule_set || []).join(', '); sets.placeholder = '规则集 tag，逗号分隔';
    const cidr = el('input'); cidr.value = [].concat(cur.ip_cidr || []).join(', '); cidr.placeholder = 'ip_cidr，逗号分隔';
    const inbound = el('input'); inbound.value = cur.inbound || ''; inbound.placeholder = 'inbound（如 fake-in）';
    const proto = el('input'); proto.value = cur.protocol || ''; proto.placeholder = 'protocol（如 dns / stun）';
    const cmode = el('input'); cmode.value = cur.clash_mode || ''; cmode.placeholder = 'clash_mode（Direct / Global）';
    const server = el('input'); server.value = cur.server || ''; server.placeholder = 'server（{{proxy_dns}} / local-dns / remote-dns / fakeip-dns）';
    const outbound = el('input'); outbound.value = cur.outbound || ''; outbound.placeholder = 'outbound（proxy / direct / select / gh / 节点 tag）';
    const rcode = el('input'); rcode.value = cur.rcode || ''; rcode.placeholder = 'rcode（NXDOMAIN / NOERROR / REFUSED）';
    const method = el('input'); method.value = cur.method || ''; method.placeholder = 'method（drop）';
    const csub = el('input'); csub.value = cur.client_subnet || ''; csub.placeholder = 'client_subnet（{{ecs}}）';
    const adv = el('textarea', 'rjson'); adv.value = JSON.stringify(cur, null, 2);
    let advDirty = false;
    const refreshAdv = () => { if (!advDirty) adv.value = JSON.stringify(build(), null, 2); };

    function build() {
      const r = JSON.parse(JSON.stringify(cur));   // 保留表单未覆盖的高级字段
      const setv = (k, v) => { if (v === '' || v === null || (Array.isArray(v) && !v.length)) delete r[k]; else r[k] = v; };
      setv('_note', note.value.trim());
      setv('_group', grp.value.trim());
      setv('_scope', scope.value);
      setv('_if', iff.value.trim());
      setv('_for_each', fEach.value.trim());
      setv('action', action.value);
      setv('rule_set', sets.value.split(',').map((x) => x.trim()).filter(Boolean));
      setv('ip_cidr', cidr.value.split(',').map((x) => x.trim()).filter(Boolean));
      setv('inbound', inbound.value.trim());
      setv('protocol', proto.value.trim());
      setv('clash_mode', cmode.value.trim());
      setv('server', server.value.trim());
      setv('outbound', outbound.value.trim());
      setv('rcode', rcode.value.trim());
      setv('method', method.value.trim());
      setv('client_subnet', csub.value.trim());
      return r;
    }
    [note, grp, sets, cidr, inbound, proto, cmode, server, outbound, rcode, method, csub, iff, fEach].forEach((n) => { n.oninput = refreshAdv; });
    [scope, action].forEach((n) => { n.onchange = refreshAdv; });
    adv.oninput = () => { advDirty = true; };
    [['注释', note], ['步骤', grp], ['作用端', scope], ['开关 _if', iff], ['循环 _for_each', fEach],
     ['动作', action], ['规则集', sets], ['ip_cidr', cidr], ['inbound', inbound], ['protocol', proto],
     ['clash_mode', cmode], ['server', server], ['outbound', outbound], ['rcode', rcode], ['method', method], ['client_subnet', csub]]
      .forEach(([l, n]) => f.append(mk(l, n)));
    const ok = el('button', '', '应用');
    ok.onclick = () => {
      try {
        const v = advDirty ? JSON.parse(adv.value) : build();
        if (typeof v !== 'object' || Array.isArray(v)) throw new Error('必须是对象');
        arrOf(side)[index] = v; open = null; render(); window.sgenLog('规则已更新（记得保存）', 'ok');
      } catch (e) { alert('规则无效: ' + e.message); }
    };
    const cancel = el('button', 'mini', '取消');
    cancel.onclick = () => { open = null; render(); };
    box.append(f, adv, ok, cancel);
    return box;
  }

  function addRule(side, group) {
    const r = { action: 'route' };
    if (group) r._group = group;
    else {
      const g = prompt('步骤编号（可留空，如 6 / 8b）', '');
      if (g && g.trim()) r._group = g.trim();
    }
    if (side === 'dns_rules') r.server = '{{proxy_dns}}';
    else r.outbound = 'direct';
    const arr = arrOf(side);
    arr.push(r);
    open = { side, index: arr.length - 1 };
    render();
  }

  function genPair(rs) {
    const tag = tagOf(rs);
    const g = prompt('步骤编号（可留空）', '');
    const base = {};
    if (g && g.trim()) base._group = g.trim();
    base._note = (g && g.trim() ? g.trim() + ' ' : '') + (rs.item || tag) + ' → 代理';
    const d = Object.assign({}, base, { rule_set: [tag], action: 'route', server: '{{proxy_dns}}' });
    const r = Object.assign({}, base, { rule_set: [tag], action: 'route', outbound: 'select' });
    doc.dns_rules.push(d); doc.route_rules.push(r);
    render();
    window.sgenLog('已生成规则对：' + tag + '（DNS + Route，记得保存）', 'ok');
  }

  /* ---------- 存取 ---------- */
  async function load() {
    try {
      const r = await fetch('/api/rules', { cache: 'no-store' });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        window.sgenLog('规则加载失败: ' + (j.error || r.status), 'err');
        return;
      }
      doc = await r.json();
      doc.rule_sets = doc.rule_sets || []; doc.dns_rules = doc.dns_rules || []; doc.route_rules = doc.route_rules || [];
      open = null; render();
    } catch (e) { window.sgenLog('规则加载异常: ' + e.message, 'err'); }
  }

  async function saveDoc() {
    try {
      const r = await fetch('/api/rules', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(doc),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { window.sgenStatus('规则保存失败', 'err'); window.sgenLog('规则保存失败: ' + (j.error || r.status), 'err'); return; }
      window.sgenStatus('规则已保存', 'ok'); window.sgenLog('规则已写入 homelab.yaml', 'ok');
      if (window.sgenReloadYaml) window.sgenReloadYaml();
    } catch (e) { window.sgenLog('规则保存异常: ' + e.message, 'err'); }
  }

  if (typeof window !== 'undefined') {
    window.rulesInit = function () { load(); };
  }

  // Node 测试出口（浏览器下 module 未定义，不影响运行）
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      setDoc: (d) => { doc = d; },
      getDoc: () => doc,
      buildRows: () => buildRows(),
      reorder: (rows) => reorder(rows),
    };
  }
})();
