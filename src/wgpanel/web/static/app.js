'use strict';

const $ = (sel) => document.querySelector(sel);
let state = null;
let busy = false;
let redirecting = false;
let refreshTimer = null;

/* The session expired (or was never there): stop polling and go log in once. */
function toLogin() {
  if (redirecting) return;
  redirecting = true;
  clearInterval(refreshTimer);
  location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search);
}

/* ------------------------------------------------------------------ utils */
async function api(path, options) {
  const res = await fetch(path, options);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { data = { error: text }; }
  if (res.status === 401) {
    toLogin();
    const err = new Error('未登录');
    err.payload = data;
    throw err;
  }
  if (!res.ok) {
    const err = new Error((data && data.error) || res.statusText);
    err.payload = data;
    throw err;
  }
  return data;
}

function bytes(n) {
  if (!n) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(n < 10 && i > 0 ? 1 : 0) + ' ' + units[i];
}

function rate(n) { return bytes(n) + '/s'; }

function age(ts) {
  if (!ts) return '从未';
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 60) return s + ' 秒前';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}

function toast(message, isError) {
  const el = $('#toast');
  el.textContent = message;
  el.className = 'toast' + (isError ? ' error' : '');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add('hidden'), isError ? 6000 : 2600);
}

function escapeHtml(text) {
  return String(text == null ? '' : text).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ----------------------------------------------------------------- render */
function render() {
  if (!state) return;
  const rt = state.runtime;

  $('#iface').textContent = `${state.interface} · ${rt.listen_port || '—'} · ${(rt.addresses || []).join(', ') || '无地址'}`;
  $('#iface').title = '接口名 · 监听端口 · 隧道地址';
  const dot = $('#status-dot');
  dot.className = 'dot ' + (rt.exists && rt.up ? 'up' : 'down');
  dot.title = rt.exists ? (rt.up ? '隧道接口已启用' : '接口存在但未启用') : '接口不存在（wireguard 容器可能在重启）';

  /* data-label mirrors the <th> text: below 760px CSS turns each row into a card
     and prints the label, because the header row is no longer visible. */
  const rows = state.peers.map((peer) => `
    <tr>
      <td data-label="名称">${escapeHtml(peer.name)}${peer.has_preshared_key ? '' : ' <span class="badge">无 PSK</span>'}</td>
      <td class="mono" data-label="隧道地址">${escapeHtml(peer.client_ip || '—')}</td>
      <td data-label="状态"><span class="status"><span class="badge ${peer.online ? 'online' : 'offline'}"
                title="${peer.online ? '最近 3 分钟内有握手' : '最近 3 分钟没有握手'}">${peer.online ? '在线' : '离线'}</span>
          <span class="mono" title="最后一次握手距今多久">${age(peer.latest_handshake)}</span></span></td>
      <td class="mono" data-label="对端地址">${escapeHtml(peer.endpoint || '—')}</td>
      <td class="num" data-label="下行">${rate(peer.tx_rate)}</td>
      <td class="num" data-label="上行">${rate(peer.rx_rate)}</td>
      <td class="num mono" data-label="累计流量">↓${bytes(peer.tx)} ↑${bytes(peer.rx)}</td>
      <td class="actions-cell">
        <button class="tiny" data-edit="${escapeHtml(peer.name)}">编辑</button>
        <button class="tiny" data-qr="${escapeHtml(peer.name)}" ${peer.has_keys ? '' : 'disabled title="没有存私钥，无法导出配置"'}>二维码</button>
        <button class="tiny danger" data-del="${escapeHtml(peer.name)}">删除</button>
      </td>
    </tr>`).join('');

  $('#peers-body').innerHTML = rows;
  $('#peers-empty').classList.toggle('hidden', state.peers.length > 0);

  $('#runtime').innerHTML = `
    <dt>接口名</dt><dd>${escapeHtml(rt.name)} ${rt.exists ? '' : '（不存在）'}</dd>
    <dt>监听端口<small>ListenPort</small></dt><dd>${rt.listen_port || '—'}</dd>
    <dt>隧道地址<small>Address</small></dt><dd>${(rt.addresses || []).join(', ') || '—'}</dd>
    <dt>MTU<small>隧道内单个包的上限</small></dt><dd>${rt.mtu == null ? '—' : rt.mtu}</dd>
    <dt>服务器公钥<small>客户端配置里的 PublicKey</small></dt><dd>${escapeHtml(rt.public_key || '—')}</dd>
    <dt>配置文件</dt><dd>${escapeHtml(state.conf_path)}</dd>`;

  renderBanner();
  renderTrafficTiles();
  renderTrafficScope();
  renderTrafficLegend();
}

function renderBanner() {
  const banner = $('#banner');
  const applyBtn = $('#btn-apply');
  const messages = [];
  let level = 'warn';

  if (state.error) { messages.push(escapeHtml(state.error)); level = 'error'; }
  if (!state.settings_ready) {
    messages.push('还没有填<b>服务器地址</b>，二维码和客户端配置无法生成。');
  }
  if (state.pending) {
    const p = state.pending;
    const bits = [];
    if (p.peer_changes.added.length) bits.push(`新增 ${p.peer_changes.added.length}`);
    if (p.peer_changes.removed.length) bits.push(`删除 ${p.peer_changes.removed.length}`);
    if (p.peer_changes.changed.length) bits.push(`修改 ${p.peer_changes.changed.length}`);
    messages.push(`有未生效的改动（${p.mode}${bits.length ? '：' + bits.join('，') : ''}），共 ${p.steps} 步。`);
    if (p.disruptive) messages.push('这个改动会短暂重挂接口。');
    if (p.destructive) messages.push('这个改动会删除正在使用的 peer 或修改监听端口。');
    applyBtn.classList.remove('hidden');
  } else {
    applyBtn.classList.add('hidden');
  }

  if (!messages.length) { banner.classList.add('hidden'); return; }
  banner.className = 'banner ' + level;
  banner.innerHTML = `<div class="row"><div>${messages.map((m) => `<div>${m}</div>`).join('')}</div>
    ${!state.settings_ready ? '<button class="ghost tiny" id="banner-settings">去设置</button>' : ''}</div>`;
  const go = $('#banner-settings');
  if (go) go.onclick = openSettings;
}

/* ---------------------------------------------------------------- traffic */
/* Rate waveform for the whole tunnel or a single peer. The backend samples the
   kernel counters and serves exactly 60 buckets per range; a null bucket means
   "not sampled" (panel was down) and has to break the line, while 0 means
   "sampled, idle". Down = server → client (wg tx), up = client → server (rx). */
const TRAFFIC_RANGES = [60, 3600, 43200, 86400, 604800, 1296000];
const TRAFFIC_KEY = 'wgpanel.traffic';
const traffic = { scope: 'all', window: 3600, points: [], error: null, geometry: null };
let trafficTimer = null;
let trafficScopeSignature = '';
let trafficResize = null;

function loadTrafficChoice() {
  try {
    const saved = JSON.parse(localStorage.getItem(TRAFFIC_KEY) || 'null');
    if (saved && TRAFFIC_RANGES.indexOf(saved.window) >= 0) traffic.window = saved.window;
    if (saved && typeof saved.scope === 'string') traffic.scope = saved.scope;
  } catch (_) { /* a corrupt preference is not worth failing over */ }
}

function saveTrafficChoice() {
  try {
    localStorage.setItem(TRAFFIC_KEY, JSON.stringify({ window: traffic.window, scope: traffic.scope }));
  } catch (_) { /* private mode */ }
}

function markTrafficRange() {
  document.querySelectorAll('#traffic-range [data-window]').forEach((button) => {
    button.setAttribute('aria-pressed', String(Number(button.dataset.window) === traffic.window));
  });
}

function renderTrafficTiles() {
  const t = (state && state.traffic) || { down: 0, up: 0, down_rate: 0, up_rate: 0 };
  $('#traffic-tiles').innerHTML = `
    <div class="tile"><span class="tile-label">总下行流量</span>
      <b class="tile-value">${bytes(t.down)}</b><small>服务器 → 客户端，面板累计</small></div>
    <div class="tile"><span class="tile-label">总上行流量</span>
      <b class="tile-value">${bytes(t.up)}</b><small>客户端 → 服务器，面板累计</small></div>
    <div class="tile"><span class="tile-label">当前下行速率</span>
      <b class="tile-value">${rate(t.down_rate)}</b><small>全部客户端合计</small></div>
    <div class="tile"><span class="tile-label">当前上行速率</span>
      <b class="tile-value">${rate(t.up_rate)}</b><small>全部客户端合计</small></div>`;
}

/* Rebuilding the <select> on every 2s refresh would close an open dropdown, so
   only touch it when the peer list actually changed. */
function renderTrafficScope() {
  const peers = (state && state.peers) || [];
  const signature = peers.map((peer) => peer.public_key + ':' + peer.name).join('|');
  const select = $('#traffic-scope');
  if (signature !== trafficScopeSignature) {
    trafficScopeSignature = signature;
    select.innerHTML = ['<option value="all">全部客户端（合计）</option>']
      .concat(peers.map((peer) =>
        `<option value="${escapeHtml(peer.public_key)}">${escapeHtml(peer.name)}</option>`))
      .join('');
  }
  if (traffic.scope !== 'all' && !peers.some((peer) => peer.public_key === traffic.scope)) {
    traffic.scope = 'all';
  }
  select.value = traffic.scope;
}

function timeLabel(ts) {
  const date = new Date(ts * 1000);
  const two = (n) => String(n).padStart(2, '0');
  if (traffic.window <= 60) {
    return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}`;
  }
  if (traffic.window <= 86400) return `${two(date.getHours())}:${two(date.getMinutes())}`;
  return `${two(date.getMonth() + 1)}-${two(date.getDate())}`;
}

function lastFilledPoint() {
  for (let i = traffic.points.length - 1; i >= 0; i--) {
    if (traffic.points[i][1] !== null || traffic.points[i][2] !== null) return traffic.points[i];
  }
  return null;
}

function renderTrafficLegend() {
  const bits = [];
  const last = lastFilledPoint();
  bits.push(`<span class="chart-swatch down"></span>下行 ${last && last[1] !== null ? rate(last[1]) : '—'}`);
  bits.push(`<span class="chart-swatch up"></span>上行 ${last && last[2] !== null ? rate(last[2]) : '—'}`);
  const since = state && state.traffic && state.traffic.since;
  if (since) {
    bits.push(`自 ${escapeHtml(new Date(since * 1000).toLocaleString('zh-CN', { hour12: false }))} 起累计`);
  }
  const error = (state && state.traffic && state.traffic.error) || traffic.error;
  if (error) bits.push(`<span class="warn-text">${escapeHtml(error)}</span>`);
  $('#traffic-legend').innerHTML = bits.join(' · ');
}

function drawTrafficChart() {
  const svg = $('#traffic-chart');
  const empty = $('#traffic-empty');
  const tip = $('#traffic-tip');
  const points = traffic.points;
  const filled = points.filter((point) => point[1] !== null || point[2] !== null);

  if (points.length < 2 || filled.length < 2) {
    svg.classList.add('hidden');
    empty.classList.remove('hidden');
    empty.textContent = points.length ? '正在采集…' : '暂无数据';
    tip.classList.add('hidden');
    traffic.geometry = null;
    return;
  }
  svg.classList.remove('hidden');
  empty.classList.add('hidden');

  /* The viewBox is set from the rendered pixel width so text keeps its real size
     instead of being scaled down with the drawing. */
  const width = Math.max(320, svg.parentElement.clientWidth || 720);
  const height = width < 520 ? 220 : 300;
  const pad = { left: 62, right: 14, top: 14, bottom: 26 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  let max = 0;
  points.forEach((point) => {
    if (point[1] !== null) max = Math.max(max, point[1]);
    if (point[2] !== null) max = Math.max(max, point[2]);
  });
  /* An all-idle window still needs an axis: scale to 1 KB/s so the labels read
     as rates instead of four identical "0 B/s". */
  const idle = !(max > 0);
  if (idle) max = 1024;

  const x = (index) => pad.left + (index / (points.length - 1)) * plotW;
  const y = (value) => pad.top + (1 - value / max) * plotH;

  function pathFor(column) {
    let d = '';
    let open = false;
    points.forEach((point, index) => {
      const value = point[column];
      if (value === null) { open = false; return; }
      d += `${open ? 'L' : 'M'}${x(index).toFixed(1)} ${y(value).toFixed(1)} `;
      open = true;
    });
    return d.trim();
  }

  const grid = [];
  for (let i = 0; i <= 4; i++) {
    const gy = y((max * i) / 4);
    grid.push(`<line class="chart-grid" x1="${pad.left}" y1="${gy.toFixed(1)}" `
      + `x2="${(width - pad.right).toFixed(1)}" y2="${gy.toFixed(1)}"></line>`);
    grid.push(`<text class="chart-axis" x="${pad.left - 8}" y="${(gy + 4).toFixed(1)}" `
      + `text-anchor="end">${escapeHtml(rate((max * i) / 4))}</text>`);
  }

  const last = points.length - 1;
  const axis = [0, Math.floor(last / 3), Math.floor((2 * last) / 3), last].map((index) => {
    const anchor = index === 0 ? 'start' : (index === last ? 'end' : 'middle');
    return `<text class="chart-axis" x="${x(index).toFixed(1)}" y="${height - 8}" `
      + `text-anchor="${anchor}">${escapeHtml(timeLabel(points[index][0]))}</text>`;
  }).join('');

  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('height', String(height));
  const note = idle
    ? `<text class="chart-axis" x="${(pad.left + plotW / 2).toFixed(1)}" `
      + `y="${(pad.top + plotH / 2).toFixed(1)}" text-anchor="middle">窗口内无流量</text>`
    : '';
  svg.innerHTML = grid.join('') + axis + note
    + `<path class="chart-line down" d="${pathFor(1)}"></path>`
    + `<path class="chart-line up" d="${pathFor(2)}"></path>`
    + `<line class="chart-cursor hidden" id="traffic-cursor" y1="${pad.top}" `
    + `y2="${(pad.top + plotH).toFixed(1)}"></line>`
    + '<circle class="chart-dot down hidden" id="traffic-dot-down" r="3.5"></circle>'
    + '<circle class="chart-dot up hidden" id="traffic-dot-up" r="3.5"></circle>'
    + `<rect id="traffic-hit" x="${pad.left}" y="${pad.top}" width="${plotW}" `
    + `height="${plotH}" fill="transparent"></rect>`;
  traffic.geometry = { x, y, pad, width, plotW };
  bindTrafficHover();
}

function bindTrafficHover() {
  const svg = $('#traffic-chart');
  const hit = svg.querySelector('#traffic-hit');
  if (!hit || !traffic.geometry) return;
  const geometry = traffic.geometry;
  const tip = $('#traffic-tip');
  const cursor = svg.querySelector('#traffic-cursor');
  const dots = { down: svg.querySelector('#traffic-dot-down'), up: svg.querySelector('#traffic-dot-up') };
  const wrap = svg.parentElement;

  function hide() {
    cursor.classList.add('hidden');
    dots.down.classList.add('hidden');
    dots.up.classList.add('hidden');
    tip.classList.add('hidden');
  }

  hit.addEventListener('mousemove', (event) => {
    const box = svg.getBoundingClientRect();
    const scale = box.width ? geometry.width / box.width : 1;
    const px = (event.clientX - box.left) * scale;
    const ratio = (px - geometry.pad.left) / geometry.plotW;
    const index = Math.max(0, Math.min(traffic.points.length - 1,
      Math.round(ratio * (traffic.points.length - 1))));
    const point = traffic.points[index];

    cursor.setAttribute('x1', geometry.x(index));
    cursor.setAttribute('x2', geometry.x(index));
    cursor.classList.remove('hidden');
    [['down', 1], ['up', 2]].forEach(([key, column]) => {
      const value = point[column];
      const dot = dots[key];
      if (value === null) { dot.classList.add('hidden'); return; }
      dot.setAttribute('cx', geometry.x(index));
      dot.setAttribute('cy', geometry.y(value));
      dot.classList.remove('hidden');
    });

    const when = new Date(point[0] * 1000).toLocaleString('zh-CN', { hour12: false });
    tip.innerHTML = `<b>${escapeHtml(when)}</b><br>下行 ${point[1] === null ? '—' : rate(point[1])}`
      + `<br>上行 ${point[2] === null ? '—' : rate(point[2])}`;
    tip.classList.remove('hidden');
    const wrapBox = wrap.getBoundingClientRect();
    tip.style.left = `${Math.max(80, Math.min(wrapBox.width - 80, event.clientX - wrapBox.left))}px`;
  });
  hit.addEventListener('mouseleave', hide);
}

async function refreshTraffic() {
  if (document.hidden) return;
  try {
    const query = `window=${traffic.window}&scope=${encodeURIComponent(traffic.scope)}`;
    const data = await api('/api/traffic?' + query);
    traffic.points = data.points || [];
    traffic.error = null;
  } catch (err) {
    if (redirecting) return;
    traffic.error = err.message || '流量数据读取失败';
  }
  renderTrafficTiles();
  renderTrafficLegend();
  drawTrafficChart();
}

function scheduleTraffic() {
  clearTimeout(trafficTimer);
  trafficTimer = setTimeout(() => {
    refreshTraffic();
    scheduleTraffic();
  }, traffic.window === 60 ? 1000 : 5000);
}

/* ---------------------------------------------------------------- actions */
async function refresh() {
  try {
    state = await api('/api/state');
    render();
  } catch (err) {
    if (!redirecting) toast('刷新失败：' + err.message, true);
  }
}

async function guard(fn) {
  if (busy) return;
  busy = true;
  try { await fn(); } catch (err) {
    const needs = err.payload && err.payload.needs;
    toast(err.message + (needs ? `（需要 ${needs.join(' ')}）` : ''), true);
  } finally { busy = false; }
}

function applyResultMessage(result) {
  if (!result) return '已完成';
  if (result.ok) return result.mode === 'noop' ? '已经是最新状态' : `已生效（${result.mode}）`;
  return '生效失败：' + (result.errors[0] || '未知错误');
}

async function addPeer(form) {
  const data = new FormData(form);
  const extra = String(data.get('extra_allowed_ips') || '')
    .split(',').map((s) => s.trim()).filter(Boolean);
  const out = await api('/api/peers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: data.get('name'),
      address: String(data.get('address') || '').trim(),
      extra_allowed_ips: extra,
    }),
  });
  toast(applyResultMessage(out.apply));
  await refresh();
}

async function deletePeer(name) {
  if (!confirm(`删除 peer “${name}”？客户端将立即断线。`)) return;
  const out = await api(`/api/peers/${encodeURIComponent(name)}`, { method: 'DELETE' });
  toast(applyResultMessage(out.apply));
  await refresh();
}

async function applyPending() {
  let allowDisruptive = false;
  let allowDestructive = false;
  if (state.pending && state.pending.disruptive) {
    if (!confirm('这个改动会短暂重挂 wireguard 接口，继续？')) return;
    allowDisruptive = true;
  }
  if (state.pending && state.pending.destructive) {
    if (!confirm('这个改动会删除 peer 或修改监听端口，继续？')) return;
    allowDestructive = true;
  }
  const out = await api('/api/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ allow_disruptive: allowDisruptive, allow_destructive: allowDestructive }),
  });
  toast(applyResultMessage(out));
  await refresh();
}

function openEdit(name) {
  const peer = (state.peers || []).find((item) => item.name === name);
  if (!peer) return;
  const form = $('#form-edit');
  form.reset();
  form.original.value = peer.name;
  form.new_name.value = peer.name;
  form.allowed_ips.value = (peer.allowed_ips || []).join(', ');
  form.keepalive.value = peer.persistent_keepalive == null ? '' : peer.persistent_keepalive;
  // The address the peer dialled in from is learned state; editing it back into
  // the file would pin a stale NAT port, so only the configured value belongs here.
  form.endpoint.value = peer.config_endpoint || '';
  $('#dlg-edit').showModal();
}

async function saveEdit(form) {
  const data = new FormData(form);
  const payload = {
    new_name: data.get('new_name'),
    allowed_ips: String(data.get('allowed_ips') || '')
      .split(',').map((s) => s.trim()).filter(Boolean),
    keepalive: data.get('keepalive') === '' ? 0 : Number(data.get('keepalive')),
    endpoint: data.get('endpoint') || '',
  };
  const out = await api(`/api/peers/${encodeURIComponent(data.get('original'))}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  toast(applyResultMessage(out.apply));
  await refresh();
}

function openQr(name) {
  const url = `/api/peers/${encodeURIComponent(name)}/qr.svg?v=${Date.now()}`;
  $('#qr-title').textContent = name + ' 的客户端配置';
  $('#qr-img').src = url;
  $('#qr-download').href = `/api/peers/${encodeURIComponent(name)}/conf`;
  $('#qr-download').setAttribute('download', name + '.conf');
  $('#dlg-qr').showModal();
}

function openSettings() {
  const form = $('#form-settings');
  const s = state.settings;
  form.server_url.value = s.server_url || '';
  form.server_port.value = s.server_port || 51820;
  form.client_dns.value = s.client_dns || '';
  form.client_allowed_ips.value = s.client_allowed_ips || '';
  form.client_keepalive.value = s.client_keepalive || 0;
  $('#dlg-settings').showModal();
}

async function saveSettings(form) {
  const data = new FormData(form);
  const payload = {
    server_url: data.get('server_url'),
    server_port: Number(data.get('server_port')) || null,
    client_dns: data.get('client_dns'),
    client_allowed_ips: data.get('client_allowed_ips'),
    client_keepalive: Number(data.get('client_keepalive')) || 0,
  };
  await api('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  toast('设置已保存');
  await refresh();
}

/* ----------------------------------------------------------------- wiring */
$('#btn-refresh').onclick = refresh;
$('#btn-settings').onclick = openSettings;
$('#btn-add').onclick = () => { $('#form-add').reset(); $('#dlg-add').showModal(); };
$('#btn-apply').onclick = () => guard(applyPending);
$('#btn-logout').onclick = async () => {
  redirecting = true;
  clearInterval(refreshTimer);
  try { await fetch('/api/logout', { method: 'POST' }); } catch (_) { /* leave anyway */ }
  location.href = '/login';
};

$('#form-add').addEventListener('submit', (ev) => {
  if (ev.submitter && ev.submitter.value === 'cancel') return;
  ev.preventDefault();
  const form = ev.target;
  $('#dlg-add').close();
  guard(() => addPeer(form));
});

$('#form-edit').addEventListener('submit', (ev) => {
  if (ev.submitter && ev.submitter.value === 'cancel') return;
  ev.preventDefault();
  const form = ev.target;
  $('#dlg-edit').close();
  guard(() => saveEdit(form));
});

$('#form-settings').addEventListener('submit', (ev) => {
  if (ev.submitter && ev.submitter.value === 'cancel') return;
  ev.preventDefault();
  const form = ev.target;
  $('#dlg-settings').close();
  guard(() => saveSettings(form));
});

$('#peers-body').addEventListener('click', (ev) => {
  const get = (attr) => (ev.target.getAttribute ? ev.target.getAttribute(attr) : null);
  const qr = get('data-qr');
  const del = get('data-del');
  const edit = get('data-edit');
  if (qr) guard(() => Promise.resolve(openQr(qr)));
  if (edit) guard(() => Promise.resolve(openEdit(edit)));
  if (del) guard(() => deletePeer(del));
});

$('#traffic-range').addEventListener('click', (ev) => {
  const button = ev.target.closest('[data-window]');
  if (!button) return;
  const wanted = Number(button.dataset.window);
  if (!TRAFFIC_RANGES.includes(wanted) || wanted === traffic.window) return;
  traffic.window = wanted;
  traffic.points = [];
  saveTrafficChoice();
  markTrafficRange();
  refreshTraffic();
  scheduleTraffic();
});

$('#traffic-scope').addEventListener('change', (ev) => {
  traffic.scope = ev.target.value || 'all';
  traffic.points = [];
  saveTrafficChoice();
  refreshTraffic();
});

/* The chart is drawn in device-independent units taken from the wrapper width,
   so it has to be redrawn when that width changes. One frame of debounce keeps
   a drag-resize from re-rendering on every pixel. */
if (window.ResizeObserver) {
  new ResizeObserver(() => {
    if (trafficResize) cancelAnimationFrame(trafficResize);
    trafficResize = requestAnimationFrame(() => drawTrafficChart());
  }).observe($('.chart-wrap'));
}

loadTrafficChoice();
markTrafficRange();
refresh();
refreshTraffic();
scheduleTraffic();
refreshTimer = setInterval(refresh, 2000);
