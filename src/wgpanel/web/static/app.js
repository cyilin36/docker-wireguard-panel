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

  const rows = state.peers.map((peer) => `
    <tr>
      <td>${escapeHtml(peer.name)}${peer.has_preshared_key ? '' : ' <span class="badge">无 PSK</span>'}</td>
      <td class="mono">${escapeHtml(peer.client_ip || '—')}</td>
      <td><span class="badge ${peer.online ? 'online' : 'offline'}"
                title="${peer.online ? '最近 3 分钟内有握手' : '最近 3 分钟没有握手'}">${peer.online ? '在线' : '离线'}</span>
          <span class="mono" title="最后一次握手距今多久">${age(peer.latest_handshake)}</span></td>
      <td class="mono">${escapeHtml(peer.endpoint || '—')}</td>
      <td class="num">${rate(peer.rx_rate)}</td>
      <td class="num">${rate(peer.tx_rate)}</td>
      <td class="num mono">↓${bytes(peer.rx)} ↑${bytes(peer.tx)}</td>
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
    body: JSON.stringify({ name: data.get('name'), extra_allowed_ips: extra }),
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
  form.endpoint.value = peer.endpoint || '';
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

refresh();
refreshTimer = setInterval(refresh, 2000);
