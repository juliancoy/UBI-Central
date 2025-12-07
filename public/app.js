const state = {
  accessToken: localStorage.getItem('accessToken') || '',
  refreshToken: localStorage.getItem('refreshToken') || '',
};

const accessStateEl = document.getElementById('access-state');
const refreshStateEl = document.getElementById('refresh-state');
const statusEl = document.getElementById('status');
const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const logoutBtn = document.getElementById('logout-btn');
const chartEl = document.getElementById('balance-chart');
const chartRangeEl = document.getElementById('chart-range');
const txnSummary = document.getElementById('txn-summary');
const txnTable = document.getElementById('txn-table-body');
const txnEmpty = document.getElementById('txn-empty');

function parseTokensFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const accessToken = params.get('accessToken');
  const refreshToken = params.get('refreshToken');
  if (accessToken || refreshToken) {
    setTokens({ accessToken, refreshToken });
    setStatus('Signed in via social login');
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

function updateBadges() {
  accessStateEl.textContent = state.accessToken ? 'set' : 'none';
  accessStateEl.classList.toggle('muted', !state.accessToken);
  refreshStateEl.textContent = state.refreshToken ? 'set' : 'none';
  refreshStateEl.classList.toggle('muted', !state.refreshToken);
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? 'var(--danger)' : 'var(--text)';
}

function emitAuthChange() {
  document.dispatchEvent(
    new CustomEvent('auth:tokens-changed', {
      detail: { accessToken: state.accessToken, refreshToken: state.refreshToken },
    })
  );
}

function setTokens({ accessToken, refreshToken }) {
  if (accessToken) {
    state.accessToken = accessToken;
    localStorage.setItem('accessToken', accessToken);
  }
  if (refreshToken) {
    state.refreshToken = refreshToken;
    localStorage.setItem('refreshToken', refreshToken);
  }
  updateBadges();
  emitAuthChange();
}

function formatCurrency(value) {
  return Number(value || 0).toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 2,
  });
}

function formatDate(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value || '—';
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (state.accessToken) {
    headers.Authorization = `Bearer ${state.accessToken}`;
  }
  const res = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...headers },
    credentials: 'include',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data.message || 'Request failed';
    throw new Error(msg);
  }
  return data;
}

function mergeTransactions(record) {
  const items = [];
  (record.inbound || []).forEach((tx) => {
    items.push({
      direction: 'Inbound',
      counterparty: tx.source || 'Unknown',
      amount: Number(tx.amount || 0),
      time: tx.time,
      delta: Number(tx.amount || 0),
    });
  });
  (record.outbound || []).forEach((tx) => {
    items.push({
      direction: 'Outbound',
      counterparty: tx.destination || 'Unknown',
      amount: Number(tx.amount || 0),
      time: tx.time,
      delta: -Number(tx.amount || 0),
    });
  });
  items.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());
  return items;
}

function renderChart(canvas, txns) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  if (!txns.length) {
    ctx.fillStyle = '#9ca3af';
    ctx.font = '14px Inter, system-ui, sans-serif';
    ctx.fillText('No activity yet', 20, height / 2);
    return;
  }

  const times = txns.map((t) => new Date(t.time).getTime());
  const deltas = txns.map((t) => t.delta);

  const points = [];
  let balance = 0;
  for (let i = 0; i < txns.length; i += 1) {
    balance += deltas[i];
    points.push({ time: times[i], balance });
  }

  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const minBal = Math.min(0, ...points.map((p) => p.balance));
  const maxBal = Math.max(0, ...points.map((p) => p.balance));
  const yRange = maxBal - minBal || 1;
  const xRange = maxTime - minTime || 1;
  const pad = 24;
  const plotW = width - pad * 2;
  const plotH = height - pad * 2;

  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad, pad);
  ctx.lineTo(pad, pad + plotH);
  ctx.lineTo(pad + plotW, pad + plotH);
  ctx.stroke();

  if (minBal < 0 && maxBal > 0) {
    const zeroY = pad + plotH - ((0 - minBal) / yRange) * plotH;
    ctx.strokeStyle = 'rgba(255,255,255,0.12)';
    ctx.beginPath();
    ctx.moveTo(pad, zeroY);
    ctx.lineTo(pad + plotW, zeroY);
    ctx.stroke();
  }

  ctx.beginPath();
  points.forEach((p, idx) => {
    const x = pad + ((p.time - minTime) / xRange) * plotW;
    const y = pad + plotH - ((p.balance - minBal) / yRange) * plotH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#46c8a0';
  ctx.lineWidth = 2;
  ctx.stroke();

  ctx.lineTo(pad + plotW, pad + plotH);
  ctx.lineTo(pad, pad + plotH);
  ctx.closePath();
  ctx.fillStyle = 'rgba(70, 200, 160, 0.12)';
  ctx.fill();
}

function renderTransactions(txns) {
  txnTable.innerHTML = '';
  if (!txns.length) {
    txnEmpty.classList.remove('hidden');
    txnSummary.textContent = 'No transfers yet.';
    chartRangeEl.textContent = 'No activity yet';
    chartRangeEl.className = 'badge muted';
    renderChart(chartEl, []);
    return;
  }
  txnEmpty.classList.add('hidden');
  txns.forEach((tx) => {
    const row = document.createElement('tr');
    const badgeClass = tx.direction === 'Inbound' ? 'success' : 'muted';
    row.innerHTML = `
      <td><span class="badge ${badgeClass}">${tx.direction}</span></td>
      <td>${tx.counterparty}</td>
      <td>${formatCurrency(tx.amount)}</td>
      <td>${formatDate(tx.time)}</td>
    `;
    txnTable.appendChild(row);
  });
  const first = new Date(txns[0].time);
  const last = new Date(txns[txns.length - 1].time);
  if (!Number.isNaN(first) && !Number.isNaN(last)) {
    chartRangeEl.textContent = `${first.toLocaleDateString()} → ${last.toLocaleDateString()}`;
    chartRangeEl.className = 'badge success';
  }
  txnSummary.textContent = `${txns.length} transaction${txns.length === 1 ? '' : 's'} recorded.`;
  renderChart(chartEl, txns);
}

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(registerForm);
  const payload = Object.fromEntries(formData.entries());
  try {
    const data = await api('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    setTokens(data);
    setStatus(`Registered as ${data.user.email}`);
    loadRecord();
  } catch (err) {
    setStatus(err.message, true);
  }
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  const payload = Object.fromEntries(formData.entries());
  try {
    const data = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    setTokens(data);
    setStatus(`Logged in as ${data.user.email}`);
    loadRecord();
  } catch (err) {
    setStatus(err.message, true);
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: state.refreshToken }),
    });
  } catch (err) {
    // logout should be best-effort
  }
  state.accessToken = '';
  state.refreshToken = '';
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  updateBadges();
  setStatus('Logged out');
  emitAuthChange();
  renderTransactions([]);
});

async function loadRecord() {
  if (!state.accessToken) {
    txnSummary.textContent = 'Login to see your history.';
    txnTable.innerHTML = '';
    txnEmpty.classList.remove('hidden');
    renderChart(chartEl, []);
    return;
  }
  try {
    const data = await api('/api/record');
    const txns = mergeTransactions(data || {});
    renderTransactions(txns);
    setStatus('Record loaded');
  } catch (err) {
    setStatus(err.message, true);
  }
}

updateBadges();
parseTokensFromQuery();
loadRecord();

document.addEventListener('auth:tokens-changed', (event) => {
  state.accessToken = event.detail?.accessToken || '';
  state.refreshToken = event.detail?.refreshToken || '';
  updateBadges();
  loadRecord();
});
