const pageState = {
  accessToken: localStorage.getItem('accessToken') || '',
  email: new URLSearchParams(window.location.search).get('email') || '',
};

const nameEl = document.getElementById('account-name');
const emailEl = document.getElementById('account-email');
const statusPill = document.getElementById('account-status-pill');
const balancePill = document.getElementById('account-balance-pill');
const inboundTotalEl = document.getElementById('stat-inbound-total');
const outboundTotalEl = document.getElementById('stat-outbound-total');
const inboundCountEl = document.getElementById('stat-inbound-count');
const outboundCountEl = document.getElementById('stat-outbound-count');
const netEl = document.getElementById('stat-net');
const chartRangeEl = document.getElementById('chart-range');
const statusMsg = document.getElementById('account-status-msg');
const txnSummary = document.getElementById('txn-summary');
const txnTable = document.getElementById('txn-table-body');
const txnEmpty = document.getElementById('txn-empty');
const chartEl = document.getElementById('balance-chart');

function syncTokens(detail = {}) {
  pageState.accessToken = detail.accessToken || localStorage.getItem('accessToken') || '';
}

function setStatus(message, isError = false) {
  statusMsg.textContent = message;
  statusMsg.style.color = isError ? 'var(--danger)' : 'var(--muted)';
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: 2 });
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

async function api(path) {
  const headers = { 'Content-Type': 'application/json' };
  if (pageState.accessToken) {
    headers.Authorization = `Bearer ${pageState.accessToken}`;
  }
  const res = await fetch(path, { headers, credentials: 'include' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data.message || 'Request failed';
    throw new Error(msg);
  }
  return data;
}

function mergeTransactions(user) {
  const items = [];
  (user.inbound || []).forEach((tx) => {
    items.push({
      direction: 'Inbound',
      counterparty: tx.source || 'Unknown',
      amount: Number(tx.amount || 0),
      time: tx.time,
      delta: Number(tx.amount || 0),
    });
  });
  (user.outbound || []).forEach((tx) => {
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

  // grid
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad, pad);
  ctx.lineTo(pad, pad + plotH);
  ctx.lineTo(pad + plotW, pad + plotH);
  ctx.stroke();

  // baseline for zero if within range
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
}

function renderAccount(user) {
  nameEl.textContent = user.name || user.email || 'Unknown user';
  emailEl.textContent = user.email || '';
  const status = user.status || 'registered';
  statusPill.textContent = `Status: ${status}`;

  inboundTotalEl.textContent = formatCurrency(user.inboundTotal || 0);
  outboundTotalEl.textContent = formatCurrency(user.outboundTotal || 0);
  inboundCountEl.textContent = `${formatNumber(user.inboundCount || 0)} transfers`;
  outboundCountEl.textContent = `${formatNumber(user.outboundCount || 0)} transfers`;
  const net = (user.inboundTotal || 0) - (user.outboundTotal || 0);
  netEl.textContent = formatCurrency(net);
  balancePill.textContent = `Balance: ${formatCurrency(net)}`;

  const txns = mergeTransactions(user);
  renderTransactions(txns);
  if (txns.length) {
    const first = new Date(txns[0].time);
    const last = new Date(txns[txns.length - 1].time);
    if (!Number.isNaN(first) && !Number.isNaN(last)) {
      chartRangeEl.textContent = `${first.toLocaleDateString()} → ${last.toLocaleDateString()}`;
      chartRangeEl.className = 'badge success';
    }
    txnSummary.textContent = `${txns.length} transaction${txns.length === 1 ? '' : 's'} recorded.`;
  } else {
    chartRangeEl.textContent = 'No activity yet';
    chartRangeEl.className = 'badge muted';
    txnSummary.textContent = 'No transfers yet.';
  }
  renderChart(chartEl, txns);
}

async function loadAccount() {
  if (!pageState.email) {
    setStatus('Missing account email in URL.', true);
    return;
  }
  if (!pageState.accessToken) {
    setStatus('Login required to view account details.', true);
    return;
  }
  setStatus('Loading account…');
  try {
    const data = await api(`/api/admin/users/${encodeURIComponent(pageState.email)}`);
    renderAccount(data.user || {});
    setStatus('Account loaded.');
  } catch (err) {
    setStatus(err.message, true);
  }
}

document.addEventListener('auth:tokens-changed', (event) => {
  syncTokens(event.detail || {});
  loadAccount();
});

syncTokens();
loadAccount();
