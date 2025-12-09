const pageState = {
  accessToken: localStorage.getItem('accessToken') || '',
  email: new URLSearchParams(window.location.search).get('email') || '',
  selectedRange: '1Y',
  dailySeries: [],
  accountStart: null,
};

const RANGE_OPTIONS = [
  { key: '5Y', label: '5Y', days: 365 * 5 },
  { key: '3Y', label: '3Y', days: 365 * 3 },
  { key: '1Y', label: '1Y', days: 365 },
  { key: '6M', label: '6M', days: 30 * 6 },
  { key: '1M', label: '1M', days: 30 },
];

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
const rangeButtons = document.getElementById('chart-range-buttons');

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

function startOfDay(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  d.setHours(0, 0, 0, 0);
  return d;
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

function inferAccountStart(user, txns) {
  const created = [
    user.createdAt,
    user.created_at,
    user.created,
    user.created_on,
  ]
    .map(startOfDay)
    .filter(Boolean)
    .map((d) => d.getTime());

  const txnStarts = txns
    .map((t) => startOfDay(t.time))
    .filter(Boolean)
    .map((d) => d.getTime());

  const earliest = [...created, ...txnStarts];
  if (!earliest.length) return startOfDay(new Date());
  return startOfDay(Math.min(...earliest));
}

function buildDailyBalances(txns, startDate) {
  const today = startOfDay(new Date());
  const inferredStart = startOfDay(startDate || new Date()) || today;
  const start = inferredStart > today ? today : inferredStart;
  const sorted = [...txns].sort(
    (a, b) => new Date(a.time).getTime() - new Date(b.time).getTime()
  );
  let balance = 0;
  let idx = 0;
  const series = [];

  for (let cursor = new Date(start); cursor <= today; cursor.setDate(cursor.getDate() + 1)) {
    const dayEnd = new Date(cursor);
    dayEnd.setHours(23, 59, 59, 999);

    while (idx < sorted.length) {
      const txTime = new Date(sorted[idx].time);
      if (Number.isNaN(txTime.getTime()) || txTime > dayEnd) break;
      balance += sorted[idx].delta;
      idx += 1;
    }

    series.push({ date: new Date(cursor), balance });
  }

  return series;
}

function filterSeriesForRange(series, rangeKey) {
  const option = RANGE_OPTIONS.find((opt) => opt.key === rangeKey);
  if (!option || !option.days) return series;
  const today = startOfDay(new Date());
  const cutoff = startOfDay(new Date(today));
  cutoff.setDate(cutoff.getDate() - option.days + 1);
  return series.filter((point) => point.date >= cutoff);
}

function updateRangeBadge(series) {
  if (!chartRangeEl) return;
  if (!series.length) {
    chartRangeEl.textContent = 'No activity yet';
    chartRangeEl.className = 'badge muted';
    return;
  }
  const first = series[0].date;
  const last = series[series.length - 1].date;
  chartRangeEl.textContent = `${first.toLocaleDateString()} → ${last.toLocaleDateString()}`;
  chartRangeEl.className = 'badge success';
}

function renderRangeButtons() {
  if (!rangeButtons) return;
  const buttons = Array.from(rangeButtons.querySelectorAll('.range-btn'));
  buttons.forEach((btn) => {
    const key = btn.dataset.range;
    btn.classList.toggle('active', key === pageState.selectedRange);
    btn.onclick = () => {
      pageState.selectedRange = key;
      refreshChart();
      renderRangeButtons();
    };
  });
}

function renderBarChart(canvas, series) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  if (!series.length) {
    ctx.fillStyle = '#9ca3af';
    ctx.font = '14px Inter, system-ui, sans-serif';
    ctx.fillText('No activity yet', 20, height / 2);
    return;
  }

  const balances = series.map((p) => p.balance);
  const minBal = Math.min(0, ...balances);
  const maxBal = Math.max(0, ...balances);
  const yRange = maxBal - minBal || 1;
  const pad = 28;
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

  const zeroY = pad + plotH - ((0 - minBal) / yRange) * plotH;
  const step = plotW / series.length;
  const barW = Math.max(1, step * 0.7);
  const offset = (step - barW) / 2;

  series.forEach((point, idx) => {
    const valueY = pad + plotH - ((point.balance - minBal) / yRange) * plotH;
    const y = Math.min(zeroY, valueY);
    const h = Math.max(2, Math.abs(zeroY - valueY));
    const x = pad + idx * step + offset;
    ctx.fillStyle = point.balance >= 0 ? 'rgba(70, 200, 160, 0.8)' : 'rgba(248, 113, 113, 0.8)';
    ctx.fillRect(x, y, barW, h);
  });

  // simple axis labels
  ctx.fillStyle = '#9ca3af';
  ctx.font = '11px Inter, system-ui, sans-serif';
  ctx.textAlign = 'left';
  ctx.fillText(series[0].date.toLocaleDateString(), pad, height - 6);
  ctx.textAlign = 'right';
  ctx.fillText(series[series.length - 1].date.toLocaleDateString(), width - pad, height - 6);
  ctx.textAlign = 'left';
}

function refreshChart() {
  const filtered = filterSeriesForRange(pageState.dailySeries || [], pageState.selectedRange);
  renderBarChart(chartEl, filtered);
  updateRangeBadge(filtered);
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
  pageState.accountStart = inferAccountStart(user, txns);
  pageState.dailySeries = buildDailyBalances(txns, pageState.accountStart);
  renderRangeButtons();
  refreshChart();

  if (txns.length) {
    txnSummary.textContent = `${txns.length} transaction${txns.length === 1 ? '' : 's'} recorded.`;
  } else {
    txnSummary.textContent = 'No transfers yet.';
  }
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
