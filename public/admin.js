const state = {
  accessToken: localStorage.getItem('accessToken') || '',
};

const statusEl = document.getElementById('status');
const tableBody = document.getElementById('user-table-body');
const tableWrapper = document.getElementById('table-wrapper');
const emptyState = document.getElementById('empty-state');
const lastSync = document.getElementById('last-sync');
const refreshBtn = document.getElementById('refresh-btn');
const totalUsersEl = document.getElementById('total-users');
const activeUsersEl = document.getElementById('active-users');

function syncTokens(detail = {}) {
  state.accessToken = detail.accessToken || localStorage.getItem('accessToken') || '';
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? 'var(--danger)' : 'var(--muted)';
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

function formatNumber(value) {
  return Number(value || 0).toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function initials(name) {
  if (!name) return 'U';
  return name
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join('');
}

function renderUsers(users) {
  tableBody.innerHTML = '';
  const activeUsers = users.filter((u) => (u.inboundCount || 0) + (u.outboundCount || 0) > 0)
    .length;
  totalUsersEl.textContent = users.length;
  activeUsersEl.textContent = activeUsers;

  if (!users.length) {
    emptyState.classList.remove('hidden');
    tableWrapper.classList.add('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  tableWrapper.classList.remove('hidden');

  users.forEach((user) => {
    const row = document.createElement('tr');
    const badgeClass = user.status === 'active' ? 'success' : 'muted';
    row.innerHTML = `
      <td>
        <div class="user-meta">
          <div class="user-avatar">${initials(user.name || user.email)}</div>
          <div>
            <div class="name">${user.name || 'Unknown user'}</div>
            <div class="muted small">${user.email}</div>
          </div>
        </div>
      </td>
      <td><span class="badge ${badgeClass}">${user.status || 'unknown'}</span></td>
      <td>
        <div class="metric"><strong>${formatNumber(user.inboundCount)}</strong></div>
        <div class="muted small">Σ ${formatNumber(user.inboundTotal)}</div>
      </td>
      <td>
        <div class="metric"><strong>${formatNumber(user.outboundCount)}</strong></div>
        <div class="muted small">Σ ${formatNumber(user.outboundTotal)}</div>
      </td>
      <td>
        <div class="metric">${formatNumber((user.inboundTotal || 0) - (user.outboundTotal || 0))}</div>
        <div class="muted small">Net</div>
      </td>
    `;
    tableBody.appendChild(row);
  });
}

async function loadUsers() {
  if (!state.accessToken) {
    setStatus('Sign in to view the admin console.', true);
    emptyState.textContent = 'Login is required to query the C++ backend.';
    emptyState.classList.remove('hidden');
    tableWrapper.classList.add('hidden');
    return;
  }
  setStatus('Loading users…');
  try {
    const data = await api('/api/admin/users');
    renderUsers(data.users || []);
    lastSync.textContent = `Last sync: ${new Date().toLocaleTimeString()}`;
    lastSync.className = 'badge success';
    setStatus('Admin data loaded.');
  } catch (err) {
    setStatus(err.message, true);
    emptyState.textContent = err.message;
    emptyState.classList.remove('hidden');
    tableWrapper.classList.add('hidden');
  }
}

refreshBtn?.addEventListener('click', loadUsers);

document.addEventListener('auth:tokens-changed', (event) => {
  syncTokens(event.detail || {});
  if (!state.accessToken) {
    emptyState.textContent = 'Login is required to query the C++ backend.';
  }
  loadUsers();
});

syncTokens();
loadUsers();
