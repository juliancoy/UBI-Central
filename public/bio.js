const profileOutput = document.getElementById('profile-output');
const statusEl = document.getElementById('status');
const logoutBtn = document.getElementById('logout-btn');

const state = {
  accessToken: localStorage.getItem('accessToken') || '',
  refreshToken: localStorage.getItem('refreshToken') || '',
};

function emitAuthChange() {
  document.dispatchEvent(
    new CustomEvent('auth:tokens-changed', {
      detail: { accessToken: state.accessToken, refreshToken: state.refreshToken },
    })
  );
}

document.addEventListener('auth:tokens-changed', (event) => {
  const detail = event.detail || {};
  state.accessToken = detail.accessToken || localStorage.getItem('accessToken') || '';
  state.refreshToken = detail.refreshToken || localStorage.getItem('refreshToken') || '';
});

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
    throw new Error(data.message || 'Request failed');
  }
  return data;
}

async function loadProfile() {
  if (!state.accessToken) {
    setStatus('No access token; please log in.', true);
    profileOutput.textContent = 'Not signed in.';
    return;
  }
  try {
    const data = await api('/api/auth/me');
    profileOutput.textContent = JSON.stringify(data.user, null, 2);
    setStatus('Profile loaded.');
  } catch (err) {
    setStatus(err.message, true);
    profileOutput.textContent = 'Could not load profile.';
  }
}

async function logout() {
  try {
    await api('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: state.refreshToken }),
    });
  } catch (err) {
    // best-effort
  }
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  state.accessToken = '';
  state.refreshToken = '';
  emitAuthChange();
  profileOutput.textContent = 'Logged out.';
  setStatus('Logged out. Redirecting to home…');
  setTimeout(() => {
    window.location.href = '/';
  }, 800);
}

logoutBtn.addEventListener('click', logout);

loadProfile();
