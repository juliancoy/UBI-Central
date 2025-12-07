const state = {
  accessToken: localStorage.getItem('accessToken') || '',
  refreshToken: localStorage.getItem('refreshToken') || '',
};

const accessStateEl = document.getElementById('access-state');
const refreshStateEl = document.getElementById('refresh-state');
const statusEl = document.getElementById('status');
const profileOutput = document.getElementById('profile-output');
const loginModal = document.getElementById('login-modal');
const modalBackdrop = document.getElementById('modal-backdrop');
const modalClose = document.getElementById('modal-close');

const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const refreshBtn = document.getElementById('refresh-btn');
const meBtn = document.getElementById('me-btn');
const logoutBtn = document.getElementById('logout-btn');

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
    profileOutput.textContent = JSON.stringify(data.user, null, 2);
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
    profileOutput.textContent = JSON.stringify(data.user, null, 2);
  } catch (err) {
    setStatus(err.message, true);
  }
});

refreshBtn.addEventListener('click', async () => {
  if (!state.refreshToken) {
    setStatus('No refresh token available', true);
    return;
  }
  try {
    const data = await api('/api/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: state.refreshToken }),
    });
    setTokens(data);
    setStatus('Access token refreshed');
  } catch (err) {
    setStatus(err.message, true);
  }
});

meBtn.addEventListener('click', async () => {
  if (!state.accessToken) {
    setStatus('No access token available', true);
    return;
  }
  try {
    const data = await api('/api/auth/me');
    profileOutput.textContent = JSON.stringify(data.user, null, 2);
    setStatus('Fetched profile');
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
  profileOutput.textContent = 'Logged out.';
  setStatus('Logged out');
  emitAuthChange();
});

updateBadges();
parseTokensFromQuery();

function hideModal() {
  loginModal.classList.add('hidden');
}

modalBackdrop?.addEventListener('click', hideModal);
modalClose?.addEventListener('click', hideModal);
document.addEventListener('keyup', (e) => {
  if (e.key === 'Escape') hideModal();
});

window.showLoginModal = () => {
  loginModal.classList.remove('hidden');
};
