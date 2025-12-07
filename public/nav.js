const navUserEl = document.getElementById('nav-user');

const navState = {
  accessToken: localStorage.getItem('accessToken') || '',
  refreshToken: localStorage.getItem('refreshToken') || '',
  profile: null,
  dropdownOpen: false,
};

function closeDropdown() {
  navState.dropdownOpen = false;
  const dropdown = document.querySelector('.nav-dropdown');
  if (dropdown) dropdown.classList.add('hidden');
}

function openDropdown() {
  navState.dropdownOpen = true;
  const dropdown = document.querySelector('.nav-dropdown');
  if (dropdown) dropdown.classList.remove('hidden');
}

function setNavStatus(message) {
  const status = document.querySelector('.nav-status');
  if (status) status.textContent = message;
}

function initials(name) {
  if (!name) return 'U';
  return name
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0].toUpperCase())
    .join('');
}

function renderLoggedOut() {
  if (!navUserEl) return;
  navUserEl.innerHTML = `
    <button class="button ghost small" id="nav-login-btn" type="button">Login</button>
  `;
  const loginBtn = document.getElementById('nav-login-btn');
  loginBtn?.addEventListener('click', () => {
    if (window.showLoginModal) {
      window.showLoginModal();
    } else {
      window.location.href = '/';
    }
  });
}

function renderLoggedIn() {
  if (!navUserEl || !navState.profile) return;
  const avatarLetter = initials(navState.profile.name || navState.profile.email);
  navUserEl.innerHTML = `
    <button class="nav-user-btn" id="nav-user-btn" type="button" aria-haspopup="true">
      <span class="nav-avatar">${avatarLetter}</span>
      <div class="nav-user-meta">
        <span class="name">${navState.profile.name || 'User'}</span>
        <span class="muted small">${navState.profile.email}</span>
      </div>
      <span class="nav-caret">▾</span>
    </button>
    <div class="nav-dropdown hidden" id="nav-dropdown">
      <div class="nav-dropdown-header">
        <div class="nav-avatar lg">${avatarLetter}</div>
        <div>
          <div class="name">${navState.profile.name || 'User'}</div>
          <div class="muted small">${navState.profile.email}</div>
        </div>
      </div>
      <button class="nav-dropdown-item" id="nav-logout-btn" type="button">Logout</button>
      <div class="nav-status muted small"></div>
    </div>
  `;
  document.getElementById('nav-user-btn')?.addEventListener('click', (event) => {
    event.stopPropagation();
    navState.dropdownOpen ? closeDropdown() : openDropdown();
  });
  document.getElementById('nav-logout-btn')?.addEventListener('click', async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: navState.refreshToken }),
        credentials: 'include',
      });
    } catch (err) {
      // best-effort
    }
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    navState.accessToken = '';
    navState.refreshToken = '';
    navState.profile = null;
    document.dispatchEvent(
      new CustomEvent('auth:tokens-changed', {
        detail: { accessToken: '', refreshToken: '' },
      })
    );
    closeDropdown();
    renderLoggedOut();
  });
}

async function loadProfile() {
  if (!navState.accessToken) {
    renderLoggedOut();
    return;
  }
  try {
    const res = await fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${navState.accessToken}` },
      credentials: 'include',
    });
    if (!res.ok) throw new Error();
    const data = await res.json();
    navState.profile = data.user;
    renderLoggedIn();
  } catch {
    renderLoggedOut();
  }
}

function syncTokens(accessToken, refreshToken) {
  navState.accessToken = accessToken || localStorage.getItem('accessToken') || '';
  navState.refreshToken = refreshToken || localStorage.getItem('refreshToken') || '';
}

document.addEventListener('auth:tokens-changed', (event) => {
  const detail = event.detail || {};
  syncTokens(detail.accessToken, detail.refreshToken);
  loadProfile();
});

document.addEventListener('click', (event) => {
  const dropdown = document.getElementById('nav-dropdown');
  if (!dropdown || dropdown.classList.contains('hidden')) return;
  if (navUserEl && navUserEl.contains(event.target)) return;
  closeDropdown();
});

syncTokens();
loadProfile();
