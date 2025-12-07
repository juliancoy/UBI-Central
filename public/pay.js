const payState = {
  accessToken: localStorage.getItem('accessToken') || '',
  payload: null,
};

const titleEl = document.getElementById('pay-title');
const memoEl = document.getElementById('pay-memo');
const amountEl = document.getElementById('pay-amount');
const destEl = document.getElementById('pay-destination');
const statusEl = document.getElementById('pay-status');
const confirmBtn = document.getElementById('confirm-pay');

function base64urlDecode(str) {
  try {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(str.length + (4 - (str.length % 4)) % 4, '=');
    return decodeURIComponent(escape(atob(padded)));
  } catch {
    return null;
  }
}

function setStatus(msg, isError = false) {
  statusEl.textContent = msg;
  statusEl.style.color = isError ? 'var(--danger)' : 'var(--muted)';
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (payState.accessToken) {
    headers.Authorization = `Bearer ${payState.accessToken}`;
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

function renderPayload() {
  const params = new URLSearchParams(window.location.search);
  const encoded = params.get('payload') || '';
  const decoded = base64urlDecode(encoded);
  if (!decoded) {
    setStatus('Invalid invoice payload', true);
    return;
  }
  try {
    payState.payload = JSON.parse(decoded);
  } catch {
    setStatus('Invalid invoice payload', true);
    return;
  }
  const p = payState.payload;
  titleEl.textContent = `Invoice for ${p.to || 'recipient'}`;
  memoEl.textContent = p.memo || 'No memo provided.';
  amountEl.textContent = `Amount: ${p.amount}`;
  destEl.textContent = `Destination: ${p.to || 'N/A'}`;
  setStatus('Ready to pay');
}

confirmBtn?.addEventListener('click', async () => {
  if (!payState.accessToken) {
    setStatus('Login required to pay invoices.', true);
    return;
  }
  if (!payState.payload || !payState.payload.amount) {
    setStatus('Missing invoice details.', true);
    return;
  }
  setStatus('Submitting payment…');
  try {
    const payload = payState.payload;
    await api('/api/transfer', {
      method: 'POST',
      body: JSON.stringify({
        direction: 'outbound',
        amount: payload.amount,
        destination: payload.to || 'invoice',
        time: new Date().toISOString(),
      }),
    });
    setStatus('Payment sent.');
  } catch (err) {
    setStatus(err.message, true);
  }
});

document.addEventListener('auth:tokens-changed', (event) => {
  payState.accessToken = event.detail?.accessToken || '';
});

renderPayload();
