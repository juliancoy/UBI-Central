const invoiceState = {
  accessToken: localStorage.getItem('accessToken') || '',
  profile: null,
};

const amountInput = document.getElementById('invoice-amount');
const memoInput = document.getElementById('invoice-memo');
const statusEl = document.getElementById('invoice-status');
const qrContainer = document.getElementById('qrcode');
const linkEl = document.getElementById('invoice-link');
const copyBtn = document.getElementById('copy-link');

let qr;

function base64urlEncode(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function buildPayload() {
  const amount = Number(amountInput.value || 0);
  const memo = memoInput.value || '';
  const to = invoiceState.profile?.email || '';
  const payload = {
    type: 'invoice',
    amount,
    memo,
    to,
    ts: new Date().toISOString(),
  };
  return payload;
}

function renderQR() {
  if (typeof QRCode === 'undefined') {
    statusEl.textContent = 'QR code library failed to load.';
    return;
  }
  if (!qr) {
    qr = new QRCode(qrContainer, {
      text: '',
      width: 240,
      height: 240,
      colorDark: '#ffffff',
      colorLight: '#0b1220',
    });
  }
  const payload = buildPayload();
  if (!payload.amount || Number.isNaN(payload.amount)) {
    statusEl.textContent = 'Enter an amount to generate a QR code.';
    return;
  }
  const encoded = base64urlEncode(JSON.stringify(payload));
  const url = `${window.location.origin}/pay.html?payload=${encoded}`;
  linkEl.textContent = url;
  qr.makeCode(url);
  statusEl.textContent = `Invoice QR ready for ${payload.amount}`;
}

copyBtn?.addEventListener('click', async () => {
  const text = linkEl.textContent || '';
  try {
    await navigator.clipboard.writeText(text);
    statusEl.textContent = 'Link copied to clipboard';
  } catch {
    statusEl.textContent = 'Unable to copy link';
  }
});

amountInput?.addEventListener('input', renderQR);
memoInput?.addEventListener('input', renderQR);

async function loadProfile() {
  if (!invoiceState.accessToken) return;
  try {
    const res = await fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${invoiceState.accessToken}` },
      credentials: 'include',
    });
    if (!res.ok) return;
    const data = await res.json();
    invoiceState.profile = data.user;
    renderQR();
  } catch {
    // ignore
  }
}

document.addEventListener('auth:tokens-changed', (event) => {
  invoiceState.accessToken = event.detail?.accessToken || '';
  loadProfile();
});

renderQR();
loadProfile();
