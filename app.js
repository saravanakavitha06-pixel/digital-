/* ============================================================
   TransitTick — Secure Digital Transportation Ticketing
   Uses Web Crypto API for AES-GCM encryption (client-side)
   ============================================================ */

// ---------- State ----------
const state = {
  masterKey: null,
  settings: null,
  routes: [],        // [{id,name,path,fare,time}]
  passes: [],        // [{id,type,routeId,code,price,issueDate,expiresAt,used,consumedAt,status}]
  activity: [],      // [{time,type,title,detail}]
  lastActivity: Date.now(),
  lockTimerId: null,
};

const STORAGE_KEY = 'transittick_settings';
const VAULT_KEY = 'transittick_vault';
const EXPORT_MAGIC = 'TRANSITTICK';
const EXPORT_VERSION = 1;
const DEFAULT_ITERATIONS = 150000;

// ---------- DOM helper ----------
const $ = (id) => document.getElementById(id);

// ---------- Utility ----------
function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToBase64(bytes) {
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}
function randomBytes(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
}
function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}
function money(n) {
  return '$' + Number(n).toFixed(2);
}

// ---------- Password strength ----------
function passwordStrength(pw) {
  if (!pw) return { score: 0, label: '', cls: '' };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const s = Math.min(score, 4);
  if (s <= 1) return { score: s, label: 'Weak', cls: 'weak' };
  if (s === 2) return { score: s, label: 'Fair', cls: 'fair' };
  if (s === 3) return { score: s, label: 'Good', cls: 'good' };
  return { score: s, label: 'Strong', cls: 'strong' };
}

// ---------- Crypto ----------
async function deriveKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function encryptWithKey(key, plaintext) {
  const iv = randomBytes(12);
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(cipher)) };
}
async function decryptWithKey(key, obj) {
  const iv = base64ToBytes(obj.iv);
  const data = base64ToBytes(obj.data);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(plain);
}
async function encrypt(plaintext) { return encryptWithKey(state.masterKey, plaintext); }
async function decrypt(obj) { return decryptWithKey(state.masterKey, obj); }

// ---------- Storage ----------
function persistSettings() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.settings));
}
async function saveVault() {
  if (!state.masterKey) return;
  const payload = {
    version: EXPORT_VERSION,
    routes: state.routes,
    passes: state.passes,
    activity: state.activity,
    updatedAt: Date.now(),
  };
  const blob = await encrypt(JSON.stringify(payload));
  localStorage.setItem(VAULT_KEY, JSON.stringify(blob));
}
async function loadVault() {
  if (!state.masterKey) return;
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) {
    state.routes = []; state.passes = []; state.activity = [];
    return;
  }
  try {
    const blob = JSON.parse(raw);
    const payload = JSON.parse(await decrypt(blob));
    state.routes = Array.isArray(payload.routes) ? payload.routes : [];
    state.passes = Array.isArray(payload.passes) ? payload.passes : [];
    state.activity = Array.isArray(payload.activity) ? payload.activity : [];
  } catch (e) {
    state.routes = []; state.passes = []; state.activity = [];
  }
}
function clearStorage() {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(VAULT_KEY);
}

// ---------- Toast ----------
let toastTimer;
function showToast(msg, type = '') {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast ' + type;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 2500);
}

// ---------- Pass types ----------
const PASS_TYPES = {
  single: { label: 'Single Ride', duration: 0, uses: 1, price: 2.50 },
  day: { label: 'Day Pass', duration: 24, uses: 999, price: 8.00 },
  weekly: { label: 'Weekly Subscription', duration: 7 * 24, uses: 999, price: 25.00 },
  monthly: { label: 'Monthly Subscription', duration: 30 * 24, uses: 999, price: 85.00 },
};

// ---------- Setup / Login ----------
async function handleSetup() {
  const pw = $('setup-password').value;
  const confirm = $('setup-confirm').value;
  if (pw.length < 8) { showToast('Master password must be at least 8 characters.', 'error'); return; }
  if (pw !== confirm) { showToast('Passwords do not match.', 'error'); return; }
  const salt = randomBytes(16);
  state.settings = { version: 1, salt: bytesToBase64(salt), iterations: DEFAULT_ITERATIONS, autoLock: 300 };
  state.masterKey = await deriveKey(pw, salt, state.settings.iterations);
  state.routes = []; state.passes = []; state.activity = [];
  persistSettings();
  await saveVault();
  enterApp();
  showToast('Vault created successfully!', 'success');
}

async function handleLogin() {
  const pw = $('login-password').value;
  try {
    const key = await deriveKey(pw, base64ToBytes(state.settings.salt), state.settings.iterations);
    state.masterKey = key;
    const test = await encryptWithKey(key, '__transittick_verify__');
    const dec = await decryptWithKey(key, test);
    if (dec !== '__transittick_verify__') throw new Error('bad key');
    await loadVault();
    enterApp();
    $('login-error').classList.add('hidden');
  } catch (e) {
    state.masterKey = null;
    $('login-error').classList.remove('hidden');
    $('login-password').value = '';
  }
}

// ---------- Screen switching ----------
function enterApp() {
  $('unlock-screen').classList.add('hidden');
  $('unlock-screen').classList.remove('active');
  $('app-screen').classList.remove('hidden');
  $('auto-lock-select').value = String(state.settings.autoLock);
  switchView('operator');
  switchTab('dashboard');
  renderAll();
  resetActivity();
}

function lockVault() {
  state.masterKey = null;
  renderAll();
  $('app-screen').classList.add('hidden');
  $('unlock-screen').classList.remove('hidden');
  $('unlock-screen').classList.add('active');
  $('login-form').classList.remove('hidden');
  $('setup-form').classList.add('hidden');
  $('login-password').value = '';
  clearInterval(state.lockTimerId);
  $('lock-timer').textContent = '';
  showToast('Vault locked.', 'success');
}

// ---------- Auto-lock ----------
function resetActivity() {
  state.lastActivity = Date.now();
  if (state.settings.autoLock > 0 && !state.lockTimerId) {
    state.lockTimerId = setInterval(updateLockTimer, 1000);
  }
  updateLockTimer();
}
function updateLockTimer() {
  if (!state.masterKey) return;
  const seconds = state.settings.autoLock;
  if (seconds === 0) { $('lock-timer').textContent = ''; return; }
  const elapsed = Math.floor((Date.now() - state.lastActivity) / 1000);
  const remaining = Math.max(0, seconds - elapsed);
  if (remaining <= 0) { lockVault(); return; }
  const m = Math.floor(remaining / 60);
  const s = remaining % 60;
  $('lock-timer').textContent = `Auto-lock: ${m}:${s.toString().padStart(2, '0')}`;
}
function markActivity() { state.lastActivity = Date.now(); updateLockTimer(); }

// ---------- View / tab switching ----------
function switchView(view) {
  document.querySelectorAll('.view-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === view);
  });
  $('view-operator').classList.toggle('active', view === 'operator');
  $('view-passenger').classList.toggle('active', view === 'passenger');
  if (view === 'operator') {
    switchTab('dashboard');
  } else {
    switchTab('my-passes');
  }
}
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  // Only toggle panels that exist
  ['dashboard', 'routes', 'verify', 'settings', 'my-passes', 'buy', 'history'].forEach((id) => {
    const el = $('tab-' + id);
    if (el) el.classList.toggle('active', id === tab);
  });
}

// ---------- Rendering ----------
function renderAll() {
  if (!state.masterKey) return;
  renderDashboard();
  renderRoutes();
  renderPassenger();
  renderHistory();
}

function renderDashboard() {
  const today = new Date().toDateString();
  const todayValidated = state.activity.filter((a) => a.type === 'validate' && new Date(a.time).toDateString() === today).length;
  const todayBlocks = state.activity.filter((a) => a.type === 'block' && new Date(a.time).toDateString() === today).length;
  const activePasses = state.passes.filter((p) => isPassActive(p)).length;
  const revenue = state.passes.reduce((s, p) => s + (p.price || 0), 0);
  $('stat-revenue').textContent = money(revenue);
  $('stat-active-pass').textContent = activePasses;
  $('stat-validated').textContent = todayValidated;
  $('stat-fraud-blocked').textContent = todayBlocks;

  const list = $('activity-list');
  list.innerHTML = '';
  if (state.activity.length === 0) {
    $('activity-empty').classList.remove('hidden');
  } else {
    $('activity-empty').classList.add('hidden');
  }
  const recent = [...state.activity].sort((a, b) => b.time - a.time).slice(0, 12);
  recent.forEach((a) => {
    const item = document.createElement('div');
    item.className = 'activity-item';
    const time = new Date(a.time).toLocaleString();
    let badge = '';
    if (a.type === 'validate') badge = '<span class="badge ok">Validated</span>';
    else if (a.type === 'block') badge = '<span class="badge block">Blocked</span>';
    else if (a.type === 'sale') badge = '<span class="badge sale">Sale</span>';
    item.innerHTML = `
      <span class="a-text">${escapeHtml(a.title)}</span>
      ${badge}
      <span class="a-time">${time}</span>
    `;
    list.appendChild(item);
  });
}

function renderRoutes() {
  const q = ($('route-search').value || '').toLowerCase();
  const container = $('route-grid');
  container.innerHTML = '';
  if (state.routes.length === 0) {
    $('routes-empty').classList.remove('hidden');
  } else {
    $('routes-empty').classList.add('hidden');
  }
  const filtered = state.routes.filter((r) => !q || r.name.toLowerCase().includes(q) || r.path.toLowerCase().includes(q));
  filtered.forEach((r) => {
    const card = document.createElement('div');
    card.className = 'route-card';
    card.innerHTML = `
      <div class="route-name">${escapeHtml(r.name)}</div>
      <div class="route-path">${escapeHtml(r.path)}</div>
      <div class="route-meta">
        <span>💲 ${money(r.fare)}</span>
        <span>🕒 ${r.time} min</span>
      </div>
      <div class="event-actions" style="display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn btn-danger btn-sm delete-route" data-id="${r.id}">Delete</button>
      </div>
    `;
    container.appendChild(card);
  });
}

// ---------- Pass status helpers ----------
function isPassActive(p) {
  if (p.used) return false;
  if (p.expiresAt && Date.now() > p.expiresAt) return false;
  return true;
}
function passStatus(p) {
  if (p.used) return { label: 'Consumed', cls: 'consumed' };
  if (p.expiresAt && Date.now() > p.expiresAt) return { label: 'Expired', cls: 'expired' };
  return { label: 'Active', cls: 'active-pass' };
}

function renderPassenger() {
  // Active card
  const active = state.passes.filter((p) => isPassActive(p))[0];
  const card = $('pass-card');
  if (active) {
    const status = passStatus(active);
    const route = state.routes.find((r) => r.id === active.routeId);
    card.className = 'pass-card valid-pass';
    card.innerHTML = `
      <h3>${escapeHtml(PASS_TYPES[active.type] ? PASS_TYPES[active.type].label : active.type)}</h3>
      <div class="route-txt">${route ? escapeHtml(route.name) : 'Any route'}</div>
      <div class="expiry-txt">Expires: ${new Date(active.expiresAt).toLocaleString()}</div>
      <button class="btn btn-block show-pass" data-id="${active.id}">Show QR</button>
    `;
    card.classList.remove('hidden');
  } else {
    card.classList.add('hidden');
  }

  // Grid of all passes
  const grid = $('my-passes-grid');
  grid.innerHTML = '';
  if (state.passes.length === 0) {
    $('passes-empty').classList.remove('hidden');
  } else {
    $('passes-empty').classList.add('hidden');
  }
  [...state.passes].sort((a, b) => b.issueDate - a.issueDate).forEach((p) => {
    const status = passStatus(p);
    const route = state.routes.find((r) => r.id === p.routeId);
    const item = document.createElement('div');
    item.className = 'pass-item';
    item.innerHTML = `
      <div class="pass-item-title">${escapeHtml(PASS_TYPES[p.type] ? PASS_TYPES[p.type].label : p.type)}</div>
      <div class="pass-item-route">${route ? escapeHtml(route.name) : 'Any route'}</div>
      <div class="pass-item-status"><span class="status-chip ${status.cls}">${status.label}</span></div>
      <div class="pass-item-meta">${money(p.price)} • ${p.code}</div>
    `;
    item.addEventListener('click', () => showPassDetail(p.id));
    grid.appendChild(item);
  });

  renderBuyRoutes();
}

function renderBuyRoutes() {
  const sel = $('buy-route');
  if (!sel) return;
  sel.innerHTML = '';
  state.routes.forEach((r) => {
    const opt = document.createElement('option');
    opt.value = r.id;
    opt.textContent = `${r.name} (${money(r.fare)})`;
    sel.appendChild(opt);
  });
}

function renderHistory() {
  const list = $('history-list');
  list.innerHTML = '';
  if (state.activity.length === 0) {
    $('history-empty').classList.remove('hidden');
  } else {
    $('history-empty').classList.add('hidden');
  }
  [...state.activity].sort((a, b) => b.time - a.time).slice(0, 30).forEach((a) => {
    const itemEl = document.createElement('div');
    itemEl.className = 'history-item';
    itemEl.innerHTML = `
      <div class="h-left">
        <span class="h-title">${escapeHtml(a.title)}</span>
        <span class="h-sub">${escapeHtml(a.detail || '')}</span>
      </div>
      <div class="h-right">${new Date(a.time).toLocaleString()}</div>
    `;
    list.appendChild(itemEl);
  });
}

// ---------- Routes CRUD ----------
function openRouteModal() {
  $('route-modal-title').textContent = 'Add Route';
  $('route-name').value = '';
  $('route-path').value = '';
  $('route-fare').value = '';
  $('route-time').value = 30;
  $('modal-route').classList.remove('hidden');
}
async function saveRoute() {
  const name = $('route-name').value.trim();
  const path = $('route-path').value.trim();
  const fare = parseFloat($('route-fare').value);
  const time = parseInt($('route-time').value, 10);
  if (!name || !path || isNaN(fare) || fare < 0 || isNaN(time) || time < 1) {
    showToast('Please fill all route fields correctly.', 'error');
    return;
  }
  state.routes.push({ id: uuid(), name, path, fare, time, created: Date.now() });
  closeModal('route');
  renderRoutes();
  await saveVault();
  showToast('Route added!', 'success');
}

// ---------- Ticket / pass code generation ----------
function createPassCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'TT-';
  const arr = new Uint32Array(8);
  crypto.getRandomValues(arr);
  for (let i = 0; i < 8; i++) code += chars[arr[i] % chars.length];
  return code;
}

// ---------- Purchase flow ----------
let pendingBuy = null;
function openBuyModal(type) {
  if (state.routes.length === 0) {
    showToast('No routes available. Add a route first.', 'error');
    return;
  }
  pendingBuy = type;
  const pt = PASS_TYPES[type];
  $('buy-modal-title').textContent = 'Purchase ' + pt.label;
  $('buy-type').value = pt.label;
  renderBuyRoutes();
  $('buy-route').value = state.routes[0].id;
  updateBuyPrice();
  $('buy-card').value = '';
  $('buy-error').classList.add('hidden');
  $('modal-buy').classList.remove('hidden');
}
function updateBuyPrice() {
  if (!pendingBuy) return;
  const routeId = $('buy-route').value;
  const route = state.routes.find((r) => r.id === routeId);
  const pt = PASS_TYPES[pendingBuy];
  const price = pendingBuy === 'single' && route ? route.fare : pt.price;
  $('buy-price').value = money(price);
}
async function confirmPurchase() {
  if (!pendingBuy) return;
  const routeId = $('buy-route').value;
  const cardNum = $('buy-card').value.trim().replace(/\D/g, '');
  if (cardNum.length < 12) {
    $('buy-error').textContent = 'Please enter a valid card number (simulated).';
    $('buy-error').classList.remove('hidden');
    return;
  }
  const route = state.routes.find((r) => r.id === routeId);
  const pt = PASS_TYPES[pendingBuy];
  const price = pendingBuy === 'single' && route ? route.fare : pt.price;

  // Simulate secure payment processing delay
  $('btn-buy-confirm').disabled = true;
  $('btn-buy-confirm').textContent = 'Processing...';
  await new Promise((res) => setTimeout(res, 900));
  $('btn-buy-confirm').disabled = false;
  $('btn-buy-confirm').textContent = 'Pay & Confirm';

  const now = Date.now();
  const expiresAt = pt.duration > 0 ? now + pt.duration * 3600 * 1000 : null;
  const pass = {
    id: uuid(),
    type: pendingBuy,
    routeId,
    code: createPassCode(),
    price,
    issueDate: now,
    expiresAt,
    used: false,
    consumedAt: null,
  };
  state.passes.push(pass);
  state.activity.push({
    time: now,
    type: 'sale',
    title: `Purchased ${pt.label}`,
    detail: `${route.name} • ${money(price)}`,
  });
  closeModal('buy');
  await saveVault();
  renderAll();
  showToast('Pass purchased!', 'success');
  showPassDetail(pass.id);
  pendingBuy = null;
}

// ---------- Pass detail / QR ----------
function showPassDetail(passId) {
  const p = state.passes.find((x) => x.id === passId);
  if (!p) return;
  const route = state.routes.find((r) => r.id === p.routeId);
  const status = passStatus(p);
  $('pass-modal-title').textContent = (PASS_TYPES[p.type] ? PASS_TYPES[p.type].label : p.type) + ' — Pass';
  const qrEl = $('qr-container');
  qrEl.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    new QRCode(qrEl, {
      text: JSON.stringify({ type: p.type, code: p.code, route: p.routeId }),
      width: 180,
      height: 180,
    });
  } else {
    qrEl.innerHTML = '<span style="color:#333">QR lib unavailable</span>';
  }
  $('pass-detail').innerHTML = `
    <div class="row"><span class="label">Code</span><span>${escapeHtml(p.code)}</span></div>
    <div class="row"><span class="label">Route</span><span>${route ? escapeHtml(route.name) : 'Any'}</span></div>
    <div class="row"><span class="label">Status</span><span class="status-chip ${status.cls}">${status.label}</span></div>
    <div class="row"><span class="label">Issued</span><span>${new Date(p.issueDate).toLocaleString()}</span></div>
    <div class="row"><span class="label">Expires</span><span>${p.expiresAt ? new Date(p.expiresAt).toLocaleString() : 'N/A'}</span></div>
    <div class="row"><span class="label">Price</span><span>${money(p.price)}</span></div>
    ${p.consumedAt ? `<div class="row"><span class="label">Consumed</span><span>${new Date(p.consumedAt).toLocaleString()}</span></div>` : ''}
  `;
  $('modal-pass').classList.remove('hidden');
}

// ---------- Verification / fraud prevention ----------
function verifyPass() {
  const codeInput = $('verify-code').value.trim().toUpperCase();
  const resultEl = $('verification-result');
  resultEl.className = 'verification-result';
  resultEl.innerHTML = '';
  if (!codeInput) {
    resultEl.classList.add('invalid');
    resultEl.textContent = 'Please enter a pass code.';
    return;
  }
  const pass = state.passes.find((p) => p.code.toUpperCase() === codeInput);
  if (!pass) {
    resultEl.classList.add('invalid');
    resultEl.textContent = '❌ Invalid pass — code not recognized.';
    logActivity('block', `Blocked unknown code ${codeInput}`, 'Fraud prevention');
    return;
  }
  state.activity.push({
    time: Date.now(),
    type: 'block',
    title: 'Blocked reuse attempt',
    detail: pass.code,
  });
  if (pass.used) {
    resultEl.classList.add('used');
    resultEl.textContent = '⚠️ Pass already used — fraudulent reuse blocked.';
    renderDashboard();
    saveVault();
    return;
  }
  if (pass.expiresAt && Date.now() > pass.expiresAt) {
    resultEl.classList.add('invalid');
    resultEl.textContent = '⛔ Pass expired — no longer valid.';
    logActivity('block', `Blocked expired pass ${pass.code}`, 'Expired');
    renderDashboard();
    saveVault();
    return;
  }
  // Valid — consume if single ride
  const pt = PASS_TYPES[pass.type];
  if (pt && pt.uses === 1) {
    pass.used = true;
    pass.consumedAt = Date.now();
  }
  const route = state.routes.find((r) => r.id === pass.routeId);
  resultEl.classList.add('valid');
  resultEl.innerHTML = `
    ✅ <strong>Valid pass!</strong><br/>
    Type: ${PASS_TYPES[pass.type] ? PASS_TYPES[pass.type].label : pass.type}<br/>
    Route: ${route ? escapeHtml(route.name) : 'Any'}<br/>
    Code: ${escapeHtml(pass.code)}<br/>
    ${pass.used ? '<br/><em>Single ride consumed.</em>' : ''}
  `;
  logActivity('validate', `Validated ${PASS_TYPES[pass.type] ? PASS_TYPES[pass.type].label : pass.type}`, pass.code);
  renderDashboard();
  saveVault();
  showToast('Pass validated.', 'success');
}
function logActivity(type, title, detail) {
  state.activity.push({ time: Date.now(), type, title, detail });
}

// ---------- Modal helpers ----------
function openModal(id) { $('modal-' + id).classList.remove('hidden'); }
function closeModal(id) {
  $('modal-' + id).classList.add('hidden');
  if (id === 'pass') $('qr-container').innerHTML = '';
  if (id === 'verify') $('verification-result').innerHTML = '';
}
function updateMeter(val, meterId) {
  const st = passwordStrength(val);
  const bar = document.querySelector('#' + meterId + ' .pw-meter-bar');
  if (bar) {
    bar.className = 'pw-meter-bar ' + st.cls;
    bar.style.width = st.score * 25 + '%';
  }
}

// ---------- Master password change ----------
async function changeMasterPassword() {
  const current = $('cp-current').value;
  const newPw = $('cp-new').value;
  const confirmPw = $('cp-confirm').value;
  $('cp-error').classList.add('hidden');
  try {
    const k = await deriveKey(current, base64ToBytes(state.settings.salt), state.settings.iterations);
    const test = await encryptWithKey(k, '__verify__');
    const dec = await decryptWithKey(k, test);
    if (dec !== '__verify__') throw new Error('bad');
  } catch (e) {
    $('cp-error').textContent = 'Current password is incorrect.';
    $('cp-error').classList.remove('hidden');
    return;
  }
  if (newPw.length < 8) { $('cp-error').textContent = 'New password must be at least 8 characters.'; $('cp-error').classList.remove('hidden'); return; }
  if (newPw !== confirmPw) { $('cp-error').textContent = 'New passwords do not match.'; $('cp-error').classList.remove('hidden'); return; }
  const newSalt = randomBytes(16);
  const newKey = await deriveKey(newPw, newSalt, state.settings.iterations);
  state.settings.salt = bytesToBase64(newSalt);
  state.masterKey = newKey;
  await saveVault();
  persistSettings();
  closeModal('changepw');
  $('cp-current').value = ''; $('cp-new').value = ''; $('cp-confirm').value = '';
  showToast('Master password updated.', 'success');
}

// ---------- Backup & restore ----------
async function exportVault() {
  if (!state.masterKey) return;
  const payload = {
    type: 'transittick-export', magic: EXPORT_MAGIC, version: EXPORT_VERSION,
    settings: { salt: state.settings.salt, iterations: state.settings.iterations },
    routes: state.routes, passes: state.passes, activity: state.activity, exportedAt: Date.now(),
  };
  const blob = await encrypt(JSON.stringify(payload));
  const blobData = { p: EXPORT_MAGIC, v: EXPORT_VERSION, iv: blob.iv, data: blob.data };
  const file = new Blob([JSON.stringify(blobData)], { type: 'application/json' });
  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = `transittick-backup-${new Date().toISOString().slice(0, 10)}.ttk`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Backup exported.', 'success');
}
async function importVault(file) {
  if (!file) return;
  const text = await file.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch (e) { showToast('Invalid backup file.', 'error'); return; }
  if (!parsed || parsed.p !== EXPORT_MAGIC) { showToast('Not a TransitTick backup file.', 'error'); return; }
  try {
    const payload = JSON.parse(await decrypt(parsed));
    if (!Array.isArray(payload.routes) || !Array.isArray(payload.passes)) throw new Error('bad');
    if (!confirm('This will REPLACE all current data with the backup. Continue?')) return;
    state.routes = payload.routes;
    state.passes = payload.passes;
    state.activity = payload.activity || [];
    renderAll();
    await saveVault();
    showToast('Backup imported.', 'success');
  } catch (e) {
    showToast('Could not decrypt backup — wrong master password.', 'error');
  }
}

// ---------- Event listeners ----------
function initListeners() {
  $('btn-setup').addEventListener('click', handleSetup);
  $('btn-login').addEventListener('click', handleLogin);
  $('login-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleLogin(); });
  $('setup-password').addEventListener('input', (e) => updateMeter(e.target.value, 'setup-meter'));

  // View switcher
  document.querySelectorAll('.view-btn').forEach((b) =>
    b.addEventListener('click', () => switchView(b.dataset.view))
  );
  // Tabs
  document.querySelectorAll('.tab').forEach((t) =>
    t.addEventListener('click', () => switchTab(t.dataset.tab))
  );

  $('btn-lock').addEventListener('click', lockVault);
  document.addEventListener('click', markActivity);
  document.addEventListener('keydown', markActivity);
  document.addEventListener('scroll', markActivity);

  // Routes
  $('btn-add-route').addEventListener('click', () => openRouteModal());
  $('btn-route-cancel').addEventListener('click', () => closeModal('route'));
  $('btn-route-save').addEventListener('click', saveRoute);
  $('route-search').addEventListener('input', renderRoutes);
  $('route-grid').addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    if (btn.classList.contains('delete-route')) {
      if (confirm('Delete this route? Existing passes remain.')) {
        state.routes = state.routes.filter((r) => r.id !== btn.dataset.id);
        renderRoutes();
        saveVault();
        showToast('Route deleted.');
      }
    }
  });

  // Buy
  document.querySelectorAll('.buy-btn').forEach((b) =>
    b.addEventListener('click', () => openBuyModal(b.dataset.type))
  );
  $('buy-route').addEventListener('change', updateBuyPrice);
  $('btn-buy-cancel').addEventListener('click', () => { pendingBuy = null; closeModal('buy'); });
  $('btn-buy-confirm').addEventListener('click', confirmPurchase);

  // Pass card QR
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.show-pass');
    if (btn) showPassDetail(btn.dataset.id);
  });

  // Verify
  $('btn-verify').addEventListener('click', verifyPass);
  $('verify-code').addEventListener('keydown', (e) => { if (e.key === 'Enter') verifyPass(); });
  $('verify-code').addEventListener('input', () => {
    const r = $('verification-result');
    r.className = 'verification-result';
    r.innerHTML = '';
  });

  $('btn-pass-close').addEventListener('click', () => closeModal('pass'));

  // Settings
  $('auto-lock-select').addEventListener('change', (e) => {
    state.settings.autoLock = Number(e.target.value);
    persistSettings();
    state.lastActivity = Date.now();
    updateLockTimer();
    showToast('Auto-lock setting saved.', 'success');
  });
  $('btn-change-password').addEventListener('click', () => {
    $('cp-current').value = ''; $('cp-new').value = ''; $('cp-confirm').value = '';
    $('cp-error').classList.add('hidden');
    $('modal-changepw').classList.remove('hidden');
  });
  $('btn-cp-cancel').addEventListener('click', () => closeModal('changepw'));
  $('btn-cp-save').addEventListener('click', changeMasterPassword);
  $('btn-wipe-data').addEventListener('click', () => {
    if (confirm('This will permanently delete ALL routes, passes and history. Continue?')) {
      state.routes = []; state.passes = []; state.activity = [];
      renderAll();
      saveVault();
      showToast('All data wiped.', 'success');
    }
  });

  // Backup
  $('btn-export').addEventListener('click', exportVault);
  $('btn-import').addEventListener('click', () => $('import-file').click());
  $('import-file').addEventListener('change', (e) => {
    importVault(e.target.files[0]);
    e.target.value = '';
  });
}

// ---------- Init ----------
function init() {
  initListeners();
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    try {
      state.settings = JSON.parse(stored);
      $('setup-form').classList.add('hidden');
      $('login-form').classList.remove('hidden');
    } catch (e) {
      state.settings = null;
      clearStorage();
    }
  }
}
document.addEventListener('DOMContentLoaded', init);
