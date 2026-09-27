// LaunchFleet Frontend

// ───────── Tauri API access ─────────
let invoke, ask, message;

function fatal(msg) {
  const loading = document.getElementById('loading');
  if (loading) {
    loading.textContent = '';
    const pre = document.createElement('pre');
    pre.className = 'fatal';
    pre.textContent = msg;
    loading.appendChild(pre);
  }
}

window.addEventListener('error', (e) => {
  fatal(`JS Error:\n${e.message}\nat ${e.filename}:${e.lineno}:${e.colno}\n\n${e.error?.stack ?? ''}`);
});
window.addEventListener('unhandledrejection', (e) => {
  fatal(`Unhandled promise rejection:\n${e.reason?.message ?? e.reason}\n\n${e.reason?.stack ?? ''}`);
});

try {
  if (window.__TAURI__?.core) {
    invoke = window.__TAURI__.core.invoke;
  } else if (window.__TAURI_INTERNALS__?.invoke) {
    invoke = window.__TAURI_INTERNALS__.invoke;
  } else {
    throw new Error('Tauri global API not available.');
  }

  if (window.__TAURI__?.dialog) {
    ask = window.__TAURI__.dialog.ask;
    message = window.__TAURI__.dialog.message;
  } else {
    ask = async (msg) => window.confirm(msg);
    message = async (msg) => window.alert(msg);
  }
} catch (e) {
  fatal(`Tauri API init failed:\n${e.message}`);
  throw e;
}

// ───────── State ─────────
let allItems = [];
let filteredItems = [];
let currentTab = 'all';
let searchQuery = '';
let filters = {
  thirdParty: false,
  enabled: false,
  orphans: false,
  mine: true,
};
let systemMode = false;
let selectedId = null;

const els = {};
for (const id of [
  'search', 'list', 'empty', 'loading', 'refresh-btn', 'system-mode-btn', 'sys-mode-dot',
  'status-text', 'toast', 'tabs', 'filter-third-party', 'filter-enabled', 'filter-orphans',
  'filter-mine', 'detail-modal', 'detail-title', 'detail-body', 'detail-close', 'detail-enable',
  'detail-disable', 'detail-delete', 'detail-reveal', 'detail-system-settings', 'welcome-modal',
  'welcome-close', 'quarantine-btn', 'quarantine-modal', 'quarantine-close', 'quarantine-list',
  'count-quarantine',
]) {
  els[id] = document.getElementById(id);
}

const selectedItem = () => allItems.find(i => i.id === selectedId) ?? null;

// ───────── Helpers ─────────
let toastTimer = null;
function showToast(msg, type = 'success', duration = 3000) {
  els['toast'].textContent = msg;
  els['toast'].className = `toast ${type}`;
  els['toast'].classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els['toast'].classList.add('hidden'), duration);
}

function getSourceBadge(item) {
  if (item.is_apple) return { label: 'APPLE', class: 'source-APPLE' };
  if (item.foreign_user) return { label: 'OTHER USER', class: 'source-FOREIGN' };
  if (item.requires_sudo) return { label: 'SYSTEM', class: 'source-SYSTEM' };
  return { label: 'USER', class: 'source-USER' };
}

/// Why an item can't be switched right now, or null if it can.
function toggleBlockedReason(item) {
  if (item.is_apple) return 'Apple system item — read-only';
  if (item.foreign_user) return `Belongs to another user account (uid ${item.uid}) — cannot be changed from this session`;
  if (item.toggle_method === 'ReadOnly') return 'This item cannot be modified by LaunchFleet';
  if (item.toggle_method === 'SystemSettingsOnly') return 'Use “Open in System Settings”';
  if (item.requires_sudo && !systemMode) return 'Enable System Mode to modify this';
  if (item.status === 'Unknown') return 'Current state is unknown — use the details panel to choose Enable or Disable';
  return null;
}

function isActionable(item) {
  return !item.is_apple && !item.foreign_user && item.toggle_method !== 'ReadOnly';
}

function impactLabel(impact) {
  return impact.toUpperCase().slice(0, 4);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDate(secs) {
  if (!secs) return '—';
  return new Date(secs * 1000).toLocaleString();
}

// ───────── Rendering ─────────
function applyFilters() {
  const q = searchQuery.toLowerCase();

  filteredItems = allItems.filter(item => {
    if (currentTab !== 'all' && item.item_type !== currentTab) return false;
    if (q) {
      const hay = `${item.label} ${item.name} ${item.program ?? ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (filters.thirdParty && item.is_apple) return false;
    if (filters.enabled && item.status !== 'Enabled') return false;
    if (filters.orphans && !item.is_orphan) return false;
    if (filters.mine && item.foreign_user) return false;
    return true;
  });

  renderList();
  updateCounts();
  updateStatus();
}

function renderList() {
  els['list'].textContent = '';

  if (filteredItems.length === 0) {
    els['empty'].classList.remove('hidden');
    return;
  }
  els['empty'].classList.add('hidden');

  const frag = document.createDocumentFragment();

  for (const item of filteredItems) {
    const isOn = item.status === 'Enabled';
    const blocked = toggleBlockedReason(item);
    const source = getSourceBadge(item);
    const running = item.running === 'Running';

    const row = document.createElement('div');
    row.className = `item-row${blocked ? ' locked' : ''}`;
    row.dataset.id = item.id;
    row.setAttribute('role', 'listitem');

    // A real <button role="switch"> so VoiceOver announces state and the
    // keyboard can operate it — the old markup was an inert <div>.
    const sw = document.createElement('button');
    sw.type = 'button';
    sw.className = `toggle-switch${isOn ? ' on' : ''}${blocked ? ' disabled' : ''}`;
    sw.setAttribute('role', 'switch');
    sw.setAttribute('aria-checked', String(isOn));
    sw.setAttribute('aria-label', `${isOn ? 'Disable' : 'Enable'} ${item.name}`);
    sw.dataset.action = 'toggle';
    if (blocked) {
      sw.disabled = true;
      sw.title = blocked;
    }

    const info = document.createElement('div');
    info.className = 'item-info';

    const nameEl = document.createElement('div');
    nameEl.className = 'item-name';
    nameEl.append(item.name);
    if (item.is_apple) nameEl.append(badge('🔒', 'Apple system item (read-only)', 'lock-icon'));
    if (item.is_orphan) nameEl.append(badge('⚠', 'Orphaned — binary not found', 'warn-icon'));
    if (item.foreign_user) nameEl.append(badge('👤', `Belongs to uid ${item.uid}`, 'user-icon'));

    const labelEl = document.createElement('div');
    labelEl.className = 'item-label';
    labelEl.textContent = item.label;

    info.append(nameEl, labelEl);

    const impact = document.createElement('div');
    impact.className = `impact-badge impact-${item.impact}`;
    impact.textContent = impactLabel(item.impact);

    const src = document.createElement('div');
    src.className = `source-badge ${source.class}`;
    src.textContent = source.label;

    const run = document.createElement('div');
    run.className = `run-state${running ? ' running' : ''}`;
    // Daemon state is unknown without System Mode; say so instead of
    // rendering a misleading "idle".
    run.textContent = item.running === 'Unknown' ? '· unknown' : (running ? '● running' : '○ idle');
    if (item.running === 'Unknown' && item.requires_sudo && !systemMode) {
      run.title = 'Enable System Mode to read system-domain service state';
    }

    const details = document.createElement('button');
    details.type = 'button';
    details.className = 'row-details';
    details.dataset.action = 'details';
    details.setAttribute('aria-label', `Details for ${item.name}`);
    details.textContent = 'ⓘ';

    row.append(sw, info, impact, src, run, details);
    frag.append(row);
  }

  els['list'].append(frag);
}

function badge(text, title, cls) {
  const s = document.createElement('span');
  s.className = cls;
  s.title = title;
  s.textContent = ` ${text}`;
  return s;
}

function updateCounts() {
  const counts = { all: allItems.length };
  for (const item of allItems) {
    counts[item.item_type] = (counts[item.item_type] || 0) + 1;
  }
  const map = {
    'count-all': 'all',
    'count-login': 'LoginItem',
    'count-user': 'UserLaunchAgent',
    'count-system': 'SystemLaunchAgent',
    'count-daemon': 'LaunchDaemon',
    'count-hook': 'LoginHook',
    'count-cron': 'CronJob',
  };
  for (const [elId, key] of Object.entries(map)) {
    const el = document.getElementById(elId);
    if (el) el.textContent = counts[key] ?? 0;
  }
}

function updateStatus() {
  const total = allItems.length;
  const enabled = allItems.filter(i => i.status === 'Enabled').length;
  const running = allItems.filter(i => i.running === 'Running').length;
  const orphans = allItems.filter(i => i.is_orphan).length;
  els['status-text'].textContent =
    `${total} items · ${enabled} enabled · ${running} running` +
    (orphans > 0 ? ` · ${orphans} orphan${orphans > 1 ? 's' : ''}` : '') +
    ` · showing ${filteredItems.length}`;
}

// ───────── Detail modal ─────────
function toggleMethodDescription(method) {
  return {
    Launchctl: 'launchctl enable/disable',
    AppleScript: 'AppleScript (System Events)',
    SMLoginItem: 'SMLoginItemSetEnabled',
    SystemSettingsOnly: 'System Settings only',
    LoginHook: 'defaults (loginwindow)',
    ReadOnly: 'read-only',
  }[method] ?? method;
}

function showDetail(item) {
  selectedId = item.id;
  els['detail-title'].textContent = item.name || item.label;

  const rows = [];
  if (item.is_orphan) rows.push(['⚠ Warning', 'Binary/path not found — this item is orphaned']);
  if (item.foreign_user) rows.push(['⚠ Other user', `This record belongs to uid ${item.uid} and cannot be changed from your session`]);

  rows.push(['Label', item.label]);
  if (item.bundle_id) rows.push(['Bundle ID', item.bundle_id]);
  rows.push(['Type', item.item_type.replace(/([A-Z])/g, ' $1').trim()]);
  if (item.btm_type) rows.push(['BTM Type', item.btm_type]);
  if (item.parent_app) rows.push(['Parent App', item.parent_app]);
  rows.push(['Status', item.status]);
  rows.push(['Running', item.running === 'Unknown' ? 'Unknown (needs System Mode)' : item.running]);
  rows.push(['Impact', item.impact]);
  rows.push(['Source', item.is_apple ? 'Apple (read-only)' : (item.requires_sudo ? 'System (needs System Mode)' : 'User')]);
  rows.push(['Toggle via', toggleMethodDescription(item.toggle_method)]);
  rows.push(['Program', item.program || '—']);
  if (item.arguments?.length) rows.push(['Arguments', item.arguments.join(' ')]);
  if (item.working_directory) rows.push(['Working Dir', item.working_directory]);
  if (item.run_at_load !== null && item.run_at_load !== undefined) rows.push(['RunAtLoad', item.run_at_load ? 'Yes' : 'No']);
  if (item.keep_alive !== null && item.keep_alive !== undefined) rows.push(['KeepAlive', item.keep_alive ? 'Yes' : 'No']);
  if (item.start_interval) rows.push(['Interval', `${item.start_interval}s`]);
  if (item.plist_path) rows.push(['Plist Path', item.plist_path]);
  if (item.description) rows.push(['Description', item.description]);

  els['detail-body'].innerHTML = rows.map(([k, v]) =>
    `<div class="detail-row">
      <div class="detail-key">${escapeHtml(k)}</div>
      <div class="detail-value">${escapeHtml(String(v))}</div>
    </div>`
  ).join('');

  const blocked = toggleBlockedReason(item);
  const actionable = isActionable(item);

  // Explicit Enable / Disable instead of a single "Toggle": the backend
  // refuses to guess when the current state is Unknown.
  const sysOnly = item.toggle_method === 'SystemSettingsOnly';
  const needsSysMode = item.requires_sudo && !systemMode;
  const canAct = actionable && !sysOnly && !needsSysMode;

  els['detail-enable'].disabled = !canAct || item.status === 'Enabled';
  els['detail-disable'].disabled = !canAct || item.status === 'Disabled';
  els['detail-delete'].disabled = !canAct || !item.plist_path;

  const hint = blocked ?? '';
  els['detail-enable'].title = hint;
  els['detail-disable'].title = hint;
  els['detail-delete'].title = item.plist_path ? hint : 'Only items backed by a plist file can be removed';

  els['detail-reveal'].disabled = !(item.path || item.program || item.plist_path);
  els['detail-system-settings'].style.display =
    (item.item_type === 'LoginItem' || sysOnly) ? '' : 'none';

  els['detail-modal'].classList.remove('hidden');
  els['detail-close'].focus();
}

function hideDetail() {
  els['detail-modal'].classList.add('hidden');
  selectedId = null;
}

// ───────── Actions ─────────
async function loadItems(initial = false) {
  if (initial) {
    els['loading'].classList.remove('hidden');
    els['loading'].textContent = 'Loading startup items…';
  }
  try {
    const result = await invoke('list_items');
    if (!Array.isArray(result)) throw new Error('list_items did not return an array');
    allItems = result;
    els['loading'].classList.add('hidden');
    applyFilters();
    await refreshQuarantineCount();
  } catch (e) {
    fatal(`Failed to load items:\n${e?.message ?? e}`);
    showToast('Failed to load: ' + (e?.message ?? e), 'error', 8000);
  }
}

async function refreshItems(quiet = false) {
  try {
    allItems = await invoke('refresh_items');
    applyFilters();
    await refreshQuarantineCount();
    if (!quiet) showToast('Refreshed');
  } catch (e) {
    showToast('Refresh failed: ' + (e?.message ?? e), 'error');
  }
}

async function handleResult(result) {
  if (result.success) {
    showToast(result.message, 'success', 5000);
    await refreshItems(true);
    const updated = selectedItem();
    if (updated) showDetail(updated);
    return;
  }

  switch (result.kind) {
    case 'SystemSettingsRequired': {
      const open = await ask(`${result.message}\n\nOpen System Settings now?`, {
        title: 'System Settings required',
        okLabel: 'Open System Settings',
        cancelLabel: 'Cancel',
      });
      if (open) await openLoginItemsSettings();
      break;
    }
    case 'SudoRequired': {
      const enable = await ask(
        `${result.message}\n\nEnable System Mode now? You will be asked to authorize once.`,
        { title: 'System Mode required', okLabel: 'Enable System Mode', cancelLabel: 'Cancel' }
      );
      if (enable) await enableSystemMode();
      break;
    }
    case 'NotToggleable':
      await message(result.message, { title: 'Cannot modify', kind: 'info' });
      break;
    default:
      // Real failures are now surfaced verbatim; they used to be hidden
      // behind an unconditional success toast.
      await message(result.message, { title: 'Action failed', kind: 'error' });
  }
}

async function setEnabled(item, enabled) {
  try {
    const result = await invoke('set_item_enabled', { id: item.id, enabled });
    await handleResult(result);
  } catch (e) {
    showToast('Action failed: ' + (e?.message ?? e), 'error', 5000);
  }
}

async function toggleItem(item) {
  const blocked = toggleBlockedReason(item);
  if (blocked) {
    if (item.requires_sudo && !systemMode) {
      const enable = await ask(
        `“${item.name}” is a system-level item.\n\nEnable System Mode now? You will be asked to authorize once.`,
        { title: 'System Mode required', okLabel: 'Enable System Mode', cancelLabel: 'Cancel' }
      );
      if (enable) await enableSystemMode();
      return;
    }
    await message(blocked, { title: 'Cannot modify', kind: 'info' });
    return;
  }

  try {
    const result = await invoke('toggle_item', { id: item.id });
    await handleResult(result);
  } catch (e) {
    showToast('Action failed: ' + (e?.message ?? e), 'error', 5000);
  }
}

async function openLoginItemsSettings() {
  try {
    await invoke('open_login_items_settings');
  } catch (e) {
    showToast('Could not open System Settings: ' + (e?.message ?? e), 'error');
  }
}

async function revealInFinder(item) {
  const path = item.path || item.program || item.plist_path;
  if (!path) return showToast('No file path to reveal', 'error');
  try {
    await invoke('reveal_in_finder', { path });
  } catch (e) {
    showToast('Could not reveal: ' + (e?.message ?? e), 'error');
  }
}

async function deleteItem(item) {
  const confirmed = await ask(
    `Remove “${item.name}”?\n\nLabel: ${item.label}\n\n` +
    `The plist will be moved to LaunchFleet's quarantine, not deleted. ` +
    `You can restore it from the Quarantine panel.`,
    { title: 'Confirm removal', okLabel: 'Remove', cancelLabel: 'Cancel', kind: 'warning' }
  );
  if (!confirmed) return;

  try {
    const result = await invoke('delete_item', { id: item.id });
    if (result.success) {
      showToast(result.message, 'success', 6000);
      hideDetail();
      await refreshItems(true);
    } else {
      await handleResult(result);
    }
  } catch (e) {
    showToast('Removal failed: ' + (e?.message ?? e), 'error', 5000);
  }
}

async function enableSystemMode() {
  if (systemMode) return;
  els['system-mode-btn'].disabled = true;
  try {
    await invoke('enable_system_mode');
    systemMode = true;
    els['sys-mode-dot'].classList.replace('off', 'on');
    els['system-mode-btn'].setAttribute('aria-pressed', 'true');
    els['system-mode-btn'].title = 'System Mode is active for this session';
    showToast('System Mode enabled');
    // Re-scan: daemon running state is only readable with root.
    await refreshItems(true);
  } catch (e) {
    // The backend now verifies the helper really is root, so this genuinely
    // means System Mode is off — it no longer reports success and then fails
    // silently on every subsequent action.
    await message(String(e?.message ?? e), { title: 'System Mode not enabled', kind: 'error' });
  } finally {
    els['system-mode-btn'].disabled = false;
  }
}

// ───────── Quarantine ─────────
async function refreshQuarantineCount() {
  try {
    const entries = await invoke('list_quarantined');
    els['count-quarantine'].textContent = entries.length;
    els['quarantine-btn'].classList.toggle('has-items', entries.length > 0);
  } catch { /* non-critical */ }
}

async function showQuarantine() {
  let entries = [];
  try {
    entries = await invoke('list_quarantined');
  } catch (e) {
    showToast('Could not read quarantine: ' + (e?.message ?? e), 'error');
    return;
  }

  els['quarantine-list'].textContent = '';

  if (entries.length === 0) {
    const p = document.createElement('p');
    p.className = 'empty-state';
    p.textContent = 'Nothing in quarantine.';
    els['quarantine-list'].append(p);
  } else {
    for (const entry of entries) {
      const row = document.createElement('div');
      row.className = 'quarantine-row';

      const info = document.createElement('div');
      info.className = 'item-info';
      const n = document.createElement('div');
      n.className = 'item-name';
      n.textContent = entry.name;
      const l = document.createElement('div');
      l.className = 'item-label';
      l.textContent = `${entry.original_path} · removed ${formatDate(entry.removed_at)}`;
      info.append(n, l);

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-primary';
      btn.textContent = 'Restore';
      btn.addEventListener('click', () => restoreEntry(entry));

      row.append(info, btn);
      els['quarantine-list'].append(row);
    }
  }

  els['quarantine-modal'].classList.remove('hidden');
  els['quarantine-close'].focus();
}

async function restoreEntry(entry) {
  try {
    const result = await invoke('restore_quarantined', { id: entry.id });
    if (result.success) {
      showToast(`Restored “${entry.name}”`, 'success', 5000);
      await refreshItems(true);
      await showQuarantine();
    } else {
      await message(result.message, { title: 'Restore failed', kind: 'error' });
    }
  } catch (e) {
    showToast('Restore failed: ' + (e?.message ?? e), 'error');
  }
}

function hideQuarantine() {
  els['quarantine-modal'].classList.add('hidden');
}

// ───────── Event handlers ─────────
let searchTimer = null;
els['search'].addEventListener('input', e => {
  const v = e.target.value;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { searchQuery = v; applyFilters(); }, 120);
});

els['refresh-btn'].addEventListener('click', () => refreshItems());
els['system-mode-btn'].addEventListener('click', enableSystemMode);
els['quarantine-btn'].addEventListener('click', showQuarantine);
els['quarantine-close'].addEventListener('click', hideQuarantine);
document.querySelector('#quarantine-modal .modal-backdrop').addEventListener('click', hideQuarantine);

els['tabs'].addEventListener('click', e => {
  const tab = e.target.closest('.tab');
  if (!tab) return;
  for (const t of document.querySelectorAll('.tab')) {
    t.classList.remove('active');
    t.removeAttribute('aria-current');
  }
  tab.classList.add('active');
  tab.setAttribute('aria-current', 'true');
  currentTab = tab.dataset.filter;
  applyFilters();
});

const filterMap = {
  'filter-third-party': 'thirdParty',
  'filter-enabled': 'enabled',
  'filter-orphans': 'orphans',
  'filter-mine': 'mine',
};
for (const [elId, key] of Object.entries(filterMap)) {
  els[elId].addEventListener('change', e => {
    filters[key] = e.target.checked;
    applyFilters();
  });
}

els['list'].addEventListener('click', e => {
  const row = e.target.closest('.item-row');
  if (!row) return;
  const item = allItems.find(i => i.id === row.dataset.id);
  if (!item) return;

  if (e.target.closest('[data-action="toggle"]')) {
    e.stopPropagation();
    toggleItem(item);
    return;
  }
  showDetail(item);
});

els['detail-close'].addEventListener('click', hideDetail);
document.querySelector('#detail-modal .modal-backdrop').addEventListener('click', hideDetail);
els['detail-enable'].addEventListener('click', () => { const i = selectedItem(); if (i) setEnabled(i, true); });
els['detail-disable'].addEventListener('click', () => { const i = selectedItem(); if (i) setEnabled(i, false); });
els['detail-delete'].addEventListener('click', () => { const i = selectedItem(); if (i) deleteItem(i); });
els['detail-reveal'].addEventListener('click', () => { const i = selectedItem(); if (i) revealInFinder(i); });
els['detail-system-settings'].addEventListener('click', openLoginItemsSettings);

els['welcome-close'].addEventListener('click', () => {
  els['welcome-modal'].classList.add('hidden');
  localStorage.setItem('welcomeShown', '1');
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if (!els['detail-modal'].classList.contains('hidden')) hideDetail();
    else if (!els['quarantine-modal'].classList.contains('hidden')) hideQuarantine();
    else if (!els['welcome-modal'].classList.contains('hidden')) els['welcome-modal'].classList.add('hidden');
  }
  if (e.key === '/' && document.activeElement !== els['search']) {
    e.preventDefault();
    els['search'].focus();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'r') {
    e.preventDefault();
    refreshItems();
  }
});

// ───────── Init ─────────
async function init() {
  if (!localStorage.getItem('welcomeShown')) {
    els['welcome-modal'].classList.remove('hidden');
  }
  await loadItems(true);
}

init();
