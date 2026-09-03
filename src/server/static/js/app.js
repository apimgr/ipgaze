/**
 * ipgaze — client-side enhancements
 * Per AI.md PART 16: ONE file, no frameworks, no bundlers, CSS-first.
 * All handlers bound via data-action delegation — inline onclick is blocked by CSP.
 */

// ============================================================================
// Cookie helpers — server-readable; localStorage is never load-bearing
// ============================================================================

// getCookie reads a cookie value by name; returns "" if absent.
function getCookie(name) {
  const match = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : '';
}

// setCookie writes a cookie with Secure added automatically on HTTPS.
function setCookie(name, value, maxAge, sameSite) {
  let c = name + '=' + encodeURIComponent(value) + '; path=/; max-age=' + maxAge + '; SameSite=' + (sameSite || 'Lax');
  if (location.protocol === 'https:') { c += '; Secure'; }
  document.cookie = c;
}

// ============================================================================
// CSRF — double-submit cookie pattern per AI.md PART 16
// Reads the csrf_token cookie and attaches it to all state-changing requests.
// ============================================================================

function getCSRFToken() {
  return getCookie('csrf_token');
}

// apiFetch wraps fetch, injecting X-CSRF-Token on POST/PUT/PATCH/DELETE.
async function apiFetch(url, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  const method = (opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const token = getCSRFToken();
    if (token) { opts.headers['X-CSRF-Token'] = token; }
  }
  return fetch(url, opts);
}

// apiGet performs a GET request; no CSRF token needed for reads.
async function apiGet(endpoint) {
  try {
    const response = await fetch(endpoint);
    const data = await response.json();
    if (!response.ok || !data.ok) { throw new Error(data.error || 'HTTP ' + response.status); }
    return data;
  } catch (err) {
    showToast(i18nStr('i18nErrorPrefix', 'Error: ') + err.message, 'error');
    throw err;
  }
}

// apiPost performs a POST with CSRF token header and JSON body.
async function apiPost(endpoint, body) {
  try {
    const response = await apiFetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok || !data.ok) { throw new Error(data.error || 'HTTP ' + response.status); }
    return data;
  } catch (err) {
    showToast(i18nStr('i18nErrorPrefix', 'Error: ') + err.message, 'error');
    throw err;
  }
}

// ============================================================================
// i18n bridge — JS has no {{t}} template access, so server-rendered strings
// are read from data-i18n-* attributes on #toast-container (populated by
// base.tmpl via {{t .Lang "key"}}) rather than hardcoded as literal English.
// ============================================================================

// i18nStr reads a translated string from #toast-container's dataset;
// falls back to the given English string if the attribute is missing.
function i18nStr(key, fallback) {
  const container = document.getElementById('toast-container');
  return (container && container.dataset[key]) || fallback;
}

// ============================================================================
// Theme — stored in the `theme` cookie so the server renders class on <html>
// without init JS and without FOUC. localStorage is never used for theme.
// Three-way cycle: dark → light → auto → dark
// ============================================================================

// THEME_CYCLE mirrors the server's NextTheme() (src/server/handler/pages.go)
// so the JS-enhanced and no-JS paths always agree on what "next" means.
const THEME_CYCLE = ['dark', 'light', 'auto'];

// currentTheme reads the mode actually in effect from the live <html> class
// rather than from the form value rendered once at page load — the rendered
// value goes stale after the first JS-driven switch, which is what makes a
// naive toggle "stick" after one click.
function currentTheme() {
  const match = document.documentElement.className.match(/theme-(dark|light|auto)/);
  return match ? match[1] : 'dark';
}

// setTheme replaces the entire theme class on <html>, persists the cookie,
// and re-points the toggle form at the mode that now comes next.
function setTheme(theme) {
  document.documentElement.className = 'theme-' + theme;
  setCookie('theme', theme, 31536000, 'Lax');
  const icon = document.querySelector('.theme-icon');
  if (icon) {
    if (theme === 'light') { icon.textContent = '☀️'; }
    else if (theme === 'auto') { icon.textContent = '🔄'; }
    else { icon.textContent = '🌙'; }
  }
  const next = THEME_CYCLE[(THEME_CYCLE.indexOf(theme) + 1) % THEME_CYCLE.length];
  document.querySelectorAll('.theme-toggle-form input[name="theme"]').forEach(function(input) {
    input.value = next;
  });
}

// toggleTheme cycles dark → light → auto → dark from the live document state.
function toggleTheme() {
  const next = THEME_CYCLE[(THEME_CYCLE.indexOf(currentTheme()) + 1) % THEME_CYCLE.length];
  setTheme(next);
  const labels = {
    dark: i18nStr('i18nThemeDark', 'dark'),
    light: i18nStr('i18nThemeLight', 'light'),
    auto: i18nStr('i18nThemeAuto', 'system')
  };
  showToast(i18nStr('i18nThemeTogglePrefix', 'Theme: ') + (labels[next] || next), 'info', 2000);
}

// initThemeToggleForms is progressive enhancement only: the toggle is a real
// form submit that already works with zero JS (POST /server/preferences), so
// this only intercepts the submit to switch in place without a page reload.
function initThemeToggleForms() {
  document.querySelectorAll('.theme-toggle-form').forEach(function(form) {
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      toggleTheme();
    });
  });
}

// ============================================================================
// Toast notifications
// ============================================================================

// Toast queue — AI.md PART 16 "Toast Behavior Rules": max 5 visible at
// once, older toasts queue until space is available (newest still renders
// on top within the visible set once its turn comes).
let toastQueue = [];
let toastIdSeq = 0;
const TOAST_MAX_VISIBLE = 5;

// showToast enqueues a notification and returns its ID for programmatic
// control (dismissToast). duration 0 = no auto-dismiss. Default durations
// by type: success/info = 3s, warning = 5s, error = no auto-dismiss.
function showToast(message, type, duration) {
  type = type || 'info';
  if (duration === undefined) {
    if (type === 'error') { duration = 0; }
    else if (type === 'warning') { duration = 5000; }
    else { duration = 3000; }
  }
  const id = 'toast-' + (++toastIdSeq);
  toastQueue.push({ id: id, message: message, type: type, duration: duration });
  processToastQueue();
  return id;
}

function getToastContainer() {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.setAttribute('role', 'region');
    container.setAttribute('aria-label', i18nStr('i18nToastRegionLabel', 'Notifications'));
    container.setAttribute('aria-live', 'polite');
    document.body.appendChild(container);
  }
  return container;
}

// processToastQueue renders queued toasts while under the max-visible limit.
function processToastQueue() {
  const container = getToastContainer();
  while (container.children.length < TOAST_MAX_VISIBLE && toastQueue.length > 0) {
    renderToast(container, toastQueue.shift());
  }
}

function renderToast(container, item) {
  const toast = document.createElement('div');
  toast.id = item.id;
  toast.className = 'toast toast-' + item.type;
  toast.setAttribute('role', 'alert');
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const icon = document.createElement('span');
  icon.className = 'toast-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = icons[item.type] || 'ℹ️';
  const msg = document.createElement('span');
  msg.className = 'toast-message';
  msg.textContent = item.message;
  const closeBtn = document.createElement('button');
  closeBtn.className = 'toast-close';
  closeBtn.setAttribute('aria-label', i18nStr('i18nToastClose', 'Close notification'));
  closeBtn.textContent = '×';
  closeBtn.addEventListener('click', function() { removeToast(toast); });
  const progress = document.createElement('div');
  progress.className = 'toast-progress';
  toast.appendChild(icon);
  toast.appendChild(msg);
  toast.appendChild(closeBtn);
  toast.appendChild(progress);
  container.appendChild(toast);
  if (item.duration > 0) {
    progress.style.animationDuration = item.duration + 'ms';
    progress.classList.add('toast-progress-active');
    let remaining = item.duration;
    let startedAt = Date.now();
    let timer = setTimeout(function() { removeToast(toast); }, remaining);
    // Pause on hover, resume with the remaining time on mouseleave —
    // hovering pauses the countdown, it does not cancel it.
    toast.addEventListener('mouseenter', function() {
      clearTimeout(timer);
      remaining -= Date.now() - startedAt;
      progress.style.animationPlayState = 'paused';
    });
    toast.addEventListener('mouseleave', function() {
      if (remaining <= 0) { removeToast(toast); return; }
      startedAt = Date.now();
      timer = setTimeout(function() { removeToast(toast); }, remaining);
      progress.style.animationPlayState = 'running';
    });
  }
}

// removeToast slides the toast out, removes it, then promotes the next
// queued toast (if any) into the now-free visible slot.
function removeToast(toast) {
  if (!toast || !toast.isConnected) { return; }
  toast.style.animation = 'slideOut 0.3s ease';
  setTimeout(function() {
    toast.remove();
    processToastQueue();
  }, 300);
}

// dismissToast removes a specific toast (visible or still queued) by the ID
// returned from showToast.
function dismissToast(id) {
  toastQueue = toastQueue.filter(function(item) { return item.id !== id; });
  const el = document.getElementById(id);
  if (el) { removeToast(el); }
}

// dismissAllToasts clears the queue and removes all visible toasts immediately.
function dismissAllToasts() {
  toastQueue = [];
  const container = document.getElementById('toast-container');
  if (!container) { return; }
  Array.from(container.children).forEach(function(el) { el.remove(); });
}

// Escape dismisses the topmost (last-added) visible toast.
document.addEventListener('keydown', function(e) {
  if (e.key !== 'Escape') { return; }
  const container = document.getElementById('toast-container');
  if (!container || !container.lastElementChild) { return; }
  removeToast(container.lastElementChild);
});

// ============================================================================
// Modal helpers — native <dialog> element; never alert()/confirm()/prompt()
// ============================================================================

function openModal(id) {
  const el = document.getElementById(id);
  if (el && el.showModal) { el.showModal(); }
}

function closeModal(id) {
  if (id) {
    const el = document.getElementById(id);
    if (el) { el.close(); }
  } else {
    document.querySelectorAll('dialog[open]').forEach(function(d) { d.close(); });
  }
}

// Backdrop click closes the dialog (AI.md PART 16 "Modal Behavior"). Escape
// key close and focus trap are handled natively by <dialog>/showModal().
// A click lands on the <dialog> element itself only when it hits the
// ::backdrop area — clicks inside the dialog's content hit a child element.
document.addEventListener('click', function(e) {
  if (e.target.tagName === 'DIALOG' && e.target.hasAttribute('open')) {
    e.target.close();
  }
});

// ============================================================================
// Copy buttons — .copy-btn class with data-copy attribute
// In-button feedback: .copied class + icon/text swap for 2s
// ============================================================================

function initCopyButtons() {
  document.addEventListener('click', function(e) {
    const btn = e.target.closest('.copy-btn');
    if (!btn) { return; }
    e.preventDefault();
    const text = btn.dataset.copy;
    if (!text) { return; }
    const doFeedback = function() {
      const icon = btn.querySelector('.copy-icon');
      const label = btn.querySelector('.copy-text');
      const copied = btn.dataset.copiedLabel || 'Copied!';
      const restore = [];
      if (icon) { restore.push([icon, icon.textContent]); icon.textContent = '✓'; }
      if (label) { restore.push([label, label.textContent]); label.textContent = copied; }
      if (!icon && !label) { restore.push([btn, btn.textContent]); btn.textContent = '✓ ' + copied; }
      btn.classList.add('copied');
      setTimeout(function() {
        restore.forEach(function(pair) { pair[0].textContent = pair[1]; });
        btn.classList.remove('copied');
      }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(doFeedback).catch(function() { fallbackCopy(text, doFeedback); });
    } else {
      fallbackCopy(text, doFeedback);
    }
  });
}

function fallbackCopy(text, onSuccess) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    if (onSuccess) { onSuccess(); }
  } catch (_) {
    showToast(i18nStr('i18nCopyFailed', 'Copy failed'), 'error');
  }
  document.body.removeChild(ta);
}

// ============================================================================
// Landing page (index.tmpl) interactive widget
// Host and JSON payload are read from data attributes on <body> so this
// stays a static, non-templated part of the one app.js file (AI.md PART 16
// "ONE file only"). initWidget() no-ops on any other page (elements absent).
// ============================================================================

var landingWidgetState = { commandBox: null, widgetBox: null, portInput: null, path: '', ipQuery: '', portQuery: '' };

function landingDisplayValue(value, notAvailable) {
  return value === undefined || value === null || value === '' ? notAvailable : value;
}

function landingSetCommandStr(host, notAvailable) {
  var s = landingWidgetState;
  var compositePath = '' + s.path + s.portQuery + s.ipQuery;
  s.commandBox.innerText = 'curl -q -LSsf -4 ' + host + '/' + compositePath;
  return compositePath;
}

function landingChangeInput(input, button, host, data, jsonObj, notAvailable) {
  var s = landingWidgetState;
  s.path = input;
  s.portQuery = '';
  s.portInput.classList.add('hidden');
  switch (s.path) {
  case 'json':
    s.widgetBox.innerText = jsonObj;
    break;
  case 'country-iso':
    s.widgetBox.innerText = landingDisplayValue(data.country_iso, notAvailable);
    break;
  case 'port': {
    s.portInput.classList.remove('hidden');
    s.widgetBox.innerText = '{}';
    landingUpdatePort(s.portInput.value, host, notAvailable);
    break;
  }
  case 'ip':
    s.widgetBox.innerText = landingDisplayValue(data.ip, notAvailable);
    s.path = '';
    break;
  default:
    s.widgetBox.innerText = landingDisplayValue(data[s.path], notAvailable);
  }
  landingSetCommandStr(host, notAvailable);

  if (button) {
    document.querySelectorAll('button.selected').forEach(function(btn) { btn.classList.remove('selected'); });
    button.classList.add('selected');
  }
}

function landingNavigate(host, notAvailable) {
  window.location = landingSetCommandStr(host, notAvailable);
}

function landingUpdatePort(value, host, notAvailable) {
  landingWidgetState.portQuery = '/' + value;
  landingSetCommandStr(host, notAvailable);
}

function landingUpdateIP(value, host, data, jsonObj, notAvailable) {
  landingWidgetState.ipQuery = '?ip=' + value;
  landingSetCommandStr(host, notAvailable);
  landingChangeInput('ip', null, host, data, jsonObj, notAvailable);
}

function initWidget() {
  var s = landingWidgetState;
  s.commandBox = document.getElementById('command');
  s.widgetBox = document.getElementById('output');
  s.portInput = document.getElementById('portInput');
  if (!s.commandBox || !s.widgetBox || !s.portInput) { return; }

  var host = document.body.dataset.host || '';
  var jsonObj = document.body.dataset.json || '{}';
  var data = JSON.parse(jsonObj);
  var notAvailable = document.body.dataset.na || '';

  document.querySelectorAll('.widget-select').forEach(function(btn) {
    btn.addEventListener('click', function() { landingChangeInput(btn.dataset.widget, btn, host, data, jsonObj, notAvailable); });
  });
  s.portInput.addEventListener('change', function() { landingUpdatePort(s.portInput.value, host, notAvailable); });
  var openBtn = document.getElementById('widget-open');
  if (openBtn) { openBtn.addEventListener('click', function() { landingNavigate(host, notAvailable); }); }
  var ipInput = document.getElementById('ipInput');
  if (ipInput) { ipInput.addEventListener('keyup', function() { landingUpdateIP(ipInput.value, host, data, jsonObj, notAvailable); }); }
  landingChangeInput('ip', null, host, data, jsonObj, notAvailable);
}

// ============================================================================
// Cookie consent banner — JS enhancement writes the cookie_consent cookie
// directly (no network round-trip); no-JS path falls back to form POST to
// /server/consent, which sets the same cookie server-side.
// ============================================================================

function writeConsentCookie(consent) {
  const value = encodeURIComponent(JSON.stringify(consent));
  document.cookie = 'cookie_consent=' + value + '; path=/; max-age=31536000; SameSite=Lax';
}

function handleCookieConsent(choice) {
  const banner = document.getElementById('consent-banner');
  const accepted = choice === 'accept';
  writeConsentCookie({
    essential: true,
    preferences: accepted,
    analytics: accepted,
    timestamp: Date.now()
  });
  if (banner) {
    banner.style.animation = 'slideOut 0.3s ease';
    setTimeout(function() { if (banner) { banner.remove(); } }, 300);
  }
  closeModal('cookie-preferences-modal');
  showToast(accepted
    ? i18nStr('i18nCookieAccepted', 'Cookies accepted')
    : i18nStr('i18nCookieDeclined', 'Cookies declined'), 'success');
}

// ============================================================================
// Announcement site-banner dismissal — JS enhancement; no-JS uses form POST
// ============================================================================

function initSiteBannerDismiss() {
  document.addEventListener('submit', function(e) {
    const form = e.target.closest('.site-banner-dismiss');
    if (!form) { return; }
    e.preventDefault();
    const id = form.querySelector('input[name="id"]');
    if (!id || !id.value) { return; }
    const banner = form.closest('.site-banner');
    if (!banner) { return; }
    const match = document.cookie.match(/(?:^|;\s*)dismissed_announcements=([^;]*)/);
    const ids = match ? decodeURIComponent(match[1]).split(',') : [];
    if (ids.indexOf(id.value) === -1) { ids.push(id.value); }
    document.cookie = 'dismissed_announcements=' + encodeURIComponent(ids.join(',')) +
      '; path=/; max-age=31536000; SameSite=Lax';
    banner.remove();
  });
}

// ============================================================================
// Offline indicator
// ============================================================================

function showOfflineIndicator() {
  const el = document.getElementById('offline-indicator');
  if (!el) { return; }
  el.textContent = '⚠️ ' + i18nStr('i18nOfflineIndicator', 'You are offline');
  el.classList.remove('hidden');
}

function hideOfflineIndicator() {
  const el = document.getElementById('offline-indicator');
  if (!el) { return; }
  el.classList.add('hidden');
  el.textContent = '';
}

window.addEventListener('offline', showOfflineIndicator);
window.addEventListener('online', hideOfflineIndicator);

// ============================================================================
// PWA: beforeinstallprompt capture for custom install button
// ============================================================================

var deferredInstallPrompt = null;

window.addEventListener('beforeinstallprompt', function(e) {
  e.preventDefault();
  deferredInstallPrompt = e;
  const btn = document.getElementById('pwa-install-btn');
  if (btn) { btn.classList.remove('hidden'); }
});

// ============================================================================
// Submit button behavior — AI.md PART 16 "Buttons": disable immediately on
// click (single submit only), swap to loading text when opted in via
// data-loading-text, preserve width, re-enable on return to the page.
// Applies to real (non-AJAX) form POSTs only — <form method="dialog"> and
// forms already intercepted by a click handler (e.preventDefault() before
// the submit event fires) are unaffected.
// ============================================================================

document.addEventListener('submit', function(e) {
  const form = e.target;
  if ((form.getAttribute('method') || '').toLowerCase() === 'dialog') { return; }
  const btn = form.querySelector('button[type="submit"]:not([disabled])');
  if (!btn) { return; }
  const loadingText = btn.dataset.loadingText;
  if (loadingText) {
    btn.style.minWidth = btn.offsetWidth + 'px';
    btn.dataset.originalText = btn.textContent;
    btn.textContent = loadingText;
  }
  btn.disabled = true;
});

// Re-enable submit buttons left disabled by a page restored from bfcache
// (browser back/forward) so a failed/aborted submit never leaves the button
// stuck — this is the "re-enable on success OR error" half of the rule for
// forms that navigate rather than fetch().
window.addEventListener('pageshow', function() {
  document.querySelectorAll('button[type="submit"][disabled]').forEach(function(btn) {
    btn.disabled = false;
    if (btn.dataset.originalText) {
      btn.textContent = btn.dataset.originalText;
      delete btn.dataset.originalText;
    }
  });
});

// ============================================================================
// Swagger UI init — /swagger page only (element absent elsewhere, no-op).
// Kept out of an inline <script> so it runs under the site's strict CSP
// (script-src 'self', no unsafe-inline).
// ============================================================================

function initSwaggerUI() {
  const el = document.getElementById('swagger-ui');
  if (!el || typeof SwaggerUIBundle === 'undefined') { return; }
  SwaggerUIBundle({
    url: el.dataset.specUrl,
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIBundle.SwaggerUIStandalonePreset
    ]
  });
}

// ============================================================================
// GraphQL explorer init — /graphql page only (element absent elsewhere, no-op).
// ============================================================================

function initGraphQLExplorer() {
  const runBtn = document.getElementById('run');
  const queryBox = document.getElementById('query');
  if (!runBtn || !queryBox) { return; }
  runBtn.addEventListener('click', function() {
    const q = queryBox.value;
    const v = document.getElementById('vars').value;
    // Leave vars empty on invalid JSON rather than blocking the query.
    let vars = {};
    try { vars = JSON.parse(v || '{}'); } catch (e) { vars = {}; }
    const result = document.getElementById('result');
    result.textContent = i18nStr('i18nRunning', 'Running…');
    fetch('/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ query: q, variables: vars })
    }).then(function(r) { return r.json(); }).then(function(d) {
      result.textContent = JSON.stringify(d, null, 2);
    }).catch(function(e) {
      result.textContent = i18nStr('i18nErrorPrefix', 'Error: ') + e.message;
      result.classList.add('err');
    });
  });
  queryBox.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { runBtn.click(); }
  });
}

// ============================================================================
// data-action event delegation — all behaviors bound here; no inline onclick
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
  initCopyButtons();
  initThemeToggleForms();
  initSiteBannerDismiss();
  initSwaggerUI();
  initGraphQLExplorer();

  document.addEventListener('click', function(e) {
    const btn = e.target.closest('[data-action]');
    if (!btn) { return; }
    switch (btn.dataset.action) {
    case 'consent-accept':
      e.preventDefault();
      handleCookieConsent('accept');
      break;
    case 'consent-decline':
      e.preventDefault();
      handleCookieConsent('decline');
      break;
    case 'cookie-preferences':
      e.preventDefault();
      openModal('cookie-preferences-modal');
      break;
    case 'pwa-install':
      e.preventDefault();
      if (deferredInstallPrompt) {
        deferredInstallPrompt.prompt();
        deferredInstallPrompt.userChoice.then(function() { deferredInstallPrompt = null; });
      }
      break;
    case 'back':
      e.preventDefault();
      history.back();
      break;
    case 'print':
      e.preventDefault();
      window.print();
      break;
    }
  });

  document.querySelectorAll('[data-confirm-dialog]').forEach(function(el) {
    el.addEventListener('click', function() {
      openModal(el.dataset.confirmDialog);
    });
  });

  initHealthzCountdown();
  initNavToggleAria();
  initWidget();
});

// initNavToggleAria keeps aria-expanded on the CSS-only mobile nav checkbox
// in sync with its checked state (the checkbox itself drives the panel via
// pure CSS; this only mirrors state for assistive tech).
function initNavToggleAria() {
  const cb = document.getElementById('nav-toggle');
  if (!cb) { return; }
  const sync = function() { cb.setAttribute('aria-expanded', cb.checked ? 'true' : 'false'); };
  cb.addEventListener('change', sync);
  sync();
}

// initHealthzCountdown drives the visible refresh countdown on /server/healthz.
// The actual reload is handled by the page's <meta http-equiv="refresh">, so
// this only decrements the displayed number. Kept in this external script
// (not inline) so it is not blocked by the CSP script-src 'self' policy.
function initHealthzCountdown() {
  var el = document.getElementById('healthz-countdown');
  if (!el) { return; }
  var seconds = parseInt(el.textContent, 10);
  if (isNaN(seconds)) { seconds = 30; }
  var timer = setInterval(function() {
    seconds -= 1;
    if (seconds <= 0) {
      clearInterval(timer);
      el.textContent = '0';
      return;
    }
    el.textContent = String(seconds);
  }, 1000);
}

// ============================================================================
// Utility functions
// ============================================================================

function formatDistance(km) {
  if (km < 1) { return (km * 1000).toFixed(0) + ' m'; }
  return km.toFixed(2) + ' km';
}

function formatCoordinates(lat, lon) {
  const latDir = lat >= 0 ? 'N' : 'S';
  const lonDir = lon >= 0 ? 'E' : 'W';
  return Math.abs(lat).toFixed(4) + '° ' + latDir + ', ' + Math.abs(lon).toFixed(4) + '° ' + lonDir;
}

// ============================================================================
// PWA: SW update notification with dedicated banner (not just a toast)
// ============================================================================

function showUpdateNotification(worker) {
  let banner = document.getElementById('sw-update-banner');
  if (banner) { return; }
  banner = document.createElement('div');
  banner.id = 'sw-update-banner';
  banner.className = 'site-banner site-banner-info';
  banner.setAttribute('role', 'status');
  const bIcon = document.createElement('span');
  bIcon.className = 'site-banner-icon';
  bIcon.setAttribute('aria-hidden', 'true');
  bIcon.textContent = '🔄';
  const bText = document.createElement('span');
  bText.className = 'site-banner-text';
  bText.textContent = i18nStr('i18nUpdateAvailable', 'A new version is available.');
  const bNow = document.createElement('button');
  bNow.className = 'btn btn-primary site-banner-action';
  bNow.id = 'sw-update-now';
  bNow.textContent = i18nStr('i18nUpdateNow', 'Update Now');
  const bLater = document.createElement('button');
  bLater.className = 'btn site-banner-action';
  bLater.id = 'sw-update-later';
  bLater.textContent = i18nStr('i18nUpdateLater', 'Later');
  banner.appendChild(bIcon);
  banner.appendChild(bText);
  banner.appendChild(bNow);
  banner.appendChild(bLater);
  document.body.insertBefore(banner, document.body.firstChild);
  bNow.addEventListener('click', function() {
    worker.postMessage({ type: 'SKIP_WAITING' });
  });
  bLater.addEventListener('click', function() {
    banner.remove();
  });
}

// ============================================================================
// PWA Service Worker registration
// ============================================================================

if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).then(function(reg) {
      reg.addEventListener('updatefound', function() {
        const w = reg.installing;
        if (!w) { return; }
        w.addEventListener('statechange', function() {
          if (w.state === 'installed' && navigator.serviceWorker.controller) {
            showUpdateNotification(w);
          }
        });
      });
      setInterval(function() { reg.update(); }, 3600000);
    }).catch(function(err) {
      console.warn('Service worker registration failed:', err);
    });
    navigator.serviceWorker.addEventListener('controllerchange', function() {
      location.reload();
    });
  });
}
