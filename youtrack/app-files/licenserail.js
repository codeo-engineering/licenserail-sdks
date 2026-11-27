// LicenseRail for YouTrack apps: license checks for your own handlers, plus the async functions that talk to the license
// server. Readable on purpose (JetBrains Marketplace rule: verify signed license data in readable code).
//
//   const licenserail = require('./licenserail');
//   exports.httpHandler = {
//     endpoints: [{ method: 'GET', path: 'report', handle(ctx) {
//       const license = licenserail.check(ctx);
//       if (!license.valid) { ctx.response.statusCode = 402; ctx.response.json({ error: 'license_required' }); return; }
//       ...
//     } }],
//     asyncFunctions: licenserail.asyncFunctions,   // lets check() schedule the daily refresh
//   };

const core = require('./licenserail-core');
const config = require('./licenserail-config');

const PROPERTY = {
  token: 'licenserailToken',
  lastSeen: 'licenserailLastSeen',
  installation: 'licenserailInstallation',
  state: 'licenserailState',
};
const PLATFORM = 'youtrack';
const REFRESH = 'licenserailRefresh';
const RESPONSE = 'licenserailResponse';
const RELEASED = 'licenserailReleased';
const LAST_SEEN_WRITE_MS = 60 * 60 * 1000;   // store "last run" at most hourly: few writes, enough for the clock check

function props(ctx) {
  return ctx.globalStorage.extensionProperties;
}

function readState(ctx) {
  try { return JSON.parse(props(ctx)[PROPERTY.state] || '{}'); } catch (e) { return {}; }
}

function writeState(ctx, change) {
  const next = Object.assign(readState(ctx), change);
  props(ctx)[PROPERTY.state] = JSON.stringify(next);
  return next;
}

/** The YouTrack instance's number of users (for licenses priced per user), or undefined if not available. */
function hostUsers() {
  try { return require('@jetbrains/youtrack-scripting-api/license').licenseInfo.currentUserCount; } catch (e) { return undefined; }
}

function installationId(ctx) {
  return props(ctx)[PROPERTY.installation] || null;
}

function fingerprint(ctx) {
  const id = installationId(ctx);
  return id ? core.installationFingerprint(config.vendor, config.product, PLATFORM, id) : null;
}

function target(ctx) {
  return { apiUrl: config.apiUrl, product: config.product, fingerprint: fingerprint(ctx) };
}

/**
 * Sends a request description with YouTrack's async HTTP (required for Marketplace apps). The response arrives later in the
 * named async function. With `withKey`, the license key from the secret setting goes in `Authorization: Bearer`.
 */
function send(ctx, request, callback, withKey) {
  const http = require('@jetbrains/youtrack-scripting-api/http');
  const connection = new http.Connection(config.apiUrl.replace(/\/+$/, ''), null, 20000);
  Object.keys(request.headers).forEach(function (name) { connection.addHeader(name, request.headers[name]); });
  if (withKey) connection.bearerAuth(ctx.settings.licenseKey);
  const path = request.url.substring(config.apiUrl.replace(/\/+$/, '').length);
  connection.postAsync(path, {}, request.body, callback);
}

/**
 * The license, checked offline from app storage (no network). `valid` is true for a valid license or trial.
 * Schedules the daily refresh when the token asks for it (needs `asyncFunctions: licenserail.asyncFunctions` in the
 * calling handler).
 */
function check(ctx) {
  return inspect(ctx, true);
}

function inspect(ctx, scheduleRefresh) {
  const token = props(ctx)[PROPERTY.token];
  const fp = fingerprint(ctx);
  if (!token || !fp) return { valid: false, status: 'Missing', summary: null };
  const payload = core.verifyToken(token, config.publicKeyPem);
  const seenText = props(ctx)[PROPERTY.lastSeen];
  const lastSeen = seenText ? new Date(Number(seenText)) : null;
  const now = new Date();
  const status = core.evaluate(payload, config.product, fp, now, lastSeen);
  if (status === 'Valid' && (!lastSeen || now.getTime() - lastSeen.getTime() > LAST_SEEN_WRITE_MS)) props(ctx)[PROPERTY.lastSeen] = String(now.getTime());
  if (payload) {
    const due = core.refreshDueAt(payload);
    if (scheduleRefresh && due && due.getTime() <= now.getTime() && typeof ctx.invokeAsync === 'function') {
      try { ctx.invokeAsync(REFRESH, 0, 'licenserail-refresh'); } catch (e) { /* the calling handler doesn't declare the async functions */ }
    }
  }
  return { valid: status === 'Valid', status: status, summary: payload ? core.summarize(payload, hostUsers()) : null };
}

/** Feature flag from the license (entitlements set in LicenseRail). */
function hasFeature(ctx, code) {
  const license = inspect(ctx, false);
  return license.valid && license.summary.entitlements.indexOf(code) >= 0;
}

/** Remembers this YouTrack instance's id (read by the admin page from /api/config). */
function setInstallation(ctx, id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9-]{8,64}$/.test(id)) throw new Error('Invalid installation id.');
  if (props(ctx)[PROPERTY.installation] !== id) props(ctx)[PROPERTY.installation] = id;
}

function common(ctx) {
  return { machineName: 'YouTrack', appVersion: config.appVersion, hostUsers: hostUsers() };
}

function activate(ctx) {
  const t = target(ctx);
  if (!t.fingerprint) throw new Error('Open the license page once so the app knows this YouTrack instance.');
  writeState(ctx, { pending: 'activate', lastAttemptAt: new Date().toISOString() });
  send(ctx, core.activateRequest(Object.assign(t, common(ctx))), RESPONSE, true);
}

/**
 * Starts the keyless trial. LicenseRail asks this YouTrack instance for its id at baseUrls (the addresses the admin page was
 * opened from) before the trial starts, so the instance must be reachable from the internet.
 */
function startTrial(ctx, baseUrls) {
  const t = target(ctx);
  if (!t.fingerprint) throw new Error('Open the license page once so the app knows this YouTrack instance.');
  const urls = (Array.isArray(baseUrls) ? baseUrls : [])
    .filter(function (u) { return typeof u === 'string' && /^https?:\/\/[^\s/]+$/.test(u); }).slice(0, 3);
  writeState(ctx, { pending: 'trial', lastAttemptAt: new Date().toISOString() });
  send(ctx, core.trialRequest(Object.assign(t, common(ctx), {
    keyId: config.keyId, host: { instanceId: installationId(ctx), baseUrls: urls },
  })), RESPONSE, false);
}

function refresh(ctx) {
  const token = props(ctx)[PROPERTY.token];
  const t = target(ctx);
  if (!token || !t.fingerprint) return false;
  const payload = core.verifyToken(token, config.publicKeyPem);
  if (!payload || payload.trial) return false;
  writeState(ctx, { pending: 'refresh', lastAttemptAt: new Date().toISOString() });
  send(ctx, core.refreshRequest(Object.assign(t, { token: token, appVersion: config.appVersion, hostUsers: hostUsers(), floating: payload.floating === true })), RESPONSE, false);
  return true;
}

function deactivate(ctx) {
  const token = props(ctx)[PROPERTY.token];
  const t = target(ctx);
  const payload = token ? core.verifyToken(token, config.publicKeyPem) : null;
  if (!token || !t.fingerprint || !payload || payload.trial) {
    props(ctx)[PROPERTY.token] = null;
    writeState(ctx, { pending: null, lastError: null });
    return false;
  }
  writeState(ctx, { pending: 'deactivate', lastAttemptAt: new Date().toISOString() });
  send(ctx, core.deactivateRequest(Object.assign(t, { token: token, floating: payload.floating === true })), RELEASED, false);
  return true;
}

/** Admin page data: never the token or the key. */
function status(ctx) {
  const license = inspect(ctx, false);
  const state = readState(ctx);
  const s = license.summary;
  return {
    status: license.status,
    valid: license.valid,
    isTrial: s ? s.isTrial : false,
    isTest: s ? s.isTest : false,
    expiresAt: s && s.expiresAt ? s.expiresAt.toISOString() : null,
    entitlements: s ? s.entitlements : [],
    hostUsers: hostUsers() === undefined ? null : hostUsers(),
    maxHostUsers: s ? s.maxHostUsers : null,
    hostUsersOverLimit: s ? s.hostUsersOverLimit : false,
    installationKnown: !!installationId(ctx),
    keyConfigured: !!ctx.settings.licenseKey,
    pending: state.pending || null,
    lastAttemptAt: state.lastAttemptAt || null,
    lastError: state.lastError || null,
  };
}

function responseOf(ctx) {
  const r = ctx.response;
  if (!r) return { status: 0, body: '' };
  return { status: r.code || 0, body: typeof r.body === 'string' ? r.body : (r.response || '') };
}

const asyncFunctions = {};

asyncFunctions[REFRESH] = function (ctx) {
  refresh(ctx);
};

asyncFunctions[RESPONSE] = function (ctx) {
  const res = responseOf(ctx);
  const r = core.readResponse(res.status, res.body);
  if (r.ok && r.token) {
    if (!core.verifyToken(r.token, config.publicKeyPem)) {
      writeState(ctx, { pending: null, lastError: { code: 'invalid_token', message: 'The license server returned a token that does not verify.' } });
      return;
    }
    props(ctx)[PROPERTY.token] = r.token;
    props(ctx)[PROPERTY.lastSeen] = String(Date.now());
    writeState(ctx, { pending: null, lastError: null, lastSuccessAt: new Date().toISOString() });
    return;
  }
  if (!r.ok) {
    if (r.revokesLocalLicense) props(ctx)[PROPERTY.token] = null;
    writeState(ctx, { pending: null, lastError: { code: r.code, message: r.message } });
  }
};

asyncFunctions[RELEASED] = function (ctx) {
  const res = responseOf(ctx);
  const r = core.readResponse(res.status, res.body);
  if (r.ok || r.revokesLocalLicense) {
    props(ctx)[PROPERTY.token] = null;
    writeState(ctx, { pending: null, lastError: null });
  } else {
    writeState(ctx, { pending: null, lastError: { code: r.code, message: r.message } });
  }
};

module.exports = {
  check: check,
  hasFeature: hasFeature,
  setInstallation: setInstallation,
  activate: activate,
  startTrial: startTrial,
  refresh: refresh,
  deactivate: deactivate,
  status: status,
  asyncFunctions: asyncFunctions,
};
