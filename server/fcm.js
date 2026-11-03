/**
 * FCM wake-up sender (HTTP v1) — wakes a child's app via a high-priority
 * data-only push when a parent-initiated action targets a child whose
 * WebSocket is down (the child app may have been killed by the OEM
 * battery manager; see the Private Call keep-alive history).
 *
 * Zero new dependencies: JWT is built and RS256-signed with node:crypto,
 * HTTP via the global fetch. Credentials come from the env var
 * FIREBASE_SERVICE_ACCOUNT, whose value is the service-account JSON
 * string (Firebase console -> Project settings -> Service accounts).
 * If the env var is missing or invalid, every entry point is a safe
 * no-op returning false — the server runs fine without FCM configured.
 *
 * Token values are NEVER logged here or by callers.
 */
const crypto = require('crypto');

const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const TOKEN_EXPIRY_S = 3600;         // JWT lifetime requested (1 h, the max)
const TOKEN_REFRESH_SKEW_MS = 5 * 60 * 1000; // refresh 5 min before expiry

function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Pure: build (and sign) the OAuth2 JWT bearer assertion for a service
 * account. `nowSeconds` is injected for deterministic tests.
 */
function buildJwt(sa, nowSeconds) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = {
    iss: sa.client_email,
    scope: FCM_SCOPE,
    aud: TOKEN_URL,
    iat: nowSeconds,
    exp: nowSeconds + TOKEN_EXPIRY_S,
  };
  const signingInput = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(claims));
  const signature = crypto.sign('sha256', Buffer.from(signingInput, 'utf8'), sa.private_key);
  return signingInput + '.' + base64url(signature);
}

function validServiceAccount(sa) {
  return !!sa && typeof sa === 'object'
    && typeof sa.client_email === 'string' && sa.client_email.includes('@')
    && typeof sa.private_key === 'string' && sa.private_key.includes('PRIVATE KEY')
    && typeof sa.project_id === 'string' && sa.project_id.length > 0;
}

/**
 * A sender bound to one service account. fetchImpl / nowFn / tokenUrl
 * are injectable so tests stay hermetic (no real Google calls).
 * Returns { sendWake } where sendWake never throws.
 */
function createSender(opts = {}) {
  const sa = opts.serviceAccount || null;
  const fetchImpl = opts.fetchImpl || (typeof fetch === 'function' ? fetch : null);
  const nowFn = opts.nowFn || (() => Date.now());
  const tokenUrl = opts.tokenUrl || TOKEN_URL;
  let cached = null; // { token, expiresAtMs }

  async function getAccessToken() {
    const now = nowFn();
    if (cached && now < cached.expiresAtMs - TOKEN_REFRESH_SKEW_MS) return cached.token;
    const jwt = buildJwt(sa, Math.floor(now / 1000));
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    });
    const res = await fetchImpl(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res || !res.ok) return null;
    const data = await res.json().catch(() => null);
    if (!data || typeof data.access_token !== 'string') return null;
    const ttlMs = (typeof data.expires_in === 'number' ? data.expires_in : TOKEN_EXPIRY_S) * 1000;
    cached = { token: data.access_token, expiresAtMs: now + ttlMs };
    return cached.token;
  }

  /**
   * Send the wake push to one device token. High-priority, data-only
   * (no notification payload — the app decides what to do, silently).
   * @returns {Promise<boolean>} true only on an FCM 2xx.
   */
  async function sendWake(fcmToken) {
    try {
      if (!validServiceAccount(sa) || !fetchImpl) return false;
      if (typeof fcmToken !== 'string' || !fcmToken) return false;
      const accessToken = await getAccessToken();
      if (!accessToken) return false;
      const url = `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`;
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: {
            token: fcmToken,
            data: { wake: '1' },
            android: { priority: 'high' },
          },
        }),
      });
      return !!(res && res.ok);
    } catch {
      return false;
    }
  }

  return { sendWake, _getAccessToken: getAccessToken };
}

/**
 * Throttle wrapper: at most one wake attempt per key (childId) per
 * windowMs (default 20 s), in memory. The attempt timestamp is stamped
 * before sending, so a failing network cannot cause a retry storm.
 * `sender` may be a sendWake function or an object with .sendWake.
 */
function createWakeService(sender, opts = {}) {
  const sendFn = typeof sender === 'function'
    ? sender
    : (sender && typeof sender.sendWake === 'function' ? sender.sendWake.bind(sender) : null);
  const windowMs = typeof opts.windowMs === 'number' ? opts.windowMs : 20000;
  const nowFn = opts.nowFn || (() => Date.now());
  const lastAttempt = new Map(); // key -> ms
  return {
    async wake(key, fcmToken) {
      if (!sendFn || typeof fcmToken !== 'string' || !fcmToken) return false;
      const now = nowFn();
      const prev = lastAttempt.get(key);
      if (prev != null && now - prev < windowMs) return false;
      lastAttempt.set(key, now);
      try { return await sendFn(fcmToken); } catch { return false; }
    },
    _lastAttempt: lastAttempt,
  };
}

// ---- default sender from env (parsed lazily, once) -------------------
let _defaultSender = null;
function loadServiceAccountFromEnv() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return validServiceAccount(parsed) ? parsed : null;
  } catch { return null; }
}
function defaultSender() {
  if (!_defaultSender) {
    _defaultSender = createSender({ serviceAccount: loadServiceAccountFromEnv() });
  }
  return _defaultSender;
}
/** Default entry point used by server.js. Safe no-op when unconfigured. */
async function sendWake(fcmToken) {
  return defaultSender().sendWake(fcmToken);
}

module.exports = {
  buildJwt,
  base64url,
  validServiceAccount,
  createSender,
  createWakeService,
  defaultSender,
  sendWake,
};
