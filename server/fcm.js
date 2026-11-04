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

// Wake payload policy (step-3): every wake carries its reason in the
// data payload so the woken app can tell a call (seconds matter) from
// a chat nudge, a per-reason collapse_key so a newer wake replaces a
// stale queued one instead of bursting, and a bounded TTL so wakes do
// not pile up for days on an offline device. A call wake only needs to
// outlive the ring window; a chat wake may reasonably wait an hour.
const WAKE_TTL_BY_REASON = { call: '45s', listen: '120s', camera: '120s', chat: '3600s' };
const WAKE_TTL_DEFAULT = '300s';
// FCM error codes that mean the registration token itself is dead
// (app uninstalled, token rotated away, token malformed): the caller
// prunes the stored token when one of these comes back.
const DEAD_TOKEN_CODES = new Set(['UNREGISTERED', 'INVALID_ARGUMENT']);

/**
 * Extract the FCM error code from an HTTP v1 error body:
 * { error: { status, details: [ { '@type': '.../FcmError',
 * errorCode: 'UNREGISTERED' } ] } }. The FcmError detail wins; the
 * top-level status is the fallback. Null when nothing parses.
 */
function parseFcmErrorCode(body) {
  try {
    const err = body && body.error;
    if (!err || typeof err !== 'object') return null;
    if (Array.isArray(err.details)) {
      for (const d of err.details) {
        if (d && typeof d.errorCode === 'string' && d.errorCode) return d.errorCode;
      }
    }
    if (typeof err.status === 'string' && err.status) return err.status;
    return null;
  } catch { return null; }
}

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
   * Detailed wake send. `payload` may carry { reason } (listen /
   * camera / call / chat): the reason rides in the data payload, and
   * the android block gains a per-reason collapse_key and TTL. With
   * no payload the message is byte-identical to the original shape
   * (data {wake:'1'}, android {priority:'high'}).
   * @returns {Promise<{ok:boolean, status:number|null,
   *   errorCode:string|null, dead:boolean}>} never throws. `dead`
   *   means FCM rejected the token itself (UNREGISTERED /
   *   INVALID_ARGUMENT) — the stored token should be pruned.
   */
  async function sendWakeDetailed(fcmToken, payload) {
    try {
      if (!validServiceAccount(sa) || !fetchImpl) return { ok: false, status: null, errorCode: 'unconfigured', dead: false };
      if (typeof fcmToken !== 'string' || !fcmToken) return { ok: false, status: null, errorCode: 'no_token', dead: false };
      const accessToken = await getAccessToken();
      if (!accessToken) return { ok: false, status: null, errorCode: 'oauth_failed', dead: false };
      const reason = payload && typeof payload.reason === 'string' && payload.reason ? payload.reason : null;
      const data = { wake: '1' };
      const android = { priority: 'high' };
      if (reason) {
        data.reason = reason;
        android.collapse_key = 'fc_wake_' + reason;
        android.ttl = WAKE_TTL_BY_REASON[reason] || WAKE_TTL_DEFAULT;
      }
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
            data,
            android,
          },
        }),
      });
      if (res && res.ok) return { ok: true, status: res.status || 200, errorCode: null, dead: false };
      let errorCode = null;
      if (res && typeof res.json === 'function') {
        errorCode = parseFcmErrorCode(await res.json().catch(() => null));
      }
      return {
        ok: false,
        status: res && typeof res.status === 'number' ? res.status : null,
        errorCode,
        dead: !!errorCode && DEAD_TOKEN_CODES.has(errorCode),
      };
    } catch {
      return { ok: false, status: null, errorCode: 'send_exception', dead: false };
    }
  }

  /**
   * Send the wake push to one device token. High-priority, data-only
   * (no notification payload — the app decides what to do, silently).
   * @returns {Promise<boolean>} true only on an FCM 2xx.
   */
  async function sendWake(fcmToken, payload) {
    const r = await sendWakeDetailed(fcmToken, payload);
    return r.ok;
  }

  return { sendWake, sendWakeDetailed, _getAccessToken: getAccessToken };
}

/**
 * Throttle wrapper: at most one wake attempt per key (childId) per
 * windowMs (default 20 s), in memory. The attempt timestamp is stamped
 * before sending, so a failing network cannot cause a retry storm.
 * `sender` may be a sendWake function or an object with .sendWake.
 *
 * wake() keeps the original boolean contract (true only when a send
 * was attempted and FCM accepted it). wakeDetailed() returns the full
 * outcome { sent, throttled, ok, status, errorCode, dead } so callers
 * can log attempts and prune dead tokens.
 */
function createWakeService(sender, opts = {}) {
  const detailedFn = sender && typeof sender.sendWakeDetailed === 'function'
    ? sender.sendWakeDetailed.bind(sender) : null;
  const sendFn = typeof sender === 'function'
    ? sender
    : (sender && typeof sender.sendWake === 'function' ? sender.sendWake.bind(sender) : null);
  const windowMs = typeof opts.windowMs === 'number' ? opts.windowMs : 20000;
  const nowFn = opts.nowFn || (() => Date.now());
  const lastAttempt = new Map(); // key -> ms
  async function wakeDetailed(key, fcmToken, payload) {
    const base = { sent: false, throttled: false, ok: false, status: null, errorCode: null, dead: false };
    if ((!detailedFn && !sendFn) || typeof fcmToken !== 'string' || !fcmToken) return base;
    const now = nowFn();
    const prev = lastAttempt.get(key);
    if (prev != null && now - prev < windowMs) return { ...base, throttled: true };
    lastAttempt.set(key, now);
    try {
      if (detailedFn) {
        const r = await detailedFn(fcmToken, payload);
        return { sent: true, throttled: false, ok: !!r.ok, status: r.status ?? null, errorCode: r.errorCode ?? null, dead: !!r.dead };
      }
      const ok = await sendFn(fcmToken, payload);
      return { ...base, sent: true, ok: !!ok };
    } catch { return { ...base, sent: true, errorCode: 'send_exception' }; }
  }
  return {
    async wake(key, fcmToken, payload) {
      const r = await wakeDetailed(key, fcmToken, payload);
      return r.sent && r.ok;
    },
    wakeDetailed,
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
async function sendWake(fcmToken, payload) {
  return defaultSender().sendWake(fcmToken, payload);
}

module.exports = {
  buildJwt,
  base64url,
  validServiceAccount,
  parseFcmErrorCode,
  WAKE_TTL_BY_REASON,
  createSender,
  createWakeService,
  defaultSender,
  sendWake,
};
