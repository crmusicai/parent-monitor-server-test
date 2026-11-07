/**
 * Parent Monitor Server — multi-tenant registry, pairing, heartbeat/events,
 * and WebRTC signalling relay for the Parental Monitoring App.
 * v2 ("Private Call", ../SPEC-V2.md): generalized sessions (listen/camera/call),
 * chat, media files, and invite-link pairing on top of the v1 protocol.
 *
 * Source of truth: ../SPEC.md + ../SPEC-V2.md
 *
 * Run: PORT=8080 node server.js
 * Storage: data.json next to this file (env DATA_FILE overrides), atomic writes.
 * Tenancy rule: every child belongs to exactly one parentId and EVERY
 * read/write/signalling path verifies it. Cross-parent access -> 403/404.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const fcm = require('./fcm');
const { createMediaStore } = require('./media-store');

const PORT = parseInt(process.env.PORT || '8080', 10);
const DATA_FILE = process.env.DATA_FILE
  ? path.resolve(process.env.DATA_FILE)
  : path.join(__dirname, 'data.json');

const PAIRING_TTL_MS = 15 * 60 * 1000;
const EVENTS_CAP = 200;       // stored per child
const EVENTS_RETURN = 100;    // returned by GET events
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // invite link lifetime
const CHAT_CAP = 200;                            // messages kept per parent-child pair
const MEDIA_MAX_BYTES = 10 * 1024 * 1024;        // media upload cap (413 above)
const MEDIA_MAX_FILES = 200;                     // stored media files kept (oldest pruned)
// Ring timeout for unaccepted calls (45 s per SPEC-V2; env override exists for tests).
const RING_TIMEOUT_MS = parseInt(process.env.RING_TIMEOUT_MS || '45000', 10);
// Wake-and-wait window (step-3, ported from the test server): how long
// a start request for an offline party is HELD while an FCM wake push
// tries to bring that party's socket back, before the request fails
// with the usual 'offline' error. Env override exists for tests.
const WAKE_WAIT_MS = parseInt(process.env.WAKE_WAIT_MS || '50000', 10);
const MEDIA_DIR = path.join(path.dirname(DATA_FILE), 'media');
// Presence grace (v2.4 audit round; merged from server.proposed.js, NOT
// YET DEPLOYED). Before this change, childView.online was exactly
// liveChildren.has(id): the instant a child's WebSocket closed — a
// Wi-Fi<->mobile-data switch, a carrier NAT rebinding, a brief tunnel
// drop — the parent saw "Offline", even though the child app was alive
// and reconnecting with backoff (field report: "shows Offline suddenly
// while actually online"). A closed socket now starts a grace window:
// the child still reads online for up to PRESENCE_GRACE_MS while it
// reconnects; only a child that stays gone past the window flips to
// offline. Env override exists for tests.
const PRESENCE_GRACE_MS = parseInt(process.env.PRESENCE_GRACE_MS || '30000', 10);
// Server-side WS heartbeat. The ws server previously never pinged and
// never reaped dead sockets, so a half-open child connection (network
// vanished without a FIN) stayed "online" forever. Every WS_PING_MS
// each client is pinged; a client that misses a full cycle is
// terminated, which runs the normal close path (sessions end,
// presence grace starts).
const WS_PING_MS = parseInt(process.env.WS_PING_MS || '10000', 10);
// A socket that has not ponged within STALE_SOCKET_MS is dead for
// ROUTING even before the reaper terminates it (field, 2026-11-07:
// requests poured into a half-open child socket — no wake push was
// sent because the child "looked online" — and the parent sat at
// "Connecting…" through the full ring/wait timeouts).
const STALE_SOCKET_MS = parseInt(process.env.STALE_SOCKET_MS || '25000', 10);

// ---------------------------------------------------------------- storage
function blankData() {
  return { parents: [], tokens: {}, pairingCodes: {}, children: [], invites: {}, chats: {}, media: {}, numbers: {} };
}
function normalizeData(d) {
  if (!d || typeof d !== 'object') return blankData();
  return {
    parents: Array.isArray(d.parents) ? d.parents : [],
    tokens: d.tokens && typeof d.tokens === 'object' ? d.tokens : {},
    pairingCodes: d.pairingCodes && typeof d.pairingCodes === 'object' ? d.pairingCodes : {},
    children: Array.isArray(d.children) ? d.children : [],
    invites: d.invites && typeof d.invites === 'object' ? d.invites : {},
    chats: d.chats && typeof d.chats === 'object' ? d.chats : {},
    media: d.media && typeof d.media === 'object' ? d.media : {},
    // Number accounts (number system): normalized phone number ->
    // { childId, salt, passwordHash, deviceName, createdAt }. Older
    // data files simply have no such key yet.
    numbers: d.numbers && typeof d.numbers === 'object' ? d.numbers : {},
  };
}
function loadData() {
  try {
    return normalizeData(JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
  } catch { return blankData(); }
}
const data = loadData();
// Replace the live state's contents in place (same object identity —
// module.exports._test.data and every handler hold this reference).
function replaceData(parsed) {
  const nd = normalizeData(parsed);
  data.parents = nd.parents;
  data.tokens = nd.tokens;
  data.pairingCodes = nd.pairingCodes;
  data.children = nd.children;
  data.invites = nd.invites;
  data.chats = nd.chats;
  data.media = nd.media;
  data.numbers = nd.numbers;
}
function isDataEmpty(d) {
  return d.parents.length === 0 && d.children.length === 0
    && Object.keys(d.tokens).length === 0 && Object.keys(d.pairingCodes).length === 0
    && Object.keys(d.invites).length === 0 && Object.keys(d.chats).length === 0
    && Object.keys(d.media).length === 0 && Object.keys(d.numbers).length === 0;
}
function saveLocalOnly() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE); // atomic replace
}
function save() {
  saveLocalOnly(); // warm local cache, exactly as before
  if (STORAGE_MODE === 'firestore') scheduleFirestorePersist();
  else { storageStats.lastPersistOk = true; storageStats.lastPersistAt = new Date().toISOString(); }
}

// ------------------------------------------------- persistent storage
// The local data.json lives on the host's EPHEMERAL disk (Render free
// tier): any restart/recycle/redeploy wipes it, and with it every
// parent account, pairing and number registration — the field failure
// behind the 2026-11-04/05 "suddenly logged out / number not
// registered" reports. The durable copy therefore lives in Firestore
// (same Firebase project as FCM), written through the REST API with
// the SAME service account and the SAME hand-rolled JWT -> OAuth2
// mechanism fcm.js uses for messaging (datastore scope; zero new
// dependencies). The whole state is one document —
// familyCallServer/<STORAGE_DOC_ID> — with a single string field
// holding the JSON. Boot hydrates from it before listening; save()
// still writes the local file synchronously and schedules a debounced
// Firestore write. STORAGE_MODE=file is the pure-local rollback path
// (and the automatic mode when no service account is configured, e.g.
// the hermetic test suites). A failed Firestore write never blocks or
// crashes request handling: it is logged, counted, and retried by the
// next save.
const STORAGE_COLLECTION = 'familyCallServer';
const STORAGE_DOC_ID = process.env.STORAGE_DOC_ID || 'test'; // doc id on this (test) track
const STORAGE_SIZE_WARN_BYTES = 900 * 1024; // Firestore docs cap at ~1 MiB; warn, never chunk (this round)
const DATASTORE_SCOPE = 'https://www.googleapis.com/auth/datastore';
const TOKEN_URL = 'https://oauth2.googleapis.com/token'; // same endpoint fcm.js uses
const TOKEN_REFRESH_SKEW_MS = 5 * 60 * 1000; // refresh 5 min early, as in fcm.js
const storageSA = (() => {
  try {
    const parsed = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '');
    return fcm.validServiceAccount(parsed) ? parsed : null;
  } catch { return null; }
})();
const STORAGE_MODE = (() => {
  const req = String(process.env.STORAGE_MODE || '').toLowerCase();
  if (req === 'file') return 'file';
  if (storageSA) return 'firestore';
  if (req === 'firestore') console.warn('[storage] STORAGE_MODE=firestore requested but FIREBASE_SERVICE_ACCOUNT is missing/invalid — falling back to file mode');
  return 'file';
})();
const storageStats = { lastPersistOk: null, lastPersistAt: null, persistErrors: 0 };
let fsTokenCache = null; // { token, expiresAtMs } — mirrors fcm.js's sender cache
async function getDatastoreToken() {
  const now = Date.now();
  if (fsTokenCache && now < fsTokenCache.expiresAtMs - TOKEN_REFRESH_SKEW_MS) return fsTokenCache.token;
  const jwt = fcm.buildJwt(storageSA, Math.floor(now / 1000), DATASTORE_SCOPE);
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res || !res.ok) return null;
  const j = await res.json().catch(() => null);
  if (!j || typeof j.access_token !== 'string') return null;
  const ttlMs = (typeof j.expires_in === 'number' ? j.expires_in : 3600) * 1000;
  fsTokenCache = { token: j.access_token, expiresAtMs: now + ttlMs };
  return fsTokenCache.token;
}
function firestoreDocUrl() {
  return `https://firestore.googleapis.com/v1/projects/${storageSA.project_id}/databases/(default)/documents/${STORAGE_COLLECTION}/${encodeURIComponent(STORAGE_DOC_ID)}`;
}
// Returns the stored JSON string, null when the doc does not exist;
// throws on any other failure (caller decides retry policy).
async function firestoreFetchDoc() {
  const token = await getDatastoreToken();
  if (!token) throw new Error('oauth_failed');
  const res = await fetch(firestoreDocUrl(), { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('firestore_get_http_' + res.status);
  const doc = await res.json().catch(() => null);
  const v = doc && doc.fields && doc.fields.state && doc.fields.state.stringValue;
  if (typeof v !== 'string') throw new Error('firestore_doc_malformed');
  return v;
}
async function firestoreWriteDoc(jsonStr) {
  const token = await getDatastoreToken();
  if (!token) throw new Error('oauth_failed');
  const url = firestoreDocUrl() + '?updateMask.fieldPaths=state&updateMask.fieldPaths=updatedAt';
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: {
        state: { stringValue: jsonStr },
        updatedAt: { timestampValue: new Date().toISOString() },
      },
    }),
  });
  if (!res.ok) throw new Error('firestore_patch_http_' + res.status);
}
// ------------------------------------------------- chat-media bytes
// The bytes behind data.media used to live ONLY as files in
// MEDIA_DIR — the same ephemeral disk as data.json — so every
// redeploy/sleep destroyed them while their messages lived on
// ("sent photos never open again"). The byte store is now pluggable
// (media-store.js): MEDIA_BACKEND=file (default) is the historical
// local-dir behavior and the rollback path; MEDIA_BACKEND=firestore
// stores the bytes chunked inside Firestore itself
// ("firestore-chunks": ~700 KB documents in mediaChunks + a manifest
// in mediaMeta per object, sha256-verified on serve), because
// Firebase Storage cannot be enabled on this project without a
// Blaze billing upgrade. Auth reuses getDatastoreToken above — the
// same JWT -> OAuth2 mechanism, datastore scope. The upload cap is
// MEDIA_MAX_BYTES (10 MB) in BOTH modes, so an oversize upload gets
// the historical 413 shape regardless of backend. MEDIA_BACKEND=
// firestore with no valid service account warns and falls back to
// file, mirroring STORAGE_MODE's never-break-requests policy.
const MEDIA_BACKEND = (() => {
  const req = String(process.env.MEDIA_BACKEND || '').toLowerCase();
  if (req === 'firestore') {
    if (storageSA) return 'firestore';
    console.warn('[media] MEDIA_BACKEND=firestore requested but FIREBASE_SERVICE_ACCOUNT is missing/invalid — falling back to file backend');
  }
  return 'file';
})();
const mediaStore = createMediaStore({
  backend: MEDIA_BACKEND,
  mediaDir: MEDIA_DIR,
  serviceAccount: storageSA,
  getToken: getDatastoreToken,
});
let persistTimer = null;
let persistInFlight = false;
let persistDirty = false;
let bootHydrateFailed = false; // boot fetch errored (vs doc-missing): first write re-checks the remote
let bootGuardDone = false;
let sizeWarnedAt = 0;
function scheduleFirestorePersist() {
  if (STORAGE_MODE !== 'firestore' || persistTimer) return; // a pending write serializes the latest state anyway
  persistTimer = setTimeout(() => { persistTimer = null; runFirestorePersist(); }, 1000);
  if (persistTimer.unref) persistTimer.unref();
}
async function runFirestorePersist() {
  if (persistInFlight) { persistDirty = true; return; }
  persistInFlight = true;
  try {
    if (bootHydrateFailed && !bootGuardDone) {
      // Boot could not read the remote (transient network), and this
      // process may be holding an empty local state recycled from a
      // wiped disk. Before the first write, look once more: if the
      // remote holds real data and local is empty, hydrate instead of
      // clobbering the only durable copy.
      bootGuardDone = true;
      try {
        const remote = await firestoreFetchDoc();
        if (remote != null && isDataEmpty(data) && !isDataEmpty(normalizeData(JSON.parse(remote)))) {
          replaceData(JSON.parse(remote));
          saveLocalOnly();
          console.warn('[storage] boot hydration had failed; recovered state from Firestore at first persist — overwrite skipped');
          return;
        }
      } catch {}
    }
    const jsonStr = JSON.stringify(data);
    const bytes = Buffer.byteLength(jsonStr);
    if (bytes > STORAGE_SIZE_WARN_BYTES && Date.now() - sizeWarnedAt > 10 * 60 * 1000) {
      sizeWarnedAt = Date.now();
      console.warn(`[storage] WARNING: serialized state is ${bytes} bytes, over the ${STORAGE_SIZE_WARN_BYTES}-byte watch level (Firestore document limit ~1 MiB). Chunking is NOT implemented in this round.`);
    }
    await firestoreWriteDoc(jsonStr);
    storageStats.lastPersistOk = true;
    storageStats.lastPersistAt = new Date().toISOString();
  } catch (e) {
    storageStats.lastPersistOk = false;
    storageStats.persistErrors++;
    console.warn('[storage] firestore persist failed:', (e && e.message) || e);
  } finally {
    persistInFlight = false;
    if (persistDirty) {
      persistDirty = false;
      const t = setTimeout(runFirestorePersist, 250);
      if (t.unref) t.unref();
    }
  }
}
// Boot-time hydration (main module only): Firestore first, with a few
// retries while the network warms. A missing doc means "authoritative
// empty" — start from local and push it up on the first save. Any
// other failure after retries leaves the local state in charge and
// arms the first-write guard above.
async function hydrateFromFirestore() {
  const delays = [500, 1000, 2000, 4000, 8000];
  for (let attempt = 0; ; attempt++) {
    try {
      const remote = await firestoreFetchDoc();
      if (remote == null) {
        console.log('[storage] no Firestore state doc yet — starting from local data');
        scheduleFirestorePersist(); // push the local state up promptly
        return;
      }
      replaceData(JSON.parse(remote));
      saveLocalOnly(); // warm cache mirrors the durable copy
      console.log('[storage] state hydrated from Firestore');
      return;
    } catch (e) {
      if (attempt >= delays.length) {
        bootHydrateFailed = true;
        console.warn('[storage] Firestore hydration failed after retries — continuing with local data:', (e && e.message) || e);
        return;
      }
      await new Promise(r => setTimeout(r, delays[attempt]));
    }
  }
}

// ---------------------------------------------------------------- live state
const liveChildren = new Map();  // childId -> ws
const childWentOfflineAt = new Map();  // childId -> ms when its live socket was lost (presence grace)
const liveParents = new Map();   // parentId -> Set<ws>
const sessions = new Map();      // sessionId -> {id, parentId, childId, parentWs, childWs, sig, dbg}
const childDebug = new Map();    // childId -> [debug strings] (diagnostics, memory-only)
const parentDebug = new Map();   // parentId -> [debug strings] (diagnostics, memory-only)
const lastSessions = [];         // archived session summaries after close (diagnostics)
const wakePendings = new Map();  // `${parentId}|${childId}|${kind}` -> held parent->child wake-and-wait request
const parentWakePendings = new Map();  // childId -> held child->parent call wake-and-wait request
const wakeLog = [];              // bounded wake-attempt log (diagnostics, memory-only; never token values)
const WAKE_LOG_CAP = 50;
let wakeAttempts = 0;            // diagnostics: wake pushes handed to the wake service

// ---------------------------------------------------------------- FCM wake
// Wake-and-wait (step-3; the pend/flush machinery is ported from the
// test server, where it was proven in the 2.7/2.8 line): when a start
// request targets a party with no live socket, the request is HELD as
// a wake pending instead of failing instantly, while a high-priority
// FCM data push tries to wake that party's app so its reconnect logic
// can bring the socket back. When the socket registers, the flush
// re-validates each held request (requester socket still open, pairing
// intact, neither party busy) and executes the original start logic; a
// request whose target never appears fails with the same offline error
// shape as before, after WAKE_WAIT_MS. Chat wakes stay fire-and-
// forget (the message is already stored). Every attempt is logged to
// the bounded wakeLog (target id + reason + FCM result + wait outcome;
// token values are NEVER logged), and an FCM answer that the token is
// dead (UNREGISTERED / INVALID_ARGUMENT) prunes it from the store so
// later actions do not keep pushing at a corpse. The push itself is
// throttled per target inside the wake service. No-op when FCM is
// unconfigured or the target never registered a token (a held request
// still waits — the wake is best-effort).
const wakeService = fcm.createWakeService(fcm.defaultSender(), { windowMs: 20000 });
function socketStale(ws) {
  return !!ws && (Date.now() - (ws.lastPongAt || 0) > STALE_SOCKET_MS);
}
function childSocketOpen(childId) {
  const cws = liveChildren.get(childId);
  return !!cws && cws.readyState === 1 && !socketStale(cws);
}
// If the child's registered socket has been silent past STALE_SOCKET_MS,
// reap it on the spot (terminate + unregister) and report true, so the
// caller routes exactly like the offline case — wake push + held
// request — instead of pouring the request into a dead socket.
function reapStaleChildSocket(childId) {
  const cws = liveChildren.get(childId);
  if (!cws || !socketStale(cws)) return false;
  liveChildren.delete(childId);
  try { cws.terminate(); } catch {}
  return true;
}
function parentSocketOpen(parentId) {
  const set = liveParents.get(parentId);
  return !!set && [...set].some(w => w.readyState === 1);
}
// Append one entry to the bounded wake log and return it; the FCM
// result and the wait outcome are filled in as they resolve.
function recordWake(role, targetId, reason, fcmState) {
  const entry = { ts: new Date().toISOString(), role, target: targetId, reason, fcm: fcmState, errorCode: null, wait: null };
  wakeLog.push(entry);
  while (wakeLog.length > WAKE_LOG_CAP) wakeLog.shift();
  return entry;
}
// FCM says the token itself is dead: clear it from the record (only if
// it is still the exact token we sent to — a rotation may already have
// replaced it) and persist.
function pruneDeadToken(rec, tokenSent) {
  try {
    if (rec && rec.fcmToken && rec.fcmToken === tokenSent) {
      rec.fcmToken = null;
      save();
    }
  } catch {}
}
// Fire one wake push at a child/parent record. Always returns the log
// entry (fcm: 'no_token' when there is nothing to send to); the entry's
// fcm/errorCode fields are updated when the send resolves. Never throws.
// opts.repush marks a continuation push of an already-held wake-and-wait
// (see armRepushes); opts.bypassThrottle gives it a one-off throttle key
// so the wake service never suppresses it — a re-push exists precisely
// because the first push did not bring the target back.
// Throttle keying (fix 2026-11-07): per (target, reason), not per target
// — field evidence 12:20 +06: a Call wake was 'throttled' seconds after
// unrelated Listen/Data wakes, so a genuinely different action never
// reached the phone. Same-reason repeats still throttle against each
// other inside the wake service's window.
function attemptWake(role, rec, reason, opts) {
  if (!rec) return null;
  if (!rec.fcmToken) return recordWake(role, rec.id, reason, 'no_token');
  const entry = recordWake(role, rec.id, reason, 'sent');
  if (opts && opts.repush) entry.repush = true;
  wakeAttempts++;
  const token = rec.fcmToken;
  let key = (role === 'parent' ? 'parent:' + rec.id : rec.id) + '|' + reason;
  if (opts && opts.bypassThrottle) key += '|x' + Date.now();
  wakeService.wakeDetailed(key, token, { reason }).then(r => {
    if (r.throttled) entry.fcm = 'throttled';
    else if (r.dead) { entry.fcm = 'dead'; entry.errorCode = r.errorCode; pruneDeadToken(rec, token); }
    else if (r.ok) entry.fcm = 'ok';
    else { entry.fcm = 'error'; entry.errorCode = r.errorCode || (r.status ? 'http_' + r.status : null); }
    console.log(`[wake] ${role} ${rec.id} reason=${reason} -> ${entry.fcm}${entry.errorCode ? ' (' + entry.errorCode + ')' : ''}`);
  }).catch(() => { entry.fcm = 'error'; });
  return entry;
}
function maybeWakeChild(child, reason) {
  try {
    if (!child || !child.fcmToken) return;
    if (childSocketOpen(child.id)) return;
    const entry = attemptWake('child', child, reason || 'wake');
    if (entry) entry.wait = 'not_waited';
  } catch {}
}
function maybeWakeParent(parent, reason) {
  try {
    if (!parent || !parent.fcmToken) return;
    if (parentSocketOpen(parent.id)) return;
    const entry = attemptWake('parent', parent, reason || 'wake');
    if (entry) entry.wait = 'not_waited';
  } catch {}
}

// The start-failure response for a held (or unholdable) start request:
// calls report busy as call_busy; listen/camera use their *_error shape
// for every reason. Offline uses the same *_error/call_error shapes the
// instant-fail path always sent.
function sendStartFailure(parentWs, kind, childId, reason) {
  if (kind === 'call' && reason === 'busy') return sendWs(parentWs, { type: 'call_busy', childId });
  return sendWs(parentWs, { type: kind + '_error', childId, reason });
}
function pendingKey(parentId, childId, kind) { return `${parentId}|${childId}|${kind}`; }
// Re-push schedule inside one wake-and-wait window (fix 2026-11-07):
// field evidence (Infinix X6880, 12:19 +06) — the first push delivered
// ('ok') but the phone's system ate the app's background start (an
// FGS-start-timeout crash is on record for the device), so nobody was
// home when the server knocked once. Extra pushes at 30% and 70% of the
// wait give the phone's revival paths (accessibility anchor, job,
// watchdog alarm) more than one doorbell inside the SAME wait — the
// parent-visible WAKE_WAIT_MS is unchanged. fire() re-validates that
// its pending is still the registered one and the target still has no
// live socket; every drop/flush/timeout path clears the timers.
const REPUSH_AT_MS = [Math.floor(WAKE_WAIT_MS * 0.3), Math.floor(WAKE_WAIT_MS * 0.7)];
function armRepushes(p, fire) {
  p.repushTimers = REPUSH_AT_MS.map(ms => {
    const t = setTimeout(() => { try { fire(); } catch {} }, ms);
    if (t.unref) t.unref();
    return t;
  });
}
function clearRepushes(p) {
  if (p && p.repushTimers) {
    for (const t of p.repushTimers) clearTimeout(t);
    p.repushTimers = [];
  }
}
function dropWakePending(key) {
  const p = wakePendings.get(key);
  if (p) {
    clearTimeout(p.timer); clearRepushes(p); wakePendings.delete(key);
    if (p.logEntry && p.logEntry.wait === 'waiting') p.logEntry.wait = 'cancelled';
  }
  return p || null;
}
// Hold a parent-initiated start request for an offline child. One
// pending per (parentId, childId, kind): a repeat request of the same
// kind replaces the old one (its timer is cleared; the parent simply
// keeps waiting and gets a fresh wake_pending).
function pendWakeRequest(parentWs, child, kind, extra) {
  const key = pendingKey(parentWs.parentId, child.id, kind);
  dropWakePending(key);
  const p = {
    kind, parentWs, parentId: parentWs.parentId, childId: child.id,
    facing: extra && extra.facing ? extra.facing : undefined,
    media: extra && extra.media ? extra.media : undefined,
    logEntry: extra && extra.logEntry ? extra.logEntry : null,
    createdAt: Date.now(), timer: null,
  };
  if (p.logEntry) p.logEntry.wait = 'waiting';
  p.timer = setTimeout(() => {
    if (wakePendings.get(key) !== p) return; // replaced or flushed
    wakePendings.delete(key);
    clearRepushes(p);
    if (p.logEntry) p.logEntry.wait = 'timeout';
    sendStartFailure(p.parentWs, kind, p.childId, 'offline');
  }, WAKE_WAIT_MS);
  if (p.timer.unref) p.timer.unref();
  armRepushes(p, () => {
    if (wakePendings.get(key) !== p) return; // replaced, flushed or timed out
    if (childSocketOpen(p.childId)) return;
    const rec = data.children.find(c => c.id === p.childId);
    attemptWake('child', rec, kind, { repush: true, bypassThrottle: true });
  });
  wakePendings.set(key, p);
  sendWs(parentWs, { type: 'wake_pending', kind, childId: child.id });
}
// Execute every held request for a child whose socket just registered.
// Each pending is re-validated before it runs; a busy pair gets the
// busy response, a vanished parent or pairing drops the request
// silently (the close/removal paths normally clear pendings first).
function flushWakePendings(child) {
  const cws = liveChildren.get(child.id);
  if (!cws || cws.readyState !== 1) return;
  for (const [key, p] of [...wakePendings.entries()]) {
    if (p.childId !== child.id) continue;
    wakePendings.delete(key);
    clearTimeout(p.timer);
    clearRepushes(p);
    if (p.logEntry) p.logEntry.wait = 'connected';
    if (!p.parentWs || p.parentWs.readyState !== 1) continue;
    const fresh = data.children.find(c => c.id === p.childId);
    if (!fresh || fresh.parentId !== p.parentId) continue;
    replaceOwnMonitoringSessions(p.parentId, p.childId);
    if (partyBusy(p.parentId, p.childId)) {
      sendStartFailure(p.parentWs, p.kind, p.childId, 'busy');
      continue;
    }
    if (p.kind === 'listen') startListenSession(p.parentWs, fresh, cws);
    else if (p.kind === 'camera') startCameraSession(p.parentWs, fresh, cws, p.facing);
    else if (p.kind === 'call') {
      const s = startCallSession(p.parentWs, fresh, cws, p.media);
      sendWs(p.parentWs, { type: 'call_ringing', sessionId: s.id, childId: p.childId });
    }
  }
}
// Parent socket went away: its held requests die with it, silently.
function clearWakePendingsForParentWs(ws) {
  for (const [key, p] of [...wakePendings.entries()]) {
    if (p.parentWs === ws) dropWakePending(key);
  }
}

// ---- Data sections (feature 2026-11-06): a bound parent views the
// child's Contacts / Call list / SMS / Gallery, fetched LIVE from the
// phone. Pure relay, exactly like the location forward: the server
// validates the control binding, wakes an offline child and holds the
// request (same wake-and-wait shape as calls), forwards the request,
// routes the response back, and stores NOTHING — lists and photos pass
// through and are gone. Access rule is the listen/camera rule: only the
// child's bound parent (child.parentId) may ask.
const DATA_SECTIONS = new Set(['contacts', 'calls', 'sms', 'gallery', 'photo']);
const DATA_WAIT_MS = WAKE_WAIT_MS;
const DATA_INFLIGHT_MS = 120000;
const dataPendings = new Map();  // reqId -> request held while the child is woken
const dataInflight = new Map();  // reqId -> request forwarded, awaiting the child's response

function sendDataError(parentWs, reqId, childId, section, reason) {
  sendWs(parentWs, { type: 'data_error', reqId, childId, section, reason });
}

function forwardDataRequest(cws, p) {
  const inflight = { parentWs: p.parentWs, parentId: p.parentId, childId: p.childId, section: p.section, timer: null };
  inflight.timer = setTimeout(() => {
    if (dataInflight.get(p.reqId) !== inflight) return;
    dataInflight.delete(p.reqId);
    sendDataError(inflight.parentWs, p.reqId, inflight.childId, inflight.section, 'timeout');
  }, DATA_INFLIGHT_MS);
  if (inflight.timer.unref) inflight.timer.unref();
  dataInflight.set(p.reqId, inflight);
  const msg = { type: 'data_request', reqId: p.reqId, section: p.section, page: p.page };
  if (p.photoId) msg.photoId = p.photoId;
  sendWs(cws, msg);
}

function pendDataRequest(parentWs, req) {
  dropDataPending(req.reqId);
  const p = { ...req, parentWs, parentId: parentWs.parentId, createdAt: Date.now(), timer: null };
  p.timer = setTimeout(() => {
    if (dataPendings.get(req.reqId) !== p) return;
    dataPendings.delete(req.reqId);
    clearRepushes(p);
    sendDataError(p.parentWs, req.reqId, p.childId, p.section, 'offline');
  }, DATA_WAIT_MS);
  if (p.timer.unref) p.timer.unref();
  armRepushes(p, () => {
    if (dataPendings.get(req.reqId) !== p) return;
    if (childSocketOpen(p.childId)) return;
    const rec = data.children.find(c => c.id === p.childId);
    attemptWake('child', rec, 'data', { repush: true, bypassThrottle: true });
  });
  dataPendings.set(req.reqId, p);
  sendWs(parentWs, { type: 'data_pending', reqId: req.reqId, childId: req.childId, section: req.section });
}

function dropDataPending(reqId) {
  const p = dataPendings.get(reqId);
  if (p) { clearTimeout(p.timer); clearRepushes(p); dataPendings.delete(reqId); }
}

// Execute held data requests for a child whose socket just registered
// (called beside flushWakePendings). Re-validates the binding first.
function flushDataPendings(child) {
  const cws = liveChildren.get(child.id);
  if (!cws || cws.readyState !== 1) return;
  for (const [reqId, p] of [...dataPendings.entries()]) {
    if (p.childId !== child.id) continue;
    dataPendings.delete(reqId);
    clearTimeout(p.timer);
    clearRepushes(p);
    if (!p.parentWs || p.parentWs.readyState !== 1) continue;
    const fresh = data.children.find(c => c.id === p.childId);
    if (!fresh || fresh.parentId !== p.parentId) continue;
    forwardDataRequest(cws, p);
  }
}

// Parent socket went away: its data requests die with it, silently.
function clearDataForParentWs(ws) {
  for (const [reqId, p] of [...dataPendings.entries()]) {
    if (p.parentWs === ws) dropDataPending(reqId);
  }
  for (const [reqId, f] of [...dataInflight.entries()]) {
    if (f.parentWs === ws) { clearTimeout(f.timer); dataInflight.delete(reqId); }
  }
}
// Hold a child-initiated call for an offline parent (the mirror image
// of pendWakeRequest). One pending per child — a child can only be
// placing one outgoing call. The child hears nothing while waiting;
// when the parent registers, flushParentWakePendings() runs the
// original call_start logic.
function pendParentWake(childWs, child, media, logEntry) {
  dropParentWakePending(child.id);
  const p = {
    childWs, parentId: child.parentId, childId: child.id, media,
    logEntry: logEntry || null, createdAt: Date.now(), timer: null,
  };
  if (p.logEntry) p.logEntry.wait = 'waiting';
  p.timer = setTimeout(() => {
    if (parentWakePendings.get(child.id) !== p) return; // replaced or flushed
    parentWakePendings.delete(child.id);
    clearRepushes(p);
    if (p.logEntry) p.logEntry.wait = 'timeout';
    sendWs(p.childWs, { type: 'call_error', reason: 'offline' });
  }, WAKE_WAIT_MS);
  if (p.timer.unref) p.timer.unref();
  armRepushes(p, () => {
    if (parentWakePendings.get(child.id) !== p) return;
    if (parentSocketOpen(p.parentId)) return;
    const rec = data.parents.find(x => x.id === p.parentId);
    attemptWake('parent', rec, 'call', { repush: true, bypassThrottle: true });
  });
  parentWakePendings.set(child.id, p);
}
function dropParentWakePending(childId, outcome) {
  const p = parentWakePendings.get(childId);
  if (p) {
    clearTimeout(p.timer); clearRepushes(p); parentWakePendings.delete(childId);
    if (p.logEntry && p.logEntry.wait === 'waiting') p.logEntry.wait = outcome || 'cancelled';
  }
  return p || null;
}
// Execute held child->parent calls for a parent whose socket just
// registered: re-validate (child still connected, pairing intact),
// then ring every live parent socket exactly like the immediate path.
function flushParentWakePendings(parent) {
  for (const [key, p] of [...parentWakePendings.entries()]) {
    if (p.parentId !== parent.id) continue;
    parentWakePendings.delete(key);
    clearTimeout(p.timer);
    clearRepushes(p);
    if (p.logEntry) p.logEntry.wait = 'connected';
    const cws = liveChildren.get(p.childId);
    if (!cws || cws.readyState !== 1) continue;
    const fresh = data.children.find(c => c.id === p.childId);
    if (!fresh || fresh.parentId !== parent.id) continue;
    if (partyBusy(parent.id, p.childId)) {
      sendWs(cws, { type: 'call_busy', childId: p.childId });
      continue;
    }
    const s = createSession({ kind: 'call', state: 'ringing', media: p.media, parentId: parent.id, childId: p.childId, parentWs: null, childWs: cws, initiatorRole: 'child' });
    armRingTimer(s);
    const set = liveParents.get(parent.id);
    if (set) for (const pws of set) sendWs(pws, { type: 'call_invite', sessionId: s.id, media: p.media, fromId: p.childId });
  }
}

// ---------------------------------------------------------------- helpers
function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', d => { body += d; if (body.length > 1_000_000) req.destroy(); });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
// Raw-body reader for media uploads: drains the request fully even when it
// exceeds the cap (so the client gets a clean 413 instead of a hang).
function readRawBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0, tooLarge = false;
    req.on('data', d => {
      total += d.length;
      if (total > cap) { tooLarge = true; chunks.length = 0; return; }
      if (!tooLarge) chunks.push(d);
    });
    req.on('end', () => resolve({ buf: tooLarge ? null : Buffer.concat(chunks), size: total, tooLarge }));
    req.on('error', reject);
  });
}
function newToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}
function checkPassword(password, parent) {
  try {
    const h = crypto.scryptSync(String(password), parent.salt, 64);
    const stored = Buffer.from(parent.passwordHash, 'hex');
    return h.length === stored.length && crypto.timingSafeEqual(h, stored);
  } catch { return false; }
}
function authParent(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const parentId = token ? data.tokens[token] : null;
  if (!parentId) return null;
  return data.parents.find(p => p.id === parentId) || null;
}
function authChild(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  return data.children.find(c => c.deviceToken === token) || null;
}
function childOnline(c) {
  // Live socket OR still inside the reconnect grace window.
  if (liveChildren.has(c.id)) return true;
  const t = childWentOfflineAt.get(c.id);
  return t != null && (Date.now() - t) < PRESENCE_GRACE_MS;
}
// Derived push reachability for parents: 'ok' once the child has an
// FCM token on file, 'fail' when the child's app reported its Firebase
// init failed on that phone, else 'none'. The token itself never leaves
// the server.
function pushStateOf(c) {
  if (c.fcmToken) return 'ok';
  if (c.fcmState === 'fail') return 'fail';
  return 'none';
}
function childView(c) {
  return {
    id: c.id,
    name: c.name,
    model: c.model,
    // Number account (number system): the address a parent used to add
    // this device, or null for invite/code-paired devices.
    number: c.number || null,
    push: pushStateOf(c),
    online: childOnline(c),
    lastSeen: c.lastSeen || null,
    battery: c.battery ?? null,
    permissions: c.permissions || null,
    lastLocation: c.lastLocation || null,
  };
}
function addEvent(child, type, detail) {
  child.events = child.events || [];
  child.events.push({ ts: new Date().toISOString(), type: String(type), detail: detail == null ? '' : String(detail) });
  if (child.events.length > EVENTS_CAP) child.events = child.events.slice(-EVENTS_CAP);
}
function findOwnChild(parent, id) {
  // Missing OR someone else's child both look the same to the caller: 404.
  const c = data.children.find(x => x.id === id);
  if (!c || c.parentId !== parent.id) return null;
  return c;
}
function sendWs(ws, obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}
function archiveSession(session) {
  lastSessions.push({ id: session.id.slice(0, 8), kind: session.kind || 'listen', childId: session.childId,
    sig: session.sig, dbg: session.dbg, closedAt: new Date().toISOString() });
  while (lastSessions.length > 5) lastSessions.shift();
}
function closeSession(session, notifyWsList, reason) {
  if (session.ringTimer) { clearTimeout(session.ringTimer); session.ringTimer = null; }
  sessions.delete(session.id);
  archiveSession(session);
  for (const peer of notifyWsList || []) {
    sendWs(peer, { type: 'session_closed', sessionId: session.id, reason: reason || 'closed' });
  }
}
function createSession(fields) {
  const session = Object.assign({
    id: crypto.randomBytes(16).toString('hex'), createdAt: Date.now(),
    kind: 'listen', state: 'active', media: null, initiatorRole: null, ringTimer: null,
    parentWs: null, childWs: null,
    sig: { offer: 0, answer: 0, childIce: {}, parentIce: {} }, dbg: [],
  }, fields);
  sessions.set(session.id, session);
  return session;
}
// Sockets that are parties to a session. For a child-initiated call that has
// not been accepted yet, parentWs is unbound: every live parent socket is a
// potential party (they all got the invite and any of them may accept).
function peerSockets(session, excludeWs) {
  const out = new Set();
  // Contact sessions (number system): the two parties are child sockets.
  if (session.contact) {
    if (session.aWs) out.add(session.aWs);
    if (session.bWs) out.add(session.bWs);
  }
  if (session.parentWs) out.add(session.parentWs);
  else if (session.kind === 'call') {
    const set = liveParents.get(session.parentId);
    if (set) for (const w of set) out.add(w);
  }
  if (session.childWs) out.add(session.childWs);
  if (excludeWs) out.delete(excludeWs);
  return [...out];
}
// Busy rule (SPEC-V2 §1b): a parent or child already in ANY session
// (listen/camera/call) cannot join a new one.
function partyBusy(parentId, childId) {
  for (const s of sessions.values()) {
    if (s.parentId === parentId || s.childId === childId ||
        s.aChildId === childId || s.bChildId === childId) return true;
  }
  return false;
}
// Ghost replace (2026-11-07, owner report 12:48 +06): the requesting
// parent's OWN leftover listen/camera session with this same child must
// never block their new request — the leftover is their own abandoned
// screen (offer never arrived, or Stop never pressed), and the new tap
// IS the intent to replace it. Closed with reason 'replaced'. Call
// sessions are never replaced (a ringing or live call keeps the pair
// busy), and sessions of any other party are never touched — those
// still report busy through partyBusy exactly as before.
function replaceOwnMonitoringSessions(parentId, childId) {
  for (const s of [...sessions.values()]) {
    if (s.kind === 'call') continue;
    if (s.parentId === parentId && s.childId === childId) {
      closeSession(s, peerSockets(s), 'replaced');
    }
  }
}
// Is this socket one of the two parties of the session? Contact
// sessions (number system) party on two CHILD sockets (aWs = caller,
// bWs = callee); every other session parties on parentWs/childWs.
function sessionParty(session, ws) {
  if (session.contact) return ws === session.aWs || ws === session.bWs;
  return ws === session.parentWs || ws === session.childWs;
}
// The OTHER party's socket (signalling relay target), or null.
function sessionPeer(session, ws) {
  if (session.contact) return ws === session.aWs ? session.bWs : (ws === session.bWs ? session.aWs : null);
  return ws === session.parentWs ? session.childWs : session.parentWs;
}
// A child is busy when it parties ANY live session, in any role
// (bound child in a parent session, or either side of a contact call).
function childBusyAny(childId) {
  for (const s of sessions.values()) {
    if (s.childId === childId || s.aChildId === childId || s.bChildId === childId) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Number system (owner design 2026-11-04): a child can register an
// account with its phone NUMBER + a self-set password instead of being
// paired by invite/code. The number is only an ADDRESS: the account's
// secret deviceToken stays the real credential (rotated on every
// password login), a parent binds the device by entering the number,
// and two number-registered children can be CONTACTS (call/chat only —
// the control kinds stay gated to parent bindings; the listen/camera
// handlers below refuse any non-parent socket outright). Invite-link
// and code pairing are unchanged. Passwords are stored ONLY as scrypt
// hashes (the same hashPassword/checkPassword helpers the parent
// accounts use — Node built-in crypto, no new dependencies).
// ---------------------------------------------------------------------------
// The legacy normalizer, kept byte-identical (link release step 1,
// 2026-11-05): every input WITHOUT an explicit international prefix
// ('+' or '00') funnels through here exactly as before, so all
// existing accounts — above all the BD forms below — keep matching.
function normalizeNumberLegacy(raw) {
  const s = String(raw == null ? '' : raw).replace(/[\s\-()]/g, '');
  if (!/^\+?\d{6,15}$/.test(s)) return null;
  // Bangladeshi equivalence (owner audit 2026-11-05, decision #3):
  // the same mobile number written in local (01...), bare-country
  // (8801...) or international (+8801...) form is ONE address. The
  // canonical stored form is +880...; every entry point (register,
  // login, add-by-number, add-contact) funnels through here, so
  // duplicates across forms collide and lookups match across forms.
  if (s[0] !== '+') {
    if (/^8801\d{9}$/.test(s)) return '+' + s;
    if (/^01\d{9}$/.test(s)) return '+880' + s.slice(1);
  }
  return s;
}
// ---------------------------------------------------------------------------
// International canonicalization (link release step 1, owner design
// 2026-11-05): the apps now offer a country picker, so a number can
// arrive from ANY country as (dial code + national digits the user
// typed). shared/countries.json — the same table both apps ship — is
// the single source of truth for the dial-code set. An explicitly
// international input ('+' or '00' prefix) is canonicalized to E.164:
// longest-match the dial code, collapse a duplicated dial code the
// user pasted ("+880 880 1712..."), strip ONE trunk leading 0 from
// the national part ("+91 09876543210" -> "+919876543210"). Anything
// without an international prefix goes through the legacy path above,
// byte-identical — canonical stored forms therefore never change for
// existing accounts (+880... and +1... canonicalize to themselves).
// ---------------------------------------------------------------------------
const COUNTRY_DIALS = (() => {
  try {
    const candidates = [
      path.join(__dirname, 'countries.json'),
      path.join(__dirname, '..', 'shared', 'countries.json'),
      path.join(__dirname, 'shared', 'countries.json'),
    ];
    const file = candidates.find((p) => fs.existsSync(p));
    if (!file) throw new Error('countries.json not found in any candidate location');
    const list = JSON.parse(fs.readFileSync(file, 'utf8'));
    const set = new Set();
    for (const c of list) { const d = String(c && c.dial || ''); if (/^\d{1,4}$/.test(d)) set.add(d); }
    // Longest first, so e.g. "1242" (Bahamas) wins over "1" (NANP).
    return [...set].sort((a, b) => b.length - a.length);
  } catch (e) {
    console.error('[numbers] shared/countries.json unavailable; international inputs pass through as before:', e.message);
    return [];
  }
})();
function matchDialCode(digits) {
  for (const d of COUNTRY_DIALS) if (digits.startsWith(d)) return d;
  return null;
}
function canonicalizeNumber(raw) {
  const s = String(raw == null ? '' : raw).replace(/[\s\-()]/g, '');
  let digits = null;
  if (s[0] === '+') digits = s.slice(1);
  else if (s.startsWith('00')) digits = s.slice(2);
  if (digits === null) return normalizeNumberLegacy(raw);
  if (!/^\d+$/.test(digits)) return null;
  const dial = matchDialCode(digits);
  if (!dial) {
    // Unknown country code: the historical pass-through, unchanged
    // (any 6-15 digit international string is kept as typed).
    return (digits.length >= 6 && digits.length <= 15) ? '+' + digits : null;
  }
  let national = digits.slice(dial.length);
  // A full international number pasted after the picked country code
  // ("+880 880 1712..."): collapse the duplication. The guard is
  // deliberately strict — the pre-collapse national part must be at
  // least 12 digits (longer than any genuine national number) and
  // removing the duplicate must leave a plausible 6-12 digits — so a
  // genuine number whose national part merely STARTS with the dial
  // digits (e.g. an Indian mobile beginning 91...) is never mangled.
  while (national.length >= 12 && national.startsWith(dial) && national.length - dial.length >= 6 && national.length - dial.length <= 12) {
    national = national.slice(dial.length);
  }
  // One trunk leading 0 ("+966 05..." -> "+9665...").
  if (national[0] === '0') national = national.slice(1);
  const total = dial.length + national.length;
  if (!national || total < 7 || total > 15) return null; // E.164 bounds
  return '+' + dial + national;
}
// Public wrapper: every number entry point (register, login,
// add-by-number, add-contact) calls this, exactly as before.
function normalizeNumber(raw) { return canonicalizeNumber(raw); }
function contactsOf(child) {
  if (!Array.isArray(child.contacts)) child.contacts = [];
  return child.contacts;
}
function areContacts(aId, bId) {
  const a = data.children.find(c => c.id === aId);
  return !!a && contactsOf(a).includes(bId);
}
// Chat store key for a contact pair (device-pair keyed, order-free).
function contactKey(aId, bId) { return aId < bId ? `c:${aId}:${bId}` : `c:${bId}:${aId}`; }
function contactView(c) {
  return {
    childId: c.id,
    number: c.number || null,
    name: c.name,
    model: c.model || '',
    online: childOnline(c),
  };
}
// Session starters shared by the immediate (child connected) path and
// the wake-and-wait flush, so both produce byte-identical messages.
function startListenSession(parentWs, child, cws) {
  const session = createSession({ kind: 'listen', parentId: parentWs.parentId, childId: child.id, parentWs, childWs: cws, initiatorRole: 'parent' });
  sendWs(cws, { type: 'listen_start', sessionId: session.id, parentId: parentWs.parentId });
  sendWs(parentWs, { type: 'listen_ready', sessionId: session.id, childId: child.id });
  return session;
}
function startCameraSession(parentWs, child, cws, facing) {
  const s = createSession({ kind: 'camera', parentId: parentWs.parentId, childId: child.id, parentWs, childWs: cws, initiatorRole: 'parent' });
  sendWs(cws, { type: 'camera_start', sessionId: s.id, parentId: parentWs.parentId, facing });
  sendWs(parentWs, { type: 'camera_started', sessionId: s.id, childId: child.id, facing });
  return s;
}
function startCallSession(parentWs, child, cws, media) {
  const s = createSession({ kind: 'call', state: 'ringing', media, parentId: parentWs.parentId, childId: child.id, parentWs, childWs: cws, initiatorRole: 'parent' });
  armRingTimer(s);
  sendWs(cws, { type: 'call_invite', sessionId: s.id, media, fromId: parentWs.parentId });
  return s;
}
function armRingTimer(session) {
  session.ringTimer = setTimeout(() => {
    if (!sessions.has(session.id)) return;
    closeSession(session, peerSockets(session), 'timeout');
  }, RING_TIMEOUT_MS);
  if (session.ringTimer.unref) session.ringTimer.unref();
}
function findInvite(pred) {
  return Object.values(data.invites).find(pred) || null;
}
function chatKey(parentId, childId) { return `${parentId}:${childId}`; }
// ---- chat v2.3 (full messenger): delete-for-me/everyone, reply/quote,
//      read receipts, typing. Party keys in deletedFor/readBy use the ids
//      already on every stored message: the parent party is keyed by its
//      parentId, the child party by its childId.
// Wire shape of a chat message (history + chat_msg relay): the stored fields
// minus the internal deletedFor/readBy lists, plus a viewer-independent
// `read` flag — true once the message's RECIPIENT (the party that did not
// send it) has marked the pair read via POST /api/chat/read.
function chatView(msg) {
  const recipientKey = msg.fromRole === 'parent' ? msg.childId : msg.parentId;
  return {
    id: msg.id, parentId: msg.parentId, childId: msg.childId,
    fromRole: msg.fromRole, kind: msg.kind, body: msg.body, mediaId: msg.mediaId,
    ts: msg.ts, clientId: msg.clientId ?? null,
    replyTo: msg.replyTo ?? null,
    replySnippet: msg.replySnippet ?? null,
    read: Array.isArray(msg.readBy) && msg.readBy.includes(recipientKey),
  };
}
// Wire shape of a CONTACT chat message (number system): the pair is
// two children, so the parties are named by device id (fromId/toId)
// instead of the parent/child pair fields. `read` is true once the
// recipient (toId) has marked the pair read.
function chatViewC(msg) {
  return {
    id: msg.id, contact: true, fromId: msg.fromId, toId: msg.toId,
    fromRole: 'child', kind: msg.kind, body: msg.body, mediaId: msg.mediaId,
    ts: msg.ts, clientId: msg.clientId ?? null,
    replyTo: msg.replyTo ?? null,
    replySnippet: msg.replySnippet ?? null,
    read: Array.isArray(msg.readBy) && msg.readBy.includes(msg.toId),
  };
}
function chatHistoryByKey(key, viewerKey) {
  const arr = data.chats[key] || [];
  return arr
    .filter(m => !(Array.isArray(m.deletedFor) && m.deletedFor.includes(viewerKey)))
    .map(m => (m.contact ? chatViewC(m) : chatView(m)));
}
function chatHistoryFor(parentId, childId, viewerKey) {
  return chatHistoryByKey(chatKey(parentId, childId), viewerKey);
}
/**
 * Step 3.5: may this caller fetch media [rec] because they party a
 * chat that references it? Parties are read off the referencing
 * messages themselves (parentId/childId for pair chats, fromId/toId
 * for contact chats); a message the caller deleted-for-themselves
 * does not count. This is what lets a contact-chat receiver — or a
 * forward recipient — open media the uploader-owner rule alone
 * would 403, while a true third party still gets 403.
 */
function mediaPartyAllowed(rec, parent, child) {
  const myId = parent ? parent.id : child.id;
  for (const arr of Object.values(data.chats)) {
    if (!Array.isArray(arr)) continue;
    for (const m of arr) {
      if (!m || m.mediaId !== rec.id) continue;
      if (Array.isArray(m.deletedFor) && m.deletedFor.includes(myId)) continue;
      if (m.contact) { if (m.fromId === myId || m.toId === myId) return true; }
      else if (parent ? m.parentId === myId : m.childId === myId) return true;
    }
  }
  return false;
}
// Push a chat event to both live sockets of a contact pair.
function pushContactChatEvent(aId, bId, obj) {
  sendWs(liveChildren.get(aId), obj);
  sendWs(liveChildren.get(bId), obj);
}
// Push a chat event to every live socket of BOTH parties of a pair (parent
// hub sockets + the child socket). Used for chat_delete: the other party
// updates live, and the requester's own other sockets stay in sync.
function pushChatEvent(parentId, childId, obj) {
  const set = liveParents.get(parentId);
  if (set) for (const pws of set) sendWs(pws, obj);
  sendWs(liveChildren.get(childId), obj);
}
// Push a chat event to the OTHER party of a pair only (chat_read, typing).
function pushChatEventToOther(parentId, childId, fromRole, obj) {
  if (fromRole === 'parent') {
    sendWs(liveChildren.get(childId), obj);
  } else {
    const set = liveParents.get(parentId);
    if (set) for (const pws of set) sendWs(pws, obj);
  }
}
function inviteUrl(req, token) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const host = req.headers.host || `127.0.0.1:${PORT}`;
  return `${proto}://${host}/join/${token}`;
}
function inviteView(req, inv) {
  return { token: inv.token, code: inv.code, url: inviteUrl(req, inv.token), expiresAt: new Date(inv.expiresAt).toISOString() };
}

// ------------------------------------------- APK signing-block invite token (v2.1)
// The invite token can travel INSIDE the downloaded APK itself: an extra
// ID-value pair in the APK Signing Block (the Walle/VasDolly channel
// technique). Verifiers ignore unknown pair IDs, and the v2/v3 content
// digests do not cover the signing block, so the signature stays valid.
// Installing + opening such an APK lets the app pair itself — no code, no
// deep link. The file on disk is never modified; injection is in-memory.
const SIG_BLOCK_MAGIC = 'APK Sig Block 42';
const INVITE_PAIR_ID = 0x50434954; // 'PCIT'

// Locate the End Of Central Directory record; returns its offset or -1.
// The EOCD sits in the last 22 + 65535 bytes (fixed part + max comment).
function findEocd(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 22) return -1;
  const window = Math.min(buf.length, 22 + 65535);
  for (let i = buf.length - 22; i >= buf.length - window; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50 && i + 22 + buf.readUInt16LE(i + 20) === buf.length) return i;
  }
  return -1;
}

// Walk the APK Signing Block immediately before the Central Directory.
// Returns { eocd, cdOffset, blockStart, blockSize(BigInt), pairs } or null
// when the buffer has no (valid) v2 signing block.
function readSigBlock(buf) {
  const eocd = findEocd(buf);
  if (eocd < 0) return null;
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset < 32 || cdOffset > buf.length) return null;
  if (buf.toString('latin1', cdOffset - 16, cdOffset) !== SIG_BLOCK_MAGIC) return null;
  const blockSize = buf.readBigUInt64LE(cdOffset - 24); // trailing size field
  const blockStart = cdOffset - (Number(blockSize) + 8);
  if (blockStart < 0 || buf.readBigUInt64LE(blockStart) !== blockSize) return null;
  const pairs = [];
  const pairsEnd = cdOffset - 24; // pairs stop where the footer size begins
  let pos = blockStart + 8;
  while (pos < pairsEnd) {
    if (pos + 8 > pairsEnd) return null;
    const pairLen = buf.readBigUInt64LE(pos);
    if (pairLen < 4n || pos + 8 + Number(pairLen) > pairsEnd) return null;
    pairs.push({ id: buf.readUInt32LE(pos + 8), valueStart: pos + 12, valueLen: Number(pairLen) - 4 });
    pos += 8 + Number(pairLen);
  }
  if (pos !== pairsEnd) return null;
  return { eocd, cdOffset, blockStart, blockSize, pairs };
}

// The invite token embedded in an APK buffer, or null. Never throws.
function parseInjectedToken(buf) {
  try {
    const sb = readSigBlock(buf);
    if (!sb) return null;
    const pair = sb.pairs.find(x => x.id === INVITE_PAIR_ID);
    if (!pair) return null;
    return buf.toString('utf8', pair.valueStart, pair.valueStart + pair.valueLen);
  } catch { return null; }
}

// Returns a NEW buffer: the APK with one extra signing-block pair
// (id INVITE_PAIR_ID, value = token as UTF-8, no terminator) inserted just
// before the block footer. Both block size fields grow by the pair size and
// the EOCD's CD offset shifts by the same delta; every other byte of the
// original (including all CD entries) is preserved verbatim. Null when the
// input has no v2 signing block.
function injectInviteToken(apkBuffer, token) {
  try {
    const sb = readSigBlock(apkBuffer);
    if (!sb) return null;
    const tokenBytes = Buffer.from(String(token), 'utf8');
    const pairLen = 4 + tokenBytes.length;  // pair length counts id + value
    const pairTotal = 8 + pairLen;          // plus the pair's own length field
    const newSize = sb.blockSize + BigInt(pairTotal);
    const oldPairsLen = sb.cdOffset - 24 - (sb.blockStart + 8);
    const block = Buffer.alloc(Number(newSize) + 8);
    block.writeBigUInt64LE(newSize, 0);
    apkBuffer.copy(block, 8, sb.blockStart + 8, sb.cdOffset - 24); // old pairs
    const np = 8 + oldPairsLen;
    block.writeBigUInt64LE(BigInt(pairLen), np);
    block.writeUInt32LE(INVITE_PAIR_ID, np + 8);
    tokenBytes.copy(block, np + 12);
    block.writeBigUInt64LE(newSize, np + pairTotal);               // trailing size
    block.write(SIG_BLOCK_MAGIC, np + pairTotal + 8, 'latin1');    // magic
    const out = Buffer.concat([
      apkBuffer.subarray(0, sb.blockStart),
      block,
      apkBuffer.subarray(sb.cdOffset),
    ]);
    out.writeUInt32LE(sb.cdOffset + pairTotal, sb.eocd + pairTotal + 16); // EOCD: new CD offset
    return out;
  } catch { return null; }
}

// Base APK for /d/<token>: cached in memory, re-read when the file changes.
let baseApkCache = null; // { mtimeMs, size, buf }
function loadBaseApk() {
  const apkPath = path.join(__dirname, 'PrivateCall.apk');
  let st;
  try { st = fs.statSync(apkPath); } catch { return null; }
  if (baseApkCache && baseApkCache.mtimeMs === st.mtimeMs && baseApkCache.size === st.size) {
    return baseApkCache.buf;
  }
  let buf;
  try { buf = fs.readFileSync(apkPath); } catch { return null; }
  baseApkCache = { mtimeMs: st.mtimeMs, size: st.size, buf };
  return buf;
}

// ---------------------------------------------------------------- REST
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    // ---- server
    if (p === '/health' && req.method === 'GET') {
      return json(res, 200, { ok: true, parents: data.parents.length, children: data.children.length, online: liveChildren.size });
    }

    // ---- diagnostics (counts + state words only; no SDP bodies, no IPs)
    if (p === '/debug' && req.method === 'GET') {
      return json(res, 200, {
        ok: true,
        parents: data.parents.length, children: data.children.length, online: liveChildren.size,
        sessions: [...sessions.values()].map(s => ({
          id: s.id.slice(0, 8), kind: s.kind, state: s.state, childId: s.childId, sig: s.sig, dbg: s.dbg,
        })),
        lastSessions,
        childDebug: Object.fromEntries(childDebug),
        parentDebug: Object.fromEntries(parentDebug),
        // Crash self-reports (v2.5.1): only children that reported one.
        childCrash: Object.fromEntries(
          data.children.filter(c => c.lastCrash).map(c => [c.id, c.lastCrash])
        ),
        // Wake diagnostics (step-3): per-state push reachability counts
        // (same derivation as childView.push, plus the parent mirror),
        // wake pushes attempted, requests currently held in wake-and-
        // wait (both directions), and the bounded wake-attempt log
        // (target, reason, FCM result, wait outcome — never tokens).
        pushStates: data.children.reduce((acc, c) => { acc[pushStateOf(c)]++; return acc; }, { ok: 0, fail: 0, none: 0 }),
        parentPushStates: data.parents.reduce((acc, par) => { acc[par.fcmToken ? 'ok' : 'none']++; return acc; }, { ok: 0, none: 0 }),
        wakeAttempts,
        wakePending: wakePendings.size + parentWakePendings.size,
        wakeLog,
        // Number system (additive): registered number accounts and
        // contact pairs (each pair counted once — contacts are stored
        // on both children, so the raw edge count is halved).
        numberAccounts: Object.keys(data.numbers).length,
        contactPairs: Math.floor(
          data.children.reduce((n, c) => n + (Array.isArray(c.contacts) ? c.contacts.length : 0), 0) / 2
        ),
        // Persistent storage (additive): which mode the durable copy
        // uses and whether the last Firestore persist landed.
        storage: {
          mode: STORAGE_MODE,
          lastPersistOk: storageStats.lastPersistOk,
          lastPersistAt: storageStats.lastPersistAt,
          persistErrors: storageStats.persistErrors,
        },
        // Chat-media byte backend (step 3.5, additive): 'file' =
        // local media dir; 'firestore' = chunked Firestore documents
        // ("firestore-chunks", see media-store.js).
        mediaBackend: MEDIA_BACKEND,
      });
    }

    // ---- child APK download (public; the file lives next to server.js)
    if (p === '/app.apk' && req.method === 'GET') {
      const apkPath = path.join(__dirname, 'PrivateCall.apk');
      if (!fs.existsSync(apkPath)) return json(res, 404, { error: 'app file not found' });
      const bytes = fs.readFileSync(apkPath);
      res.writeHead(200, { 'Content-Type': 'application/vnd.android.package-archive', 'Content-Length': bytes.length });
      return res.end(bytes);
    }

    // ---- invite-personalized APK download (public, v2.1): the served APK
    // carries this invite's token in its signing block, so installing +
    // opening it pairs automatically — no code, no "Open in App" step.
    const dMatch = p.match(/^\/d\/([^/]+)$/);
    if (dMatch && req.method === 'GET') {
      const token = decodeURIComponent(dMatch[1]);
      const inv = findInvite(i => i.token === token);
      const valid = !!inv && !inv.used && Date.now() <= inv.expiresAt;
      if (!valid) {
        res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Family Call</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px 20px">
<h1>Family Call</h1>
<p>This invite link is invalid or has expired.</p>
<p>Please ask the person who sent it to create a new link.</p>
</body></html>`);
      }
      const base = loadBaseApk();
      const injected = base && injectInviteToken(base, inv.token);
      if (!injected) {
        res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Family Call</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px 20px">
<h1>Family Call</h1>
<p>The app file is not available on the server yet. Please try again later.</p>
</body></html>`);
      }
      res.writeHead(200, {
        'Content-Type': 'application/vnd.android.package-archive',
        'Content-Disposition': 'attachment; filename="PrivateCall.apk"',
        'Content-Length': injected.length,
      });
      return res.end(injected);
    }

    // ---- invite landing page (public, SPEC-V2 §4)
    const joinMatch = p.match(/^\/join\/([^/]+)$/);
    if (joinMatch && req.method === 'GET') {
      const token = decodeURIComponent(joinMatch[1]);
      const inv = findInvite(i => i.token === token);
      const valid = !!inv && !inv.used && Date.now() <= inv.expiresAt;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      if (!valid) {
        return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Family Call</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px 20px">
<h1>Family Call</h1>
<p>This invite link is invalid or has expired.</p>
<p>Please ask the person who sent it to create a new link.</p>
</body></html>`);
      }
      const apkReady = fs.existsSync(path.join(__dirname, 'PrivateCall.apk'));
      return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Family Call</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px 20px">
<h1>Family Call</h1>
<p>You have been invited to install <b>Family Call</b>.</p>
<p><a href="/d/${inv.token}" style="display:inline-block;background:#12805c;color:#fff;padding:16px 32px;border-radius:10px;text-decoration:none;font-size:20px">Download App</a></p>
${apkReady ? '' : '<p><i>Note: the app file is not available on the server yet.</i></p>'}
<p>After installing, just open the app — it connects by itself.</p>
</body></html>`);
    }

    // ---- parent auth
    if (p === '/api/parents/register' && req.method === 'POST') {
      const { name, phone, password, fcmToken } = await readBody(req).catch(() => null) || {};
      if (!name || !phone || !password) return json(res, 400, { error: 'name, phone and password required' });
      if (String(password).length < 6) return json(res, 400, { error: 'password must be at least 6 characters' });
      if (data.parents.some(x => x.phone === String(phone))) return json(res, 409, { error: 'phone already registered' });
      const salt = crypto.randomBytes(16).toString('hex');
      const parent = {
        id: crypto.randomBytes(8).toString('hex'),
        name: String(name), phone: String(phone),
        salt, passwordHash: hashPassword(password, salt),
        // Parent FCM token (step-3): lets the server wake an offline
        // parent for child-initiated calls/chat. Optional everywhere;
        // also accepted at login and over the parent WS. Never logged.
        fcmToken: fcmToken ? String(fcmToken) : null,
        createdAt: new Date().toISOString(),
      };
      data.parents.push(parent);
      const token = newToken();
      data.tokens[token] = parent.id;
      save();
      return json(res, 201, { parentId: parent.id, token });
    }
    if (p === '/api/parents/login' && req.method === 'POST') {
      const { phone, password, fcmToken } = await readBody(req).catch(() => null) || {};
      const parent = data.parents.find(x => x.phone === String(phone || ''));
      if (!parent || !checkPassword(password || '', parent)) return json(res, 401, { error: 'bad credentials' });
      // Parent FCM token registration/rotation (step-3): non-empty
      // string replaces, explicit empty string clears. Never logged.
      if (typeof fcmToken === 'string') parent.fcmToken = fcmToken || null;
      const token = newToken();
      data.tokens[token] = parent.id;
      save();
      return json(res, 200, { token });
    }
    if (p === '/api/parents/me' && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, { parentId: parent.id, name: parent.name, phone: parent.phone });
    }

    // ---- pairing codes (parent)
    if (p === '/api/pairing-codes' && req.method === 'POST') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      // One active code per parent: a new code invalidates the parent's old one.
      for (const [code, rec] of Object.entries(data.pairingCodes)) {
        if (rec.parentId === parent.id) delete data.pairingCodes[code];
      }
      let code;
      do { code = String(crypto.randomInt(100000, 1000000)); } while (data.pairingCodes[code]);
      const expiresAt = new Date(Date.now() + PAIRING_TTL_MS).toISOString();
      data.pairingCodes[code] = { parentId: parent.id, expiresAt: Date.now() + PAIRING_TTL_MS };
      save();
      return json(res, 200, { code, expiresAt });
    }

    // ---- invite link (parent, SPEC-V2 §4): one active invite per parent
    if (p === '/api/invite' && req.method === 'POST') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      let code;
      do { code = String(crypto.randomInt(100000, 1000000)); }
      while (data.pairingCodes[code] || findInvite(i => i.code === code && !i.used));
      const inv = {
        token: crypto.randomBytes(16).toString('hex'), // 32 hex chars
        code,
        parentId: parent.id,
        expiresAt: Date.now() + INVITE_TTL_MS,
        used: false,
        createdAt: new Date().toISOString(),
      };
      data.invites[parent.id] = inv; // create/replace
      save();
      return json(res, 200, inviteView(req, inv));
    }
    if (p === '/api/invite' && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const inv = data.invites[parent.id];
      if (!inv || inv.used || Date.now() > inv.expiresAt) return json(res, 200, null);
      return json(res, 200, inviteView(req, inv));
    }
    if (p === '/api/invite' && req.method === 'DELETE') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      delete data.invites[parent.id];
      save();
      return json(res, 200, { ok: true });
    }

    // ---- child pairing (public; credential = v1 pairing code, invite code,
    //      or invite token — SPEC-V2 §4). All are single-use.
    if (p === '/api/children/pair' && req.method === 'POST') {
      const { code, token, name, model, fcmToken } = await readBody(req).catch(() => null) || {};
      let parentId = null;
      if (token) {
        const inv = findInvite(i => i.token === String(token));
        if (!inv || inv.used || Date.now() > inv.expiresAt) {
          return json(res, 400, { error: 'invalid or expired invite' });
        }
        inv.used = true; // single use
        parentId = inv.parentId;
      } else if (code) {
        const rec = data.pairingCodes[String(code)];
        if (rec) {
          if (Date.now() > rec.expiresAt) {
            delete data.pairingCodes[String(code)]; save();
            return json(res, 410, { error: 'pairing code expired' });
          }
          delete data.pairingCodes[String(code)]; // single use
          parentId = rec.parentId;
        } else {
          const inv = findInvite(i => i.code === String(code));
          if (!inv || inv.used || Date.now() > inv.expiresAt) {
            return json(res, 400, { error: 'invalid pairing code' });
          }
          inv.used = true; // single use
          parentId = inv.parentId;
        }
      }
      if (!parentId) return json(res, 400, { error: 'invalid pairing code' });
      const child = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId,
        name: name ? String(name) : (model ? String(model) : 'Child'),
        model: model ? String(model) : '',
        deviceToken: newToken(),
        fcmToken: fcmToken ? String(fcmToken) : null,
        createdAt: new Date().toISOString(),
        lastSeen: null, battery: null, permissions: null, lastLocation: null, appVersion: null,
        events: [],
      };
      data.children.push(child);
      save();
      return json(res, 201, { childId: child.id, deviceToken: child.deviceToken });
    }

    // ---- number accounts (number system): a child registers with its
    //      phone number + a self-set password. The number is claimed by
    //      ONE account; the password (scrypt hash only) is what opens
    //      the account on a new device / reinstall. Registering an
    //      already-claimed number is refused — the login route is the
    //      only way in, and it demands the password.
    if (p === '/api/numbers/register' && req.method === 'POST') {
      const { number, password, name, model, fcmToken } = await readBody(req).catch(() => null) || {};
      const num = normalizeNumber(number);
      if (!num) return json(res, 400, { error: 'invalid phone number' });
      if (!password || String(password).length < 6) return json(res, 400, { error: 'password must be at least 6 characters' });
      if (data.numbers[num]) return json(res, 409, { error: 'number already registered' });
      const child = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId: null, // unbound until a parent adds this number
        number: num,
        name: name ? String(name) : (model ? String(model) : 'Family'),
        model: model ? String(model) : '',
        deviceToken: newToken(),
        fcmToken: fcmToken ? String(fcmToken) : null,
        contacts: [],
        createdAt: new Date().toISOString(),
        lastSeen: null, battery: null, permissions: null, lastLocation: null, appVersion: null,
        events: [],
      };
      const salt = crypto.randomBytes(16).toString('hex');
      data.numbers[num] = {
        childId: child.id,
        salt, passwordHash: hashPassword(password, salt),
        deviceName: child.name,
        createdAt: child.createdAt,
      };
      data.children.push(child);
      save();
      return json(res, 201, { childId: child.id, deviceToken: child.deviceToken, number: num });
    }
    if (p === '/api/numbers/login' && req.method === 'POST') {
      const { number, password, model } = await readBody(req).catch(() => null) || {};
      const num = normalizeNumber(number);
      if (!num) return json(res, 400, { error: 'invalid phone number' });
      const entry = data.numbers[num];
      const child = entry ? data.children.find(c => c.id === entry.childId) : null;
      if (!entry || !child) return json(res, 404, { error: 'number not registered' });
      if (!checkPassword(password || '', entry)) return json(res, 401, { error: 'wrong password' });
      // Password proven: this device becomes the account's device. The
      // deviceToken ROTATES — the previous device's credential dies
      // here (its live socket is closed; its next reconnect is refused
      // as unauthorized). The childId (the account identity a parent
      // binds to) is stable across the rotation.
      child.deviceToken = newToken();
      if (model) child.model = String(model);
      const live = liveChildren.get(child.id);
      if (live) { try { live.close(); } catch {} liveChildren.delete(child.id); }
      save();
      return json(res, 200, { childId: child.id, deviceToken: child.deviceToken, number: num });
    }

    // ---- parent adds a family device by its registered number
    //      (number system): instant bind with FULL parent control —
    //      the same binding invite/code pairing creates. One child
    //      account binds to ONE parent at a time.
    if (p === '/api/children/add-by-number' && req.method === 'POST') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const { number } = await readBody(req).catch(() => null) || {};
      const num = normalizeNumber(number);
      if (!num) return json(res, 400, { error: 'invalid phone number' });
      const entry = data.numbers[num];
      const child = entry ? data.children.find(c => c.id === entry.childId) : null;
      if (!entry || !child) return json(res, 404, { error: 'no device registered with this number' });
      if (child.parentId && child.parentId !== parent.id) {
        return json(res, 409, { error: 'this device already belongs to another account' });
      }
      if (child.parentId === parent.id) return json(res, 200, childView(child));
      child.parentId = parent.id;
      save();
      // A live child socket authenticated while unbound: retarget it
      // at the new parent so its calls/chat route correctly at once.
      const cws = liveChildren.get(child.id);
      if (cws) {
        cws.parentId = parent.id;
        sendWs(cws, { type: 'parent_bound', parentId: parent.id });
      }
      return json(res, 201, childView(child));
    }

    // ---- contacts between number-registered children (child auth):
    //      call/chat only. Control kinds are never reachable from a
    //      contact relation — the listen/camera handlers refuse any
    //      non-parent socket, and location flows only to the bound
    //      parent.
    if (p === '/api/contacts' && req.method === 'POST') {
      const me = authChild(req);
      if (!me) return json(res, 401, { error: 'unauthorized' });
      if (!me.number) return json(res, 400, { error: 'this device has no number account' });
      const { number } = await readBody(req).catch(() => null) || {};
      const num = normalizeNumber(number);
      if (!num) return json(res, 400, { error: 'invalid phone number' });
      const entry = data.numbers[num];
      const target = entry ? data.children.find(c => c.id === entry.childId) : null;
      if (!entry || !target) return json(res, 404, { error: 'number not registered' });
      if (target.id === me.id) return json(res, 400, { error: 'cannot add your own number' });
      if (!contactsOf(me).includes(target.id)) contactsOf(me).push(target.id);
      if (!contactsOf(target).includes(me.id)) contactsOf(target).push(me.id);
      save();
      // Tell the other side live, if it is connected: it gained a contact.
      sendWs(liveChildren.get(target.id), { type: 'contact_added', contact: contactView(me) });
      return json(res, 200, { contact: contactView(target) });
    }
    if (p === '/api/contacts' && req.method === 'GET') {
      const me = authChild(req);
      if (!me) return json(res, 401, { error: 'unauthorized' });
      const out = [];
      for (const id of contactsOf(me)) {
        const c = data.children.find(x => x.id === id);
        if (c) out.push(contactView(c));
      }
      return json(res, 200, out);
    }
    const contactMatch = p.match(/^\/api\/contacts\/([^/]+)$/);
    if (contactMatch && req.method === 'DELETE') {
      const me = authChild(req);
      if (!me) return json(res, 401, { error: 'unauthorized' });
      const otherId = decodeURIComponent(contactMatch[1]);
      me.contacts = contactsOf(me).filter(id => id !== otherId);
      const other = data.children.find(c => c.id === otherId);
      if (other) other.contacts = contactsOf(other).filter(id => id !== me.id);
      save();
      return json(res, 200, { ok: true });
    }

    // ---- child heartbeat + events (deviceToken auth)
    if (p === '/api/children/heartbeat' && req.method === 'POST') {
      const child = authChild(req);
      if (!child) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req).catch(() => null);
      if (!body) return json(res, 400, { error: 'bad json' });
      const prevPerms = child.permissions || null;
      if (typeof body.battery === 'number') child.battery = body.battery;
      if (body.permissions && typeof body.permissions === 'object') {
        // Tamper events on negative transitions true -> false (incl. admin).
        if (prevPerms) {
          for (const [key, val] of Object.entries(body.permissions)) {
            if (prevPerms[key] === true && val === false) {
              addEvent(child, 'tamper', `${key} disabled`);
            }
          }
        }
        child.permissions = { ...(prevPerms || {}), ...body.permissions };
      }
      if (body.location && typeof body.location.lat === 'number' && typeof body.location.lng === 'number') {
        child.lastLocation = {
          lat: body.location.lat, lng: body.location.lng,
          accuracy: body.location.accuracy ?? null,
          ts: body.location.ts ?? Date.now(),
        };
      }
      if (body.appVersion) child.appVersion = String(body.appVersion);
      // FCM token registration/rotation: non-empty string replaces,
      // explicit empty string clears. Value is never logged.
      if (typeof body.fcmToken === 'string') child.fcmToken = body.fcmToken || null;
      // Push health self-report (step-3): 'ok' once a token has been
      // obtained on the device, 'fail' when Firebase init failed there.
      // Only these two states are stored; parents see just the derived
      // `push` field in childView, never the token.
      if (body.fcmState === 'ok' || body.fcmState === 'fail') child.fcmState = body.fcmState;
      // Crash self-report (v2.5.1): the child app's last uncaught-
      // exception trace, harvested after the crash and carried once by
      // the next heartbeat. Truncated to 4000 chars; stored on the
      // record and surfaced in /debug as childCrash for diagnosis.
      if (typeof body.lastCrash === 'string' && body.lastCrash) {
        child.lastCrash = body.lastCrash.slice(0, 4000);
      }
      child.lastSeen = new Date().toISOString();
      save();
      return json(res, 200, { ok: true });
    }
    if (p === '/api/children/events' && req.method === 'POST') {
      const child = authChild(req);
      if (!child) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req).catch(() => null);
      if (!body || !body.type) return json(res, 400, { error: 'type required' });
      addEvent(child, body.type, body.detail);
      child.lastSeen = new Date().toISOString();
      save();
      return json(res, 200, { ok: true });
    }

    // ---- chat history (SPEC-V2 §2): parent by childId, child for its own pair.
    //      v2.3: messages deleted-for the requester are excluded.
    if (p === '/api/chat' && req.method === 'GET') {
      const child = authChild(req);
      if (!child) return json(res, 401, { error: 'unauthorized' });
      // Contact conversation (number system): ?with=<childId> names the
      // contact; only an actual contact of the caller may be read.
      const withId = url.searchParams.get('with');
      if (withId) {
        const peer = data.children.find(c => c.id === withId);
        if (!peer) return json(res, 404, { error: 'contact not found' });
        if (!areContacts(child.id, peer.id)) return json(res, 403, { error: 'forbidden' });
        return json(res, 200, chatHistoryByKey(contactKey(child.id, peer.id), child.id));
      }
      // An unbound number child has no parent conversation yet.
      if (!child.parentId) return json(res, 200, []);
      return json(res, 200, chatHistoryFor(child.parentId, child.id, child.id));
    }
    const chatMatch = p.match(/^\/api\/chat\/([^/]+)$/);
    if (chatMatch && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const child = data.children.find(c => c.id === decodeURIComponent(chatMatch[1]));
      if (!child) return json(res, 404, { error: 'child not found' });
      if (child.parentId !== parent.id) return json(res, 403, { error: 'forbidden' });
      return json(res, 200, chatHistoryFor(parent.id, child.id, parent.id));
    }

    // ---- chat read receipts (v2.3): mark all INCOMING messages of the pair
    //      as read by the requester; the other party gets {type:'chat_read'}.
    //      Parent callers name the child in the body ({childId}); a child
    //      caller's pair is implied. Response {ok, marked}.
    if (p === '/api/chat/read' && req.method === 'POST') {
      const parent = authParent(req);
      const child = parent ? null : authChild(req);
      if (!parent && !child) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req).catch(() => ({})) || {};
      // Contact pair (number system): a child caller naming
      // {withChildId} marks the CONTACT conversation read instead.
      if (child && body.withChildId) {
        const peer = data.children.find(x => x.id === String(body.withChildId));
        if (!peer) return json(res, 404, { error: 'contact not found' });
        if (!areContacts(child.id, peer.id)) return json(res, 403, { error: 'forbidden' });
        let markedC = 0;
        const arrC = data.chats[contactKey(child.id, peer.id)] || [];
        for (const msg of arrC) {
          if (msg.fromId === child.id) continue; // only incoming
          if (!Array.isArray(msg.readBy)) msg.readBy = [];
          if (!msg.readBy.includes(child.id)) { msg.readBy.push(child.id); markedC++; }
        }
        if (markedC) save();
        sendWs(liveChildren.get(peer.id),
          { type: 'chat_read', contact: true, fromId: child.id, toId: peer.id });
        return json(res, 200, { ok: true, marked: markedC });
      }
      let parentId, childId, role, myKey;
      if (parent) {
        const c = data.children.find(x => x.id === String(body.childId || ''));
        if (!c) return json(res, 404, { error: 'child not found' });
        if (c.parentId !== parent.id) return json(res, 403, { error: 'forbidden' });
        parentId = parent.id; childId = c.id; role = 'parent'; myKey = parent.id;
      } else {
        parentId = child.parentId; childId = child.id; role = 'child'; myKey = child.id;
      }
      let marked = 0;
      const arr = data.chats[chatKey(parentId, childId)] || [];
      for (const msg of arr) {
        if (msg.fromRole === role) continue; // only incoming messages
        if (!Array.isArray(msg.readBy)) msg.readBy = [];
        if (!msg.readBy.includes(myKey)) { msg.readBy.push(myKey); marked++; }
      }
      if (marked) save();
      pushChatEventToOther(parentId, childId, role,
        { type: 'chat_read', parentId, childId, byRole: role });
      return json(res, 200, { ok: true, marked });
    }

    // ---- chat message delete (v2.3): DELETE /api/chat/messages/:id,
    //      scope from JSON body or ?scope= ('me' default, or 'everyone').
    //      'me'       -> requester added to the message's deletedFor; the
    //                      message vanishes from the requester's history only.
    //      'everyone' -> the message is hard-removed for both parties; a
    //                      media message's stored media is deleted too when
    //                      no other message references it (GET -> 404).
    //      Either way {type:'chat_delete', msgId, scope} is pushed to every
    //      live socket of both parties. A message outside the requester's
    //      pair(s) is indistinguishable from a missing one: 404.
    const chatMsgMatch = p.match(/^\/api\/chat\/messages\/([^/]+)$/);
    if (chatMsgMatch && req.method === 'DELETE') {
      const parent = authParent(req);
      const child = parent ? null : authChild(req);
      if (!parent && !child) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req).catch(() => ({})) || {};
      const scope = String(body.scope || url.searchParams.get('scope') || 'me');
      if (scope !== 'me' && scope !== 'everyone') return json(res, 400, { error: 'bad scope' });
      const msgId = decodeURIComponent(chatMsgMatch[1]);
      const myKey = parent ? parent.id : child.id;
      // Search ONLY the requester's own pair(s) (isolation).
      let hit = null;
      // A child caller's scope: its parent pair (when bound) PLUS every
      // contact pair it parties (number system).
      const childKeys = new Set();
      if (child) {
        if (child.parentId) childKeys.add(chatKey(child.parentId, child.id));
        for (const cid of contactsOf(child)) childKeys.add(contactKey(child.id, cid));
      }
      for (const [key, arr] of Object.entries(data.chats)) {
        const inScope = parent ? key.startsWith(parent.id + ':') : childKeys.has(key);
        if (!inScope || !Array.isArray(arr)) continue;
        const idx = arr.findIndex(m => m.id === msgId);
        if (idx >= 0) { hit = { key, arr, idx, msg: arr[idx] }; break; }
      }
      if (!hit) return json(res, 404, { error: 'message not found' });
      const { parentId, childId } = hit.msg;
      if (scope === 'me') {
        if (!Array.isArray(hit.msg.deletedFor)) hit.msg.deletedFor = [];
        if (!hit.msg.deletedFor.includes(myKey)) hit.msg.deletedFor.push(myKey);
        save();
      } else {
        const mediaId = hit.msg.mediaId;
        hit.arr.splice(hit.idx, 1);
        if (mediaId && data.media[mediaId]) {
          const stillReferenced = Object.values(data.chats)
            .some(a => Array.isArray(a) && a.some(m => m.mediaId === mediaId));
          if (!stillReferenced) {
            // Last reference gone: the bytes go too (whichever
            // backend holds them — local file or Firestore chunks).
            await mediaStore.del(mediaId).catch(() => {});
            delete data.media[mediaId];
          }
        }
        save();
      }
      if (hit.msg.contact) {
        pushContactChatEvent(hit.msg.fromId, hit.msg.toId,
          { type: 'chat_delete', msgId, scope, contact: true, fromId: hit.msg.fromId, toId: hit.msg.toId });
      } else {
        pushChatEvent(parentId, childId,
          { type: 'chat_delete', msgId, scope, parentId, childId });
      }
      return json(res, 200, { ok: true, msgId, scope });
    }

    // ---- media files (SPEC-V2 §3): upload raw bytes, owner-only download
    if (p === '/api/media' && req.method === 'POST') {
      const parent = authParent(req);
      const child = parent ? null : authChild(req);
      if (!parent && !child) return json(res, 401, { error: 'unauthorized' });
      const { buf, size, tooLarge } = await readRawBody(req, MEDIA_MAX_BYTES);
      if (tooLarge) return json(res, 413, { error: 'file too large (max 10 MB)' });
      const mediaId = crypto.randomBytes(16).toString('hex');
      try {
        await mediaStore.put(mediaId, buf,
          String(req.headers['content-type'] || 'application/octet-stream'));
      } catch { return json(res, 500, { error: 'media store failed' }); }
      data.media[mediaId] = {
        id: mediaId,
        ownerParentId: parent ? parent.id : child.parentId,
        uploaderChildId: child ? child.id : null,
        fileName: String(req.headers['x-file-name'] || 'file').slice(0, 200),
        contentType: String(req.headers['content-type'] || 'application/octet-stream'),
        size,
        ts: Date.now(),
      };
      // Prune oldest files beyond the cap.
      const idsByAge = Object.keys(data.media).sort((a, b) => data.media[a].ts - data.media[b].ts);
      while (idsByAge.length > MEDIA_MAX_FILES) {
        const old = idsByAge.shift();
        mediaStore.del(old).catch(() => {});
        delete data.media[old];
      }
      save();
      return json(res, 201, { mediaId, size });
    }
    const mediaMatch = p.match(/^\/api\/media\/([^/]+)$/);
    if (mediaMatch && req.method === 'GET') {
      const parent = authParent(req);
      const child = parent ? null : authChild(req);
      if (!parent && !child) return json(res, 401, { error: 'unauthorized' });
      const rec = data.media[decodeURIComponent(mediaMatch[1])];
      if (!rec) return json(res, 404, { error: 'media not found' });
      // Owner-only: the owning parent, or that parent's child (for child
      // uploads, only the very child that uploaded it).
      let allowed = false;
      if (parent) allowed = parent.id === rec.ownerParentId;
      else if (child) allowed = child.parentId === rec.ownerParentId &&
        (rec.uploaderChildId === null || rec.uploaderChildId === child.id);
      // Step 3.5: a party of any chat that REFERENCES this media may
      // also fetch it — contact-chat receivers and forward recipients
      // are not the uploader's family, so the owner rule alone 403'd
      // media they legitimately hold in their own history.
      if (!allowed) allowed = mediaPartyAllowed(rec, parent, child);
      if (!allowed) return json(res, 403, { error: 'forbidden' });
      const got = await mediaStore.get(rec.id).catch(() => null);
      if (!got) return json(res, 404, { error: 'media file missing' });
      const bytes = got.buf;
      res.writeHead(200, { 'Content-Type': rec.contentType, 'Content-Length': bytes.length });
      return res.end(bytes);
    }

    // ---- children (parent, strictly owner-filtered)
    if (p === '/api/children' && req.method === 'GET') {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, data.children.filter(c => c.parentId === parent.id).map(childView));
    }
    const childMatch = p.match(/^\/api\/children\/([^/]+)(\/events)?$/);
    if (childMatch && (req.method === 'PATCH' || req.method === 'DELETE' || req.method === 'GET')) {
      const parent = authParent(req);
      if (!parent) return json(res, 401, { error: 'unauthorized' });
      const id = decodeURIComponent(childMatch[1]);
      const child = findOwnChild(parent, id);
      if (!child) return json(res, 404, { error: 'child not found' });
      if (childMatch[2] === '/events') {
        if (req.method !== 'GET') return json(res, 404, { error: 'not found' });
        return json(res, 200, (child.events || []).slice(-EVENTS_RETURN));
      }
      if (req.method === 'PATCH') {
        const body = await readBody(req).catch(() => null);
        if (!body || typeof body.name !== 'string' || !body.name.trim()) return json(res, 400, { error: 'name required' });
        child.name = body.name.trim();
        save();
        return json(res, 200, childView(child));
      }
      if (req.method === 'DELETE') {
        // Fail any held wake-and-wait requests for this child fast —
        // it can never appear now — with the standard offline shape.
        for (const [key, p] of [...wakePendings.entries()]) {
          if (p.childId === child.id) {
            clearTimeout(p.timer); clearRepushes(p); wakePendings.delete(key);
            if (p.logEntry) p.logEntry.wait = 'cancelled';
            sendStartFailure(p.parentWs, p.kind, p.childId, 'offline');
          }
        }
        dropParentWakePending(child.id);
        // Close any live session + socket for this child first.
        for (const s of [...sessions.values()]) {
          if (s.childId === child.id || s.aChildId === child.id || s.bChildId === child.id) {
            closeSession(s, peerSockets(s), 'child_removed');
          }
        }
        const cws = liveChildren.get(child.id);
        if (cws) { try { cws.close(); } catch {} liveChildren.delete(child.id); }
        if (child.number) {
          // Number account (number system): "Remove" UNBINDS only —
          // the child's own account (number, password, contacts) is
          // the child's, not the parent's, and survives; the parent
          // can add the same number again later. The socket close
          // above is enough: on reconnect the child authenticates as
          // an unbound device.
          child.parentId = null;
          save();
          return json(res, 200, { ok: true, unbound: true });
        }
        data.children = data.children.filter(c => c.id !== child.id);
        save();
        return json(res, 200, { ok: true });
      }
      // GET /api/children/:id is not part of the API.
      return json(res, 404, { error: 'not found' });
    }

    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 500, { error: 'server error' });
  }
});

// ---------------------------------------------------------------- WebSocket
const wss = new WebSocketServer({ server });
// Heartbeat/reaper for half-open sockets (see WS_PING_MS).
const wsPingTimer = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { try { ws.terminate(); } catch {} continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, WS_PING_MS);
if (wsPingTimer.unref) wsPingTimer.unref();
// Stale-session sweep (2026-11-07): a listen/camera session whose offer
// was never answered (the requesting screen was abandoned — the
// 2026-11-06 "Busy forever" zombie) must not hold the pair busy
// indefinitely. Answered sessions are never touched, however long they
// run; ringing calls already expire via RING_TIMEOUT_MS.
// TTL shortened 600000 -> 90000 the same day (owner hit "Busy — another
// session is already active" at 12:48 +06 from a session whose child
// never sent an offer at all): in every healthy trail the child's offer
// arrives within seconds of the start, so 90 s is generous, and a
// 10-minute ghost is indistinguishable from a permanent block to the
// parent. The sweep tick derives from the TTL (tests run it fast);
// production keeps the 30 s tick.
const SESSION_UNANSWERED_TTL_MS = parseInt(process.env.SESSION_UNANSWERED_TTL_MS || '90000', 10);
const SESSION_SWEEP_MS = Math.min(30000, Math.max(1000, Math.floor(SESSION_UNANSWERED_TTL_MS / 3)));
const sessionSweepTimer = setInterval(() => {
  const now = Date.now();
  for (const s of [...sessions.values()]) {
    if (s.kind === 'call') continue;
    if (s.sig && s.sig.answer > 0) continue;
    if (now - (s.createdAt || 0) > SESSION_UNANSWERED_TTL_MS) {
      closeSession(s, peerSockets(s), 'timeout');
    }
  }
}, SESSION_SWEEP_MS);
if (sessionSweepTimer.unref) sessionSweepTimer.unref();
wss.on('connection', (ws, req) => {
  // Liveness tracking for the reaper above. The ws library (and OkHttp
  // on Android) answer protocol pings with pongs automatically; a
  // client that stops ponging is a dead connection.
  ws.isAlive = true;
  ws.lastPongAt = Date.now();
  ws.on('pong', () => { ws.isAlive = true; ws.lastPongAt = Date.now(); });
  const url = new URL(req.url, 'http://x');
  const role = url.searchParams.get('role');

  if (role === 'parent') {
    const token = url.searchParams.get('token') || '';
    const parentId = data.tokens[token];
    const parent = parentId && data.parents.find(p => p.id === parentId);
    if (!parent) { sendWs(ws, { type: 'error', error: 'unauthorized' }); try { ws.close(4401); } catch {} return; }
    ws.role = 'parent'; ws.parentId = parent.id;
    if (!liveParents.has(parent.id)) liveParents.set(parent.id, new Set());
    liveParents.get(parent.id).add(ws);
    // Parent FCM token may also ride the connect URL (step-3).
    const wsFcmToken = url.searchParams.get('fcmToken');
    if (typeof wsFcmToken === 'string' && wsFcmToken) { parent.fcmToken = wsFcmToken; save(); }
    sendWs(ws, { type: 'connected', role: 'parent', parentId: parent.id });
    // Wake-and-wait: execute any child->parent calls held for this parent.
    flushParentWakePendings(parent);
  } else if (role === 'child') {
    const deviceToken = url.searchParams.get('deviceToken') || '';
    const child = data.children.find(c => c.deviceToken === deviceToken);
    if (!child) { sendWs(ws, { type: 'error', error: 'unauthorized' }); try { ws.close(4401); } catch {} return; }
    ws.role = 'child'; ws.childId = child.id; ws.parentId = child.parentId;
    const old = liveChildren.get(child.id);
    if (old && old !== ws) { try { old.close(); } catch {} }
    liveChildren.set(child.id, ws);
    childWentOfflineAt.delete(child.id); // back inside the grace model
    child.lastSeen = new Date().toISOString();
    save();
    sendWs(ws, { type: 'connected', role: 'child', childId: child.id, parentId: child.parentId });
    // Wake-and-wait: execute any parent requests held for this child.
    flushWakePendings(child);
    flushDataPendings(child);
  } else {
    sendWs(ws, { type: 'error', error: 'bad role' });
    try { ws.close(4400); } catch {}
    return;
  }

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!m || typeof m.type !== 'string') return;

    // ---- parent registers/rotates its FCM token over the socket
    //      (step-3): non-empty string replaces, explicit empty clears.
    if (m.type === 'fcm_token' && ws.role === 'parent') {
      const parent = data.parents.find(p => p.id === ws.parentId);
      if (parent && typeof m.fcmToken === 'string') {
        parent.fcmToken = m.fcmToken || null;
        save();
      }
      return;
    }

    // ---- parent gives up on a held wake-and-wait request (silent)
    if (m.type === 'wake_cancel' && ws.role === 'parent') {
      if (m.kind === 'listen' || m.kind === 'camera' || m.kind === 'call') {
        dropWakePending(pendingKey(ws.parentId, String(m.childId || ''), m.kind));
      }
      return;
    }

    // ---- parent starts listening. CONTROL GATE (number system):
    //      listen is a parent-binding-only kind — any non-parent
    //      socket (e.g. a contact child) asking for it is refused
    //      outright, here and for camera_start below.
    if (m.type === 'listen_start') {
      if (ws.role !== 'parent') {
        return sendWs(ws, { type: 'listen_error', childId: String(m.childId || ''), reason: 'forbidden' });
      }
      const childId = String(m.childId || '');
      const child = data.children.find(c => c.id === childId);
      if (!child) return sendWs(ws, { type: 'listen_error', childId, reason: 'not_found' });
      if (child.parentId !== ws.parentId) return sendWs(ws, { type: 'listen_error', childId, reason: 'forbidden' });
      replaceOwnMonitoringSessions(ws.parentId, childId);
      const cws = liveChildren.get(childId);
      if (!cws || cws.readyState !== 1 || reapStaleChildSocket(childId)) {
        // Wake-and-wait: hold the request while a wake push tries to
        // bring the child back — unless the pair is busy anyway.
        if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'listen_error', childId, reason: 'busy' });
        const entry = attemptWake('child', child, 'listen');
        pendWakeRequest(ws, child, 'listen', { logEntry: entry });
        return;
      }
      if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'listen_error', childId, reason: 'busy' });
      startListenSession(ws, child, cws);
      return;
    }

    // ---- parent (or child) stops listening
    if (m.type === 'listen_stop') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'listen') return;
      if (ws !== s.parentWs && ws !== s.childWs) return;
      sessions.delete(s.id);
      archiveSession(s);
      const other = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(other, { type: 'listen_stop', sessionId: s.id });
      return;
    }

    // ---- camera session (SPEC-V2 §1a): parent opens front/back camera on the
    //      child; child streams sendonly audio+video, no preview on the child.
    if (m.type === 'camera_start') {
      if (ws.role !== 'parent') {
        return sendWs(ws, { type: 'camera_error', childId: String(m.childId || ''), reason: 'forbidden' });
      }
      const childId = String(m.childId || '');
      const facing = m.facing === 'front' ? 'front' : 'back';
      const child = data.children.find(c => c.id === childId);
      if (!child) return sendWs(ws, { type: 'camera_error', childId, reason: 'not_found' });
      if (child.parentId !== ws.parentId) return sendWs(ws, { type: 'camera_error', childId, reason: 'forbidden' });
      replaceOwnMonitoringSessions(ws.parentId, childId);
      const cws = liveChildren.get(childId);
      if (!cws || cws.readyState !== 1 || reapStaleChildSocket(childId)) {
        if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'camera_error', childId, reason: 'busy' });
        const entry = attemptWake('child', child, 'camera');
        pendWakeRequest(ws, child, 'camera', { facing, logEntry: entry });
        return;
      }
      if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'camera_error', childId, reason: 'busy' });
      startCameraSession(ws, child, cws, facing);
      return;
    }
    if (m.type === 'camera_ready' && ws.role === 'child') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'camera' || ws !== s.childWs) return;
      sendWs(s.parentWs, { type: 'camera_ready', sessionId: s.id });
      return;
    }
    if (m.type === 'camera_switch' && ws.role === 'parent') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'camera' || ws !== s.parentWs) return;
      sendWs(s.childWs, { type: 'camera_switch', sessionId: s.id });
      return;
    }
    if (m.type === 'camera_stop') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'camera') return;
      if (ws !== s.parentWs && ws !== s.childWs) return;
      sessions.delete(s.id);
      archiveSession(s);
      const other = ws === s.parentWs ? s.childWs : s.parentWs;
      sendWs(other, { type: 'camera_stop', sessionId: s.id });
      return;
    }

    // ---- contact call (number system): a number-registered child
    //      calls one of its CONTACTS (another child). Call/chat are the
    //      ONLY session kinds a contact relation can produce — control
    //      kinds are refused in their own handlers above. The session
    //      parties on the two child sockets (aWs caller, bWs callee)
    //      and reuses the normal ring/accept/signal machinery.
    if (m.type === 'contact_call_start' && ws.role === 'child') {
      const media = m.media === 'video' ? 'video' : 'audio';
      const toId = String(m.toChildId || '');
      const peer = data.children.find(c => c.id === toId);
      if (!peer) return sendWs(ws, { type: 'call_error', childId: toId, reason: 'not_found' });
      if (!areContacts(ws.childId, peer.id)) {
        return sendWs(ws, { type: 'call_error', childId: toId, reason: 'forbidden' });
      }
      if (childBusyAny(ws.childId) || childBusyAny(peer.id)) {
        return sendWs(ws, { type: 'call_busy', childId: toId });
      }
      const pws = liveChildren.get(peer.id);
      if (!pws || pws.readyState !== 1 || reapStaleChildSocket(peer.id)) {
        maybeWakeChild(peer, 'call'); // fire-and-forget nudge; no hold for contacts
        return sendWs(ws, { type: 'call_error', childId: toId, reason: 'offline' });
      }
      const s = createSession({
        kind: 'call', state: 'ringing', media, contact: true,
        parentId: null, childId: peer.id,
        aChildId: ws.childId, bChildId: peer.id, aWs: ws, bWs: pws,
        parentWs: null, childWs: null, initiatorRole: 'contact',
      });
      armRingTimer(s);
      sendWs(pws, { type: 'call_invite', sessionId: s.id, media, fromId: ws.childId, contact: true });
      sendWs(ws, { type: 'call_ringing', sessionId: s.id, childId: peer.id });
      return;
    }

    // ---- two-way call (SPEC-V2 §1b): either side initiates; the invite goes
    //      to the child's socket, or to ALL of the parent's sockets when the
    //      child calls (the accepting parent socket becomes the session party).
    if (m.type === 'call_start') {
      const media = m.media === 'video' ? 'video' : 'audio';
      if (ws.role === 'parent') {
        const childId = String(m.childId || '');
        const child = data.children.find(c => c.id === childId);
        if (!child) return sendWs(ws, { type: 'call_error', childId, reason: 'not_found' });
        if (child.parentId !== ws.parentId) return sendWs(ws, { type: 'call_error', childId, reason: 'forbidden' });
        const cws = liveChildren.get(childId);
        if (!cws || cws.readyState !== 1 || reapStaleChildSocket(childId)) {
          if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'call_busy', childId });
          const entry = attemptWake('child', child, 'call');
          pendWakeRequest(ws, child, 'call', { media, logEntry: entry });
          return;
        }
        if (partyBusy(ws.parentId, childId)) return sendWs(ws, { type: 'call_busy', childId });
        startCallSession(ws, child, cws, media);
        return;
      }
      if (ws.role === 'child') {
        // An unbound number child has no parent to call; its calls go
        // to contacts via contact_call_start instead.
        if (!ws.parentId) return sendWs(ws, { type: 'call_error', reason: 'no_parent' });
        const pset = liveParents.get(ws.parentId);
        const parentOnline = !!pset && [...pset].some(x => x.readyState === 1);
        if (!parentOnline) {
          // Wake-and-wait, mirrored: hold the child's call while a
          // wake push tries to bring the parent back; the child gets
          // the classic offline error only after WAKE_WAIT_MS.
          if (partyBusy(ws.parentId, ws.childId)) return sendWs(ws, { type: 'call_busy', childId: ws.childId });
          const child = data.children.find(c => c.id === ws.childId);
          const parent = data.parents.find(p => p.id === ws.parentId);
          const entry = attemptWake('parent', parent, 'call');
          pendParentWake(ws, child, media, entry);
          return;
        }
        if (partyBusy(ws.parentId, ws.childId)) return sendWs(ws, { type: 'call_busy', childId: ws.childId });
        const s = createSession({ kind: 'call', state: 'ringing', media, parentId: ws.parentId, childId: ws.childId, parentWs: null, childWs: ws, initiatorRole: 'child' });
        armRingTimer(s);
        for (const pws of pset) sendWs(pws, { type: 'call_invite', sessionId: s.id, media, fromId: ws.childId });
        return;
      }
      return;
    }
    if (m.type === 'call_ringing') {
      // Ringing ACK (2026-11-07): the invited device's app confirms the
      // invite is ON ITS SCREEN and ringing. Until this arrives the
      // caller only knows the invite was sent — the parent app shows
      // "Calling…" and stays silent; on this ack it shows "Ringing…"
      // and plays ringback. Relayed once per session.
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'call' || s.state !== 'ringing' || s.ringingAcked) return;
      if (s.contact) {
        if (ws !== s.bWs) return;
        s.ringingAcked = true;
        sendWs(s.aWs, { type: 'call_ringing', sessionId: s.id, childId: s.childId });
        return;
      }
      if (ws !== s.childWs) return; // only the invited child can ack
      s.ringingAcked = true;
      if (s.parentWs) {
        sendWs(s.parentWs, { type: 'call_ringing', sessionId: s.id, childId: s.childId });
      } else {
        const set = liveParents.get(s.parentId);
        if (set) for (const pws of set) sendWs(pws, { type: 'call_ringing', sessionId: s.id, childId: s.childId });
      }
      return;
    }
    if (m.type === 'call_accept') {
      const s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'call' || s.state !== 'ringing') return;
      if (s.contact) {
        // Contact call (number system): only the invited contact
        // (bWs) can accept; the caller (aWs) is told, as usual.
        if (ws !== s.bWs) return;
        if (s.ringTimer) { clearTimeout(s.ringTimer); s.ringTimer = null; }
        s.state = 'active';
        sendWs(s.aWs, { type: 'call_accepted', sessionId: s.id });
        return;
      }
      if (s.initiatorRole === 'parent') {
        if (ws !== s.childWs) return; // only the invited child can accept
      } else {
        if (ws.role !== 'parent' || ws.parentId !== s.parentId) return;
        s.parentWs = ws; // the accepting socket becomes the parent-side party
      }
      if (s.ringTimer) { clearTimeout(s.ringTimer); s.ringTimer = null; }
      s.state = 'active';
      const initiator = s.initiatorRole === 'parent' ? s.parentWs : s.childWs;
      sendWs(initiator, { type: 'call_accepted', sessionId: s.id });
      return;
    }
    if (m.type === 'call_reject' || m.type === 'call_end' || m.type === 'call_cancel') {
      // A child hanging up a call that is still HELD in parent
      // wake-and-wait (no session exists yet) cancels the hold silently.
      if (ws.role === 'child') dropParentWakePending(ws.childId);
      let s = sessions.get(m.sessionId);
      if (!s || s.kind !== 'call') {
        // v2.3.3: the INITIATOR never learns the sessionId while the call
        // is still ringing (it is only revealed in call_accepted), so a
        // ringing-phase call_cancel / call_end from the caller arrives
        // with no usable id and used to be dropped here — the callee kept
        // ringing until the 45 s timeout. Resolve the pair's current call
        // session from the AUTHENTICATED sender instead: a parent sender
        // is matched by parentId (and by m.childId when it names one), a
        // child sender by its own childId. partyBusy() guarantees at most
        // one live session per pair, so this cannot cross pairs; the
        // isParty check below still applies to the resolved session.
        s = undefined;
        for (const cand of sessions.values()) {
          if (cand.kind !== 'call') continue;
          if (ws.role === 'parent') {
            if (cand.parentId !== ws.parentId) continue;
            if (m.childId && cand.childId !== String(m.childId)) continue;
          } else if (ws.role === 'child') {
            if (cand.childId !== ws.childId && cand.aChildId !== ws.childId && cand.bChildId !== ws.childId) continue;
          } else continue;
          if (cand.state === 'ringing') { s = cand; break; }
          if (!s) s = cand;
        }
        if (!s) return;
      }
      const isParty = sessionParty(s, ws) ||
        (s.initiatorRole === 'child' && ws.role === 'parent' && ws.parentId === s.parentId);
      if (!isParty) return;
      const reason = m.type === 'call_reject' ? 'rejected' : (m.type === 'call_cancel' ? 'cancelled' : 'ended');
      closeSession(s, peerSockets(s, ws), reason);
      return;
    }

    // ---- chat (SPEC-V2 §2): persist per pair, relay to the other party
    if (m.type === 'chat_send') {
      // Contact chat (number system): a child sender naming toChildId
      // writes to the CONTACT pair store, never the parent pair. Only
      // an actual contact may be written to; media must be one of the
      // two parties' own uploads.
      if (ws.role === 'child' && m.toChildId) {
        const peer = data.children.find(c => c.id === String(m.toChildId));
        if (!peer || !areContacts(ws.childId, peer.id)) {
          return sendWs(ws, { type: 'chat_error', reason: 'forbidden' });
        }
        const kind = (m.kind === 'photo' || m.kind === 'file') ? m.kind : 'text';
        const mediaId = m.mediaId ? String(m.mediaId) : null;
        if (kind !== 'text') {
          const rec = mediaId ? data.media[mediaId] : null;
          if (!rec || (rec.uploaderChildId !== ws.childId && rec.uploaderChildId !== peer.id)) {
            return sendWs(ws, { type: 'chat_error', reason: 'bad_media' });
          }
        }
        const key = contactKey(ws.childId, peer.id);
        const arr = data.chats[key] || (data.chats[key] = []);
        let replyTo = null, replySnippet = null;
        if (m.replyTo) {
          const target = arr.find(x => x.id === String(m.replyTo));
          if (target) {
            replyTo = target.id;
            replySnippet = target.kind === 'text'
              ? String(target.body || '').slice(0, 80)
              : (target.kind === 'photo' ? 'Photo' : 'File');
          }
        }
        const msg = {
          id: crypto.randomBytes(8).toString('hex'),
          contact: true, fromId: ws.childId, toId: peer.id,
          parentId: null, childId: peer.id, fromRole: 'child', kind,
          body: m.body == null ? '' : String(m.body).slice(0, 4000),
          mediaId, ts: new Date().toISOString(),
          clientId: m.clientId ? String(m.clientId).slice(0, 64) : null,
          replyTo, replySnippet,
          deletedFor: [], readBy: [],
        };
        arr.push(msg);
        if (arr.length > CHAT_CAP) data.chats[key] = arr.slice(-CHAT_CAP);
        save();
        const out = Object.assign({ type: 'chat_msg' }, chatViewC(msg));
        sendWs(liveChildren.get(peer.id), out);
        maybeWakeChild(peer, 'chat');
        return;
      }
      let parentId, childId;
      if (ws.role === 'parent') {
        childId = String(m.childId || '');
        const child = data.children.find(c => c.id === childId);
        if (!child || child.parentId !== ws.parentId) return sendWs(ws, { type: 'chat_error', reason: 'forbidden' });
        parentId = ws.parentId;
      } else if (ws.role === 'child') {
        parentId = ws.parentId; childId = ws.childId;
      } else return;
      const kind = (m.kind === 'photo' || m.kind === 'file') ? m.kind : 'text';
      const mediaId = m.mediaId ? String(m.mediaId) : null;
      if (kind !== 'text') {
        const rec = mediaId ? data.media[mediaId] : null;
        if (!rec || rec.ownerParentId !== parentId) return sendWs(ws, { type: 'chat_error', reason: 'bad_media' });
      }
      const key = chatKey(parentId, childId);
      const arr = data.chats[key] || (data.chats[key] = []);
      // Reply/quote (v2.3): replyTo must name a message of THIS pair; an
      // unknown or foreign id is ignored (stored null), never an error.
      // The snippet is a send-time snapshot (first 80 chars of text, or
      // 'Photo'/'File' for media), so it survives the target being deleted.
      let replyTo = null, replySnippet = null;
      if (m.replyTo) {
        const target = arr.find(x => x.id === String(m.replyTo));
        if (target) {
          replyTo = target.id;
          replySnippet = target.kind === 'text'
            ? String(target.body || '').slice(0, 80)
            : (target.kind === 'photo' ? 'Photo' : 'File');
        }
      }
      const msg = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId, childId, fromRole: ws.role, kind,
        body: m.body == null ? '' : String(m.body).slice(0, 4000),
        mediaId, ts: new Date().toISOString(),
        clientId: m.clientId ? String(m.clientId).slice(0, 64) : null,
        replyTo, replySnippet,
        deletedFor: [], readBy: [],
      };
      arr.push(msg);
      if (arr.length > CHAT_CAP) data.chats[key] = arr.slice(-CHAT_CAP);
      save();
      const out = Object.assign({ type: 'chat_msg' }, chatView(msg));
      if (ws.role === 'parent') {
        sendWs(liveChildren.get(childId), out);
        // Message is stored regardless; if the child is not connected,
        // nudge its app awake so it can fetch/react (fire-and-forget).
        // (The validated `child` const above is block-scoped to the
        // role check, so re-resolve the record here.)
        maybeWakeChild(data.children.find(c => c.id === childId), 'chat');
      } else {
        const set = liveParents.get(parentId);
        if (set) for (const pws of set) sendWs(pws, out);
        // Mirror nudge: a child messaging an offline parent wakes the
        // parent's app (fire-and-forget; the message is stored).
        maybeWakeParent(data.parents.find(p => p.id === parentId), 'chat');
      }
      return;
    }

    // ---- chat forward (step 3.5): copy one of MY OWN chats' media
    //      messages into another chat I party, reusing the same
    //      mediaId — no byte copy; the stored object simply gains a
    //      referencing message, and delete-for-everyone removes the
    //      bytes only when the LAST reference goes (see the DELETE
    //      handler's refcount). Authorization mirrors chat_send's
    //      addressing: the source message must sit in a chat the
    //      sender parties, and so must the target — a parent names
    //      childId, a child names toChildId for a contact chat or
    //      nothing for its own parent pair. The new message carries
    //      the source's kind/body/mediaId under a fresh id; relay and
    //      wake nudges mirror chat_send exactly.
    if (m.type === 'chat_forward') {
      const srcId = String(m.msgId || '');
      let src = null;
      if (ws.role === 'parent') {
        for (const [key, arr] of Object.entries(data.chats)) {
          if (!key.startsWith(ws.parentId + ':') || !Array.isArray(arr)) continue;
          const hitMsg = arr.find(x => x.id === srcId);
          if (hitMsg) { src = hitMsg; break; }
        }
      } else if (ws.role === 'child') {
        const myKeys = [];
        if (ws.parentId) myKeys.push(chatKey(ws.parentId, ws.childId));
        const me = data.children.find(c => c.id === ws.childId);
        if (me) for (const cid of contactsOf(me)) myKeys.push(contactKey(ws.childId, cid));
        for (const key of myKeys) {
          const arr = data.chats[key];
          if (!Array.isArray(arr)) continue;
          const hitMsg = arr.find(x => x.id === srcId);
          if (hitMsg) { src = hitMsg; break; }
        }
      } else return;
      if (!src) return sendWs(ws, { type: 'chat_error', reason: 'not_found' });
      const kind = src.kind;
      const mediaId = src.mediaId ? String(src.mediaId) : null;
      if ((kind !== 'photo' && kind !== 'file') || !mediaId || !data.media[mediaId]) {
        return sendWs(ws, { type: 'chat_error', reason: 'bad_media' });
      }
      const fwdBody = src.body == null ? '' : String(src.body).slice(0, 4000);
      const fwdTs = new Date().toISOString();
      // Contact target (a child sender naming a contact peer).
      if (ws.role === 'child' && m.toChildId) {
        const peer = data.children.find(c => c.id === String(m.toChildId));
        if (!peer || !areContacts(ws.childId, peer.id)) {
          return sendWs(ws, { type: 'chat_error', reason: 'forbidden' });
        }
        const key = contactKey(ws.childId, peer.id);
        const arr = data.chats[key] || (data.chats[key] = []);
        const msg = {
          id: crypto.randomBytes(8).toString('hex'),
          contact: true, fromId: ws.childId, toId: peer.id,
          parentId: null, childId: peer.id, fromRole: 'child', kind,
          body: fwdBody, mediaId, ts: fwdTs,
          replyTo: null, replySnippet: null,
          deletedFor: [], readBy: [],
        };
        arr.push(msg);
        if (arr.length > CHAT_CAP) data.chats[key] = arr.slice(-CHAT_CAP);
        save();
        sendWs(liveChildren.get(peer.id), Object.assign({ type: 'chat_msg' }, chatViewC(msg)));
        maybeWakeChild(peer, 'chat');
        return;
      }
      // Parent-pair target: a parent names the child; a child reaches
      // its own parent pair by naming nothing.
      let parentId, childId;
      if (ws.role === 'parent') {
        childId = String(m.childId || '');
        const child = data.children.find(c => c.id === childId);
        if (!child || child.parentId !== ws.parentId) return sendWs(ws, { type: 'chat_error', reason: 'forbidden' });
        parentId = ws.parentId;
      } else if (ws.role === 'child') {
        if (!ws.parentId) return sendWs(ws, { type: 'chat_error', reason: 'forbidden' });
        parentId = ws.parentId; childId = ws.childId;
      } else return;
      const key = chatKey(parentId, childId);
      const arr = data.chats[key] || (data.chats[key] = []);
      const msg = {
        id: crypto.randomBytes(8).toString('hex'),
        parentId, childId, fromRole: ws.role, kind,
        body: fwdBody, mediaId, ts: fwdTs,
        replyTo: null, replySnippet: null,
        deletedFor: [], readBy: [],
      };
      arr.push(msg);
      if (arr.length > CHAT_CAP) data.chats[key] = arr.slice(-CHAT_CAP);
      save();
      const out = Object.assign({ type: 'chat_msg' }, chatView(msg));
      if (ws.role === 'parent') {
        sendWs(liveChildren.get(childId), out);
        maybeWakeChild(data.children.find(c => c.id === childId), 'chat');
      } else {
        const set = liveParents.get(parentId);
        if (set) for (const pws of set) sendWs(pws, out);
        maybeWakeParent(data.parents.find(p => p.id === parentId), 'chat');
      }
      return;
    }

    // ---- typing indicator (v2.3): ephemeral relay to the other party only.
    //      Never stored, never appears in history.
    if (m.type === 'typing') {
      if (ws.role === 'parent') {
        const childId = String(m.childId || '');
        const child = data.children.find(c => c.id === childId);
        if (!child || child.parentId !== ws.parentId) return; // foreign pair: drop
        sendWs(liveChildren.get(childId),
          { type: 'typing', on: !!m.on, fromRole: 'parent', parentId: ws.parentId, childId });
      } else if (ws.role === 'child') {
        const set = liveParents.get(ws.parentId);
        if (set) for (const pws of set) {
          sendWs(pws, { type: 'typing', on: !!m.on, fromRole: 'child', parentId: ws.parentId, childId: ws.childId });
        }
      }
      return;
    }

    // ---- WebRTC signalling: relay ONLY between the two parties of the session
    if (m.type === 'signal') {
      const s = sessions.get(m.sessionId);
      if (!s) return sendWs(ws, { type: 'error', error: 'no such session' });
      if (!sessionParty(s, ws)) return;
      // Diagnostics tallies: message kinds + ICE candidate TYPES only.
      try {
        const pl = m.payload || {};
        if (pl.kind === 'offer') s.sig.offer++;
        else if (pl.kind === 'answer') s.sig.answer++;
        else if (pl.kind === 'ice') {
          const tmatch = / typ ([a-z]+)/.exec(String(pl.candidate || ''));
          const t = tmatch ? tmatch[1] : 'unknown';
          const bucket = ws.role === 'child' ? s.sig.childIce : s.sig.parentIce;
          bucket[t] = (bucket[t] || 0) + 1;
        }
      } catch {}
      sendWs(sessionPeer(s, ws), { type: 'signal', sessionId: s.id, payload: m.payload });
      return;
    }

    // ---- Bare offer/answer/ice (SPEC-V2 §1): relayed verbatim between the
    //      two session parties, in both directions, for every session kind.
    if (m.type === 'offer' || m.type === 'answer' || m.type === 'ice') {
      const s = sessions.get(m.sessionId);
      if (!s) return sendWs(ws, { type: 'error', error: 'no such session' });
      if (!sessionParty(s, ws)) return;
      try {
        if (m.type === 'offer') s.sig.offer++;
        else if (m.type === 'answer') s.sig.answer++;
        else {
          const tmatch = / typ ([a-z]+)/.exec(String(m.candidate || ''));
          const t = tmatch ? tmatch[1] : 'unknown';
          const bucket = ws.role === 'child' ? s.sig.childIce : s.sig.parentIce;
          bucket[t] = (bucket[t] || 0) + 1;
        }
      } catch {}
      sendWs(sessionPeer(s, ws), m);
      return;
    }

    // ---- RTC diagnostics from either party (short state words only)
    if (m.type === 'rtc_debug') {
      const state = String(m.state || '').slice(0, 80);
      if (!state) return;
      const s = sessions.get(m.sessionId);
      if (s && sessionParty(s, ws)) {
        s.dbg.push(`${ws.role}:${state}`);
        if (s.dbg.length > 40) s.dbg = s.dbg.slice(-40);
      }
      // Mirror into per-party stores too, so the trail survives session close.
      if (ws.role === 'child' && ws.childId) {
        const arr = childDebug.get(ws.childId) || [];
        arr.push(state);
        childDebug.set(ws.childId, arr.slice(-30));
      } else if (ws.role === 'parent' && ws.parentId) {
        const arr = parentDebug.get(ws.parentId) || [];
        arr.push(state);
        parentDebug.set(ws.parentId, arr.slice(-30));
      }
      return;
    }

    // ---- child location: store + relay to owning parent(s)
    if (m.type === 'location' && ws.role === 'child') {
      const child = data.children.find(c => c.id === ws.childId);
      if (!child || typeof m.lat !== 'number' || typeof m.lng !== 'number') return;
      child.lastLocation = { lat: m.lat, lng: m.lng, accuracy: m.accuracy ?? null, ts: m.ts ?? Date.now() };
      child.lastSeen = new Date().toISOString();
      save();
      const msg = { type: 'location', childId: child.id, lat: m.lat, lng: m.lng, accuracy: m.accuracy ?? null, ts: child.lastLocation.ts };
      if (m.sessionId) msg.sessionId = m.sessionId;
      const set = liveParents.get(child.parentId);
      if (set) for (const pws of set) sendWs(pws, msg);
      return;
    }

    // ---- data sections (feature 2026-11-06): bound parent asks the
    // child for Contacts / Call list / SMS / Gallery data. Same binding
    // rule as listen_start; an offline child is woken and the request is
    // held (data_pending), an online child gets it at once.
    if (m.type === 'data_request' && ws.role === 'parent') {
      const reqId = String(m.reqId || '');
      const childId = String(m.childId || '');
      const section = String(m.section || '');
      if (!reqId || !DATA_SECTIONS.has(section)) return sendDataError(ws, reqId, childId, section, 'bad_request');
      const child = data.children.find(c => c.id === childId);
      if (!child) return sendDataError(ws, reqId, childId, section, 'not_found');
      if (child.parentId !== ws.parentId) return sendDataError(ws, reqId, childId, section, 'forbidden');
      const page = Math.max(0, parseInt(m.page || '0', 10) || 0);
      const photoId = section === 'photo' ? String(m.photoId || '') : undefined;
      if (section === 'photo' && !photoId) return sendDataError(ws, reqId, childId, section, 'bad_request');
      const cws = liveChildren.get(childId);
      if (!cws || cws.readyState !== 1 || reapStaleChildSocket(childId)) {
        attemptWake('child', child, 'data');
        pendDataRequest(ws, { reqId, childId, section, page, photoId });
        return;
      }
      forwardDataRequest(cws, { reqId, childId, section, page, photoId, parentWs: ws, parentId: ws.parentId });
      return;
    }

    // ---- data sections: the child's response, routed to the parent who
    // asked (and only that parent). List responses are single-shot;
    // photo responses stream chunks with done:false until the last one.
    if (m.type === 'data_response' && ws.role === 'child') {
      const reqId = String(m.reqId || '');
      const f = dataInflight.get(reqId);
      if (!f || f.childId !== ws.childId) return;
      if (m.done !== false) { clearTimeout(f.timer); dataInflight.delete(reqId); }
      if (f.parentWs && f.parentWs.readyState === 1) {
        const out = { type: 'data_response', reqId, childId: f.childId, section: f.section };
        if (Array.isArray(m.items)) out.items = m.items;
        if (typeof m.hasMore === 'boolean') out.hasMore = m.hasMore;
        if (m.error) out.error = String(m.error);
        if (m.chunk !== undefined) out.chunk = m.chunk;
        if (m.totalChunks !== undefined) out.totalChunks = m.totalChunks;
        if (typeof m.data === 'string') out.data = m.data;
        if (m.name) out.name = String(m.name);
        if (m.mime) out.mime = String(m.mime);
        sendWs(f.parentWs, out);
      }
      return;
    }
  });

  ws.on('close', () => {
    if (ws.role === 'parent') {
      clearWakePendingsForParentWs(ws); // held wake requests die silently
      clearDataForParentWs(ws); // held data requests die silently too
      const set = liveParents.get(ws.parentId);
      if (set) { set.delete(ws); if (!set.size) liveParents.delete(ws.parentId); }
      for (const s of [...sessions.values()]) {
        if (s.parentWs === ws) closeSession(s, peerSockets(s), 'disconnect');
      }
    }
    if (ws.role === 'child') {
      dropParentWakePending(ws.childId); // a held outgoing call dies with its socket
      if (liveChildren.get(ws.childId) === ws) {
        liveChildren.delete(ws.childId);
        // Presence does not flip offline yet — the grace window in
        // childOnline() covers the app's reconnect backoff.
        childWentOfflineAt.set(ws.childId, Date.now());
      }
      const child = data.children.find(c => c.id === ws.childId);
      if (child) { child.lastSeen = new Date().toISOString(); save(); }
      for (const s of [...sessions.values()]) {
        if (s.childWs === ws || s.aWs === ws || s.bWs === ws) closeSession(s, peerSockets(s), 'disconnect');
      }
    }
  });
});

try { fs.mkdirSync(MEDIA_DIR, { recursive: true }); } catch {}
if (require.main === module) {
  console.log(`[storage] mode=${STORAGE_MODE}${STORAGE_MODE === 'firestore' ? ` doc=${STORAGE_COLLECTION}/${STORAGE_DOC_ID}` : ''}`);
  console.log(`[media] backend=${MEDIA_BACKEND}${MEDIA_BACKEND === 'firestore' ? ' (firestore-chunks)' : ` dir=${MEDIA_DIR}`}`);
  if (STORAGE_MODE === 'firestore') {
    // Hydrate BEFORE listening so no request can mutate (or be
    // clobbered by) the pre-hydration state.
    hydrateFromFirestore()
      .catch(() => {})
      .finally(() => server.listen(PORT, () => console.log(`parent-monitor server on :${PORT} (data: ${DATA_FILE})`)));
  } else {
    server.listen(PORT, () => console.log(`parent-monitor server on :${PORT} (data: ${DATA_FILE})`));
  }
}

// Exported for tests (scripts/v2_1-test.js); running `node server.js` is unaffected.
module.exports = { injectInviteToken, parseInjectedToken };
// Test-only handle (scripts/step3-test.js): lets hermetic tests drive
// the wake path against a stubbed fetch and inspect the wake log and
// stored records. Not used by any wire path.
module.exports._test = { data, wakeLog, attemptWake, wakePendings, parentWakePendings, dataPendings, dataInflight, STORAGE_MODE, storageStats, normalizeNumber, canonicalizeNumber, MEDIA_BACKEND, mediaStore };
