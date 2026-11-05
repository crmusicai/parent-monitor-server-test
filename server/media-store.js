/**
 * Chat-media byte storage (Step 3.5) — the bytes behind data.media.
 *
 * Two backends behind one tiny async interface (put / get / del):
 *
 *  - 'file' (default): bytes are files in the local media dir — exactly
 *    the historical behavior, and the rollback path. The dir sits on
 *    the host's EPHEMERAL disk, so bytes vanish on redeploy/sleep
 *    while the metadata in data.media persists (the field failure
 *    behind "sent photos never open again").
 *
 *  - 'firestore' (report name: "firestore-chunks"): Firebase Storage
 *    cannot be enabled on this project without a Blaze billing
 *    upgrade, so the bytes live in Firestore itself, chunked. Each
 *    media object becomes one manifest document in `mediaMeta`
 *    (size, chunk count, content type, sha256) plus N chunk documents
 *    in `mediaChunks` (`<mediaId>_<idx>`), each holding ~700 KB of
 *    raw bytes as a Firestore bytesValue (base64 on the wire; the
 *    encoded chunk stays safely under Firestore's ~1 MiB document
 *    limit). Upload writes chunks first and the manifest LAST, so a
 *    visible manifest implies a complete object; serve reads the
 *    manifest + chunks in order and verifies size + sha256 before
 *    returning a single byte — any miss or mismatch returns null and
 *    the caller answers exactly as for a missing local file. Auth is
 *    the same hand-rolled JWT -> OAuth2 service-account mechanism the
 *    state persistence layer uses (datastore scope); the server
 *    passes its own token getter in, so there is one token cache.
 *
 * Quota note: one upload costs (chunks + 1) Firestore writes and one
 * serve costs (chunks + 1) reads — at the 10 MB cap that is 16
 * writes / 16 reads per file. Zero new dependencies.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CHUNK_BYTES = 700 * 1024; // 716800 B -> 955,736 base64 chars < 1 MiB doc cap
const META_COLLECTION = 'mediaMeta';
const CHUNK_COLLECTION = 'mediaChunks';
const STORE_VERSION = 1;

function createMediaStore(opts = {}) {
  const backend = opts.backend === 'firestore' ? 'firestore' : 'file';
  const mediaDir = opts.mediaDir;
  const fetchImpl = opts.fetchImpl || (typeof fetch === 'function' ? fetch : null);

  // ---------------- file backend (historical behavior) ----------------
  if (backend === 'file') {
    const fileOf = (id) => path.join(mediaDir, id);
    return {
      backend,
      async put(id, buf) {
        try { fs.mkdirSync(mediaDir, { recursive: true }); } catch {}
        fs.writeFileSync(fileOf(id), buf);
      },
      async get(id) {
        try { return { buf: fs.readFileSync(fileOf(id)), contentType: null }; }
        catch { return null; }
      },
      async del(id) {
        try { fs.unlinkSync(fileOf(id)); } catch {}
      },
    };
  }

  // ---------------- firestore-chunks backend ----------------
  const sa = opts.serviceAccount || null;
  const getToken = typeof opts.getToken === 'function' ? opts.getToken : null;
  const base = `https://firestore.googleapis.com/v1/projects/${sa && sa.project_id}/databases/(default)/documents`;
  const docUrl = (collection, id) => `${base}/${collection}/${encodeURIComponent(id)}`;

  async function call(method, url, body) {
    if (!fetchImpl || !getToken) throw new Error('media_store_unconfigured');
    const token = await getToken();
    if (!token) throw new Error('oauth_failed');
    const res = await fetchImpl(url, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return res;
  }

  function manifestFields(id, buf, contentType, chunks) {
    return {
      mediaId: { stringValue: id },
      size: { integerValue: String(buf.length) },
      chunks: { integerValue: String(chunks) },
      contentType: { stringValue: String(contentType || 'application/octet-stream') },
      sha256: { stringValue: crypto.createHash('sha256').update(buf).digest('hex') },
      v: { integerValue: String(STORE_VERSION) },
    };
  }

  return {
    backend,
    /** Store buf under id. Chunks first, manifest last. Throws on failure. */
    async put(id, buf, contentType) {
      const chunks = Math.ceil(buf.length / CHUNK_BYTES); // 0 for an empty payload
      for (let i = 0; i < chunks; i++) {
        const slice = buf.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES);
        const res = await call('PATCH', docUrl(CHUNK_COLLECTION, `${id}_${i}`), {
          fields: {
            mediaId: { stringValue: id },
            idx: { integerValue: String(i) },
            data: { bytesValue: slice.toString('base64') },
          },
        });
        if (!res || !res.ok) throw new Error('media_chunk_put_http_' + (res && res.status));
      }
      const res = await call('PATCH', docUrl(META_COLLECTION, id), {
        fields: manifestFields(id, buf, contentType, chunks),
      });
      if (!res || !res.ok) throw new Error('media_manifest_put_http_' + (res && res.status));
    },
    /**
     * Fetch the whole object: manifest + every chunk in order,
     * verified against the manifest's size and sha256.
     * Returns { buf, contentType } or null when anything is missing
     * or fails verification (the caller maps null to the historical
     * "media file missing" 404).
     */
    async get(id) {
      try {
        const mres = await call('GET', docUrl(META_COLLECTION, id));
        if (!mres || mres.status === 404) return null;
        if (!mres.ok) return null;
        const doc = await mres.json().catch(() => null);
        const f = doc && doc.fields;
        if (!f || !f.sha256 || typeof f.sha256.stringValue !== 'string') return null;
        const size = parseInt(f.size && f.size.integerValue, 10);
        const chunks = parseInt(f.chunks && f.chunks.integerValue, 10);
        if (!Number.isFinite(size) || !Number.isFinite(chunks) || chunks < 0) return null;
        const parts = await Promise.all(
          Array.from({ length: chunks }, async (_, i) => {
            const cres = await call('GET', docUrl(CHUNK_COLLECTION, `${id}_${i}`));
            if (!cres || !cres.ok) return null;
            const cdoc = await cres.json().catch(() => null);
            const b64 = cdoc && cdoc.fields && cdoc.fields.data && cdoc.fields.data.bytesValue;
            return typeof b64 === 'string' ? Buffer.from(b64, 'base64') : null;
          })
        );
        if (parts.some((part) => part === null)) return null;
        const buf = Buffer.concat(parts);
        if (buf.length !== size) return null;
        const sha = crypto.createHash('sha256').update(buf).digest('hex');
        if (sha !== f.sha256.stringValue) return null;
        return {
          buf,
          contentType: f.contentType && typeof f.contentType.stringValue === 'string'
            ? f.contentType.stringValue : null,
        };
      } catch { return null; }
    },
    /** Remove manifest + all chunks (chunk count learned from the manifest). */
    async del(id) {
      let chunks = 0;
      try {
        const mres = await call('GET', docUrl(META_COLLECTION, id));
        if (mres && mres.ok) {
          const doc = await mres.json().catch(() => null);
          const n = doc && doc.fields && parseInt(doc.fields.chunks && doc.fields.chunks.integerValue, 10);
          if (Number.isFinite(n) && n > 0) chunks = n;
        }
      } catch {}
      const jobs = [];
      for (let i = 0; i < chunks; i++) {
        jobs.push(call('DELETE', docUrl(CHUNK_COLLECTION, `${id}_${i}`)).catch(() => null));
      }
      jobs.push(call('DELETE', docUrl(META_COLLECTION, id)).catch(() => null));
      await Promise.all(jobs);
    },
    _chunkBytes: CHUNK_BYTES,
  };
}

module.exports = { createMediaStore, CHUNK_BYTES, META_COLLECTION, CHUNK_COLLECTION };
