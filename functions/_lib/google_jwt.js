// אימות אסימון הזהות (ID token) של Google — Web Crypto בלבד, בלי תלויות.
// בודק: מבנה, alg=RS256, kid מוכר, חתימה מול JWKS של Google, iss, aud (= ה-Client ID שלנו), exp, iat, email_verified.
// אין כאן סוד: מפתחות Google ציבוריים, ה-Client ID ציבורי.

export const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
export const GOOGLE_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];
const SKEW_SEC = 60;          // סטיית שעון מותרת
const MAX_TOKEN_LEN = 4096;

export class AuthError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function b64urlToBytes(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new AuthError('token_malformed');
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : s.length % 4 === 0 ? '' : null;
  if (pad === null) throw new AuthError('token_malformed');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseJson(bytes) {
  let v;
  try { v = JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new AuthError('token_malformed'); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new AuthError('token_malformed');   // «null», מספר, מערך ⇒ 401, לא 500
  return v;
}

// מטמון JWKS לכל מופע (isolate): לפי Cache-Control max-age של Google, ברירת מחדל שעה.
// רענון כפוי (kid לא מוכר) — לכל היותר פעם בדקה, כדי ש-kid אקראי לא יהפוך למשיכות חוזרות מ-Google.
const FORCE_MIN_MS = 60000;
let jwksCache = { keys: null, until: 0 };
let lastForced = -Infinity;
export function _resetJwksCache() { jwksCache = { keys: null, until: 0 }; lastForced = -Infinity; }

async function defaultFetchJwks() {
  const r = await fetch(GOOGLE_JWKS_URL);   // בלי מטמון קצה: רענון כפוי חייב לקבל את הרשימה העדכנית
  if (!r.ok) throw new AuthError('jwks_unavailable');
  const m = /max-age=(\d+)/.exec(r.headers.get('cache-control') || '');
  return { jwks: await r.json(), maxAgeSec: m ? Math.min(+m[1], 86400) : 3600 };
}

async function getKey(kid, fetchJwks, nowMs, forceRefresh) {
  if (forceRefresh) {
    if (nowMs - lastForced < FORCE_MIN_MS) return null;
    lastForced = nowMs;
  }
  if (!jwksCache.keys || nowMs >= jwksCache.until || forceRefresh) {
    const { jwks, maxAgeSec } = await fetchJwks();
    if (!jwks || !Array.isArray(jwks.keys)) throw new AuthError('jwks_unavailable');
    jwksCache = { keys: jwks.keys, until: nowMs + (maxAgeSec || 3600) * 1000 };
  }
  return jwksCache.keys.find(k => k.kid === kid && k.kty === 'RSA') || null;
}

/**
 * @param {string} token  אסימון הזהות מ-Google Identity Services (credential)
 * @param {{clientId:string, nowMs?:number, fetchJwks?:Function, nonce?:string}} opt
 * @returns {Promise<{sub:string,email:string}>}
 */
export async function verifyGoogleIdToken(token, opt) {
  const clientId = (opt && opt.clientId || '').trim();
  if (!clientId) throw new AuthError('server_misconfigured');
  const nowMs = opt.nowMs ?? Date.now();
  const fetchJwks = opt.fetchJwks || defaultFetchJwks;

  if (typeof token !== 'string' || token.length > MAX_TOKEN_LEN) throw new AuthError('token_malformed');
  const parts = token.split('.');
  if (parts.length !== 3) throw new AuthError('token_malformed');
  const header = parseJson(b64urlToBytes(parts[0]));
  const payload = parseJson(b64urlToBytes(parts[1]));
  const sig = b64urlToBytes(parts[2]);

  if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new AuthError('token_bad_alg');

  let jwk = await getKey(header.kid, fetchJwks, nowMs, false);
  if (!jwk) jwk = await getKey(header.kid, fetchJwks, nowMs, true);   // החלפת מפתחות אצל Google
  if (!jwk) throw new AuthError('token_unknown_kid');

  const key = await crypto.subtle.importKey(
    'jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  if (!ok) throw new AuthError('token_bad_signature');

  if (!GOOGLE_ISSUERS.includes(payload.iss)) throw new AuthError('token_bad_iss');
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(clientId)) throw new AuthError('token_bad_aud');
  if (Array.isArray(payload.aud) && payload.azp !== clientId) throw new AuthError('token_bad_aud');
  const nowSec = Math.floor(nowMs / 1000);
  if (typeof payload.exp !== 'number' || payload.exp + SKEW_SEC < nowSec) throw new AuthError('token_expired');
  if (typeof payload.iat !== 'number' || payload.iat - SKEW_SEC > nowSec) throw new AuthError('token_not_yet_valid');   // Google תמיד שולח iat
  if (typeof payload.sub !== 'string' || !payload.sub) throw new AuthError('token_malformed');
  if (typeof payload.email !== 'string' || !payload.email) throw new AuthError('token_no_email');
  if (payload.email_verified !== true && payload.email_verified !== 'true') throw new AuthError('email_not_verified');
  // nonce (ש12): כשהקורא מעביר opt.nonce — האסימון חייב לשאת בדיוק אותו ערך (Google מעתיק אותו מ-initialize)
  if (opt.nonce !== undefined) {
    if (typeof opt.nonce !== 'string' || !opt.nonce || typeof payload.nonce !== 'string' || payload.nonce !== opt.nonce) throw new AuthError('token_bad_nonce');
  }

  return { sub: payload.sub, email: payload.email.trim().toLowerCase() };
}
