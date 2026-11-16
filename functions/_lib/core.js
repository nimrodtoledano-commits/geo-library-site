// עזרים משותפים לשכבת המשתמשים: תשובות JSON, בדיקת Origin, עוגיית הפעלה, טעינת משתמש, הגבלת קצב.
// אין כאן סוד. הגדרות מגיעות ממשתני סביבה של Pages (ops/users/DEPLOY_STEPS.md):
//   GOOGLE_CLIENT_ID   — ה-Client ID הציבורי (חובה)
//   ALLOWED_EMAILS     — רשימת מיילים מורשים להתחברות, מופרדת בפסיקים; '*' = כל חשבון Google מאומת; ריק = אף אחד (סגור כברירת מחדל)
//   ALLOWED_ORIGINS    — מקורות נוספים מורשים לכתיבה (מופרדים בפסיקים); המקור של הבקשה עצמה מורשה תמיד
//   DB                 — קשירת D1

export const COOKIE = '__Host-geo_sess';
export const SESSION_DAYS = 30;
export const SEEN_DAYS = 30;
const DAY = 86400000;

export function json(body, status = 200, extra = {}) {
  const h = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  // ערך מערך ⇒ כמה כותרות באותו שם (למשל שתי עוגיות: הפעלה + מחיקת nonce)
  for (const [k, v] of Object.entries(extra || {})) {
    if (Array.isArray(v)) { h.delete(k); for (const x of v) h.append(k, x); } else h.set(k, v);
  }
  return new Response(JSON.stringify(body), { status, headers: h });
}
export const err = (status, code, extra) => json({ error: code }, status, extra);

export function now(env) { return env && typeof env.__now === 'function' ? env.__now() : Date.now(); }

function list(v) {
  return String(v || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

export function emailAllowed(env, email) {
  const L = list(env.ALLOWED_EMAILS);
  return L.includes('*') || L.includes(String(email).toLowerCase());
}

// כתיבה (POST/PUT/DELETE) מותרת רק עם Origin ששווה למקור הבקשה או ברשימת ALLOWED_ORIGINS. בלי Origin — נדחה.
export function originOk(request, env) {
  const o = request.headers.get('origin');
  if (!o || o === 'null') return false;
  const self = new URL(request.url).origin.toLowerCase();
  const oo = o.toLowerCase();
  return oo === self || list(env.ALLOWED_ORIGINS).includes(oo);
}

export function readCookie(request, name) {
  const h = request.headers.get('cookie') || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export function sessionCookie(token, maxAgeSec) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

// nonce לכניסת Google (ש12 של סוקר האבטחה): השרת מנפיק ערך אקראי בעוגייה קצרת חיים; הלקוח מעביר אותו ל-GIS (initialize nonce);
// Google מטביע אותו באסימון; login משווה את nonce שבאסימון לעוגייה. אסימון שנגנב במקום אחר לא עובר בלי העוגייה של אותו דפדפן.
export const NONCE_COOKIE = '__Host-geo_nonce';
export const NONCE_SEC = 600;
export const nonceCookie = v => `${NONCE_COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${NONCE_SEC}`;
export const clearNonceCookie = () => `${NONCE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
// קשירת קישור המייל לדפדפן שביקש אותו (REVIEW_CLIENT ה3): עוגייה קצרת חיים; במסד רק גיבוב (email_tokens.bind_hash)
export const EMBIND_COOKIE = '__Host-geo_em';
export const embindCookie = v => `${EMBIND_COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`;
export const clearEmbindCookie = () => `${EMBIND_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;   // 32 בתים אקראיים ב-base64url (newToken)

function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
export async function sha256hex(s) { return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))); }

export function newToken() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function createSession(env, userId) {
  const token = newToken();
  const t = now(env);
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(await sha256hex(token), userId, t, t + SESSION_DAYS * DAY).run();
  return { token, maxAgeSec: SESSION_DAYS * 86400 };
}

// המשתמש מההפעלה בלבד — אף פעם לא ממה שהדפדפן שלח בגוף הבקשה.
export async function currentUser(request, env) {
  const token = readCookie(request, COOKIE);
  if (!token || !TOKEN_RE.test(token)) return null;
  const h = await sha256hex(token);
  const row = await env.DB.prepare(
    `SELECT s.token_hash, s.expires_at, u.id, u.email, u.status, u.created_at, u.username
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1`).bind(h).first();
  if (!row) return null;
  if (row.expires_at <= now(env)) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?1').bind(h).run();
    return null;
  }
  if (row.status !== 'active') return null;
  return { id: row.id, email: row.email, username: row.username || null, created_at: row.created_at, token_hash: h };
}

export const byteLen = s => new TextEncoder().encode(s).length;
// שגיאת readJson ⇒ סטטוס: גוף גדול 413, השאר 400
export const bodyStatus = code => (code === 'too_large' ? 413 : 400);

export async function readJson(request, maxBytes = 16384) {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (!ct.startsWith('application/json')) return { error: 'bad_content_type' };
  const cl = Number(request.headers.get('content-length') || 0);
  if (cl > maxBytes) return { error: 'too_large' };            // לפני קריאת הגוף
  const txt = await request.text();
  if (byteLen(txt) > maxBytes) return { error: 'too_large' };   // גם בלי content-length; בבתים, לא בתווים
  try { return { body: JSON.parse(txt) }; } catch { return { error: 'bad_json' }; }
}

// הגבלת קצב בסיסית: חלון קבוע בזיכרון של המופע (isolate). לא גלובלית — הגנה ראשונה בלבד;
// ההגנה הגלובלית: כלל Rate limiting של Cloudflare (DEPLOY_STEPS צעד 6). ה-IP לא נשמר בשום מקום.
const buckets = new Map();
export function _resetRate() { buckets.clear(); }
export function rateLimited(key, limit, windowMs, t) {
  const b = buckets.get(key);
  if (!b || t - b.start >= windowMs) {
    if (buckets.size > 5000) buckets.clear();
    buckets.set(key, { start: t, n: 1 });
    return false;
  }
  b.n += 1;
  return b.n > limit;
}
