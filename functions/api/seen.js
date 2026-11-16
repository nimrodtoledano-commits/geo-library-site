// /api/seen — «ראה» של המשתמש המחובר (30 יום אחרונים).
// GET  ⇒ {keys:[{k, ts}]}
// POST {keys:[ "<ev_key>" | {k, ts} ], עד 200} ⇒ INSERT OR IGNORE (ה«ראה» הראשון נשמר) ⇒ מחזיר את האיחוד המלא —
//      כך «נראה» מקומי של אורח שנכנס מתמזג בלי התנגשויות (USERS_PLAN «ארכיטקטורה»).
// DELETE {keys:[…], עד 200} ⇒ «לא ראיתי» (D416): המפתחות יוצאים מה«ראה» ונרשמים ב-seen_nsn (ה2) ⇒ האירוע חוזר ל«7 הגדולים» בכל המכשירים. כל תשובה: {keys, nsn}.
import { json, err, currentUser, readJson, bodyStatus, rateLimited, now, SEEN_DAYS } from '../_lib/core.js';

const DAY = 86400000;
const MAX_KEYS = 200;
// מפתחות האירועים האמיתיים הם לרוב «p» + עברית + מספר (pהורמוזלפיאיראן…1113) ⇒ אותיות וספרות בכל שפה
const KEY_RE = /^[\p{L}\p{N}_.:\-]{1,120}$/u;
export const MAX_ROWS_PER_USER = 5000;   // = ה-LIMIT של list; מגן על מכסת הכתיבה היומית של D1

async function list(DB, uid, t) {
  const r = await DB.prepare('SELECT ev_key AS k, first_ts AS ts FROM seen WHERE user_id = ?1 AND first_ts > ?2 ORDER BY first_ts DESC LIMIT 5000')
    .bind(uid, t - SEEN_DAYS * DAY).all();
  return r.results || [];
}
// «לא ראיתי» של המשתמש (ה2) — חוזר עם כל תשובה, כדי שכל מכשיר יסתיר אותו גם אם שם הוא נקרא קודם
async function nsnList(DB, uid, t) {
  const r = await DB.prepare('SELECT ev_key AS k, ts FROM seen_nsn WHERE user_id = ?1 AND ts > ?2 ORDER BY ts DESC LIMIT 1000').bind(uid, t - SEEN_DAYS * DAY).all();
  return r.results || [];
}

export async function onRequestGet({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  const t = now(env);
  return json({ keys: await list(env.DB, u.id, t), nsn: await nsnList(env.DB, u.id, t) });
}

export async function onRequestPost({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  const t = now(env);
  if (rateLimited('seen:' + u.id, 30, 60000, t)) return err(429, 'rate_limited', { 'retry-after': '60' });
  const { body, error } = await readJson(request, 32768);
  if (error) return err(bodyStatus(error), error);
  const keys = body && body.keys;
  if (!Array.isArray(keys)) return err(400, 'missing_keys');
  if (keys.length > MAX_KEYS) return err(413, 'too_many_keys');
  const rows = new Map();
  for (const x of keys) {
    const k = typeof x === 'string' ? x : x && x.k;
    let ts = typeof x === 'object' && x && Number.isFinite(x.ts) ? Math.floor(x.ts) : t;
    if (typeof k !== 'string' || !KEY_RE.test(k)) return err(400, 'bad_key');
    if (ts > t || ts < t - SEEN_DAYS * DAY) ts = Math.min(Math.max(ts, t - SEEN_DAYS * DAY + 1), t);   // לא עתידי, לא מעבר ל-30 יום
    if (!rows.has(k) || rows.get(k) > ts) rows.set(k, ts);
  }
  const DB = env.DB;
  // ה2: מפתח שסומן «לא ראיתי» אחרי זמן הקריאה שנשלח — לא חוזר ל«ראה» (מכשיר אחר שבו נקרא קודם); קריאה מאוחרת יותר — נרשמת והסימון יורד
  const N = new Map((await nsnList(DB, u.id, t)).map(x => [x.k, x.ts]));
  const clear = [];
  for (const [k, ts] of [...rows]) {
    if (!N.has(k)) continue;
    if (N.get(k) >= ts) rows.delete(k); else clear.push(k);
  }
  const have = await DB.prepare('SELECT COUNT(*) AS n FROM seen WHERE user_id = ?1 AND first_ts > ?2').bind(u.id, t - SEEN_DAYS * DAY).first('n');
  if (have + rows.size > MAX_ROWS_PER_USER) return err(413, 'seen_quota');
  const st = [DB.prepare('DELETE FROM seen WHERE user_id = ?1 AND first_ts <= ?2').bind(u.id, t - SEEN_DAYS * DAY)];
  for (const [k, ts] of rows) st.push(DB.prepare('INSERT OR IGNORE INTO seen (user_id, ev_key, first_ts) VALUES (?1, ?2, ?3)').bind(u.id, k, ts));
  for (const k of clear) st.push(DB.prepare('DELETE FROM seen_nsn WHERE user_id = ?1 AND ev_key = ?2').bind(u.id, k));
  st.push(DB.prepare('DELETE FROM seen_nsn WHERE user_id = ?1 AND ts <= ?2').bind(u.id, t - SEEN_DAYS * DAY));
  await DB.batch(st);
  return json({ ok: true, received: rows.size, keys: await list(DB, u.id, t), nsn: await nsnList(DB, u.id, t) });
}

export async function onRequestDelete({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  const t = now(env);
  if (rateLimited('seen:' + u.id, 30, 60000, t)) return err(429, 'rate_limited', { 'retry-after': '60' });
  const { body, error } = await readJson(request, 32768);
  if (error) return err(bodyStatus(error), error);
  const keys = body && body.keys;
  if (!Array.isArray(keys)) return err(400, 'missing_keys');
  if (keys.length > MAX_KEYS) return err(413, 'too_many_keys');
  for (const k of keys) if (typeof k !== 'string' || !KEY_RE.test(k)) return err(400, 'bad_key');
  const DB = env.DB;
  if (keys.length) await DB.batch(keys.flatMap(k => [
    DB.prepare('DELETE FROM seen WHERE user_id = ?1 AND ev_key = ?2').bind(u.id, k),
    DB.prepare('INSERT OR REPLACE INTO seen_nsn (user_id, ev_key, ts) VALUES (?1, ?2, ?3)').bind(u.id, k, t),   // ה2: סימון שנשאר בשרת
  ]));
  return json({ ok: true, removed: keys.length, keys: await list(DB, u.id, t), nsn: await nsnList(DB, u.id, t) });
}
