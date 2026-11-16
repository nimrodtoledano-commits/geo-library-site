// POST /api/login  {credential: <אסימון הזהות מ-Google Identity Services>}
// דורש עוגיית nonce מ-POST /api/nonce, ו-nonce זהה באסימון (ש12); אחרי כניסה מוצלחת העוגייה נמחקת (חד-פעמי).
// מאמת את האסימון, בודק שהמייל ברשימת המורשים, יוצר/מעדכן משתמש לפי google_sub, ופותח הפעלה (עוגייה).
// כניסה כאורח לא עוברת כאן בכלל — האתר פתוח לכל מי שיש לו הקישור (D429); ההתחברות רשות (D409).
import { verifyGoogleIdToken, AuthError } from '../_lib/google_jwt.js';
import { json, err, readJson, bodyStatus, emailAllowed, createSession, sessionCookie, now, rateLimited, readCookie, sha256hex, COOKIE, SEEN_DAYS, NONCE_COOKIE, TOKEN_RE, clearNonceCookie } from '../_lib/core.js';

const DAY = 86400000;

export async function onRequestPost({ request, env }) {
  // הגבלת קצב לכניסה כאן ולא לפי נתיב ב-middleware — כך היא חלה על כל נתיב שמגיע לפונקציה הזו
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  if (rateLimited('login:' + ip, 10, 60000, now(env))) return err(429, 'rate_limited', { 'retry-after': '60' });
  const { body, error } = await readJson(request, 8192);
  if (error) return err(bodyStatus(error), error);
  if (!body || typeof body.credential !== 'string') return err(400, 'missing_credential');

  // nonce מהעוגייה; בלי עוגייה תקינה — מחרוזת ריקה, שאף אסימון לא יתאים לה (token_bad_nonce אחרי בדיקת החתימה)
  const nc = readCookie(request, NONCE_COOKIE);
  const nonce = nc && TOKEN_RE.test(nc) ? nc : '';
  let id;
  try {
    id = await verifyGoogleIdToken(body.credential, { clientId: env.GOOGLE_CLIENT_ID, fetchJwks: typeof env.__fetchJwks === 'function' ? env.__fetchJwks : undefined, nowMs: now(env), nonce });
  } catch (e) {
    if (e instanceof AuthError) {
      if (e.code === 'server_misconfigured') return err(503, e.code);
      if (e.code === 'jwks_unavailable') return err(503, e.code);
      return err(401, e.code);
    }
    throw e;
  }
  if (!emailAllowed(env, id.email)) return err(403, 'email_not_allowed');

  const t = now(env);
  const DB = env.DB;
  let user = await DB.prepare('SELECT id, email, status FROM users WHERE google_sub = ?1').bind(id.sub).first();
  if (!user) {
    // מייל שכבר שייך ל-sub אחר — לא מחברים אוטומטית (מניעת השתלטות דרך מייל ממוחזר)
    const clash = await DB.prepare('SELECT id, google_sub, status FROM users WHERE email = ?1').bind(id.email).first();
    if (clash && String(clash.google_sub).startsWith('em:')) {
      // משתמש שנוצר בכניסת מייל (D413, 0002): שתי הדרכים הוכיחו שליטה באותו מייל ⇒ מצמידים את מזהה Google לאותו משתמש
      if (clash.status !== 'active') return err(403, 'user_blocked');
      await DB.prepare('UPDATE users SET google_sub = ?1 WHERE id = ?2').bind(id.sub, clash.id).run();
      user = await DB.prepare('SELECT id, email, status FROM users WHERE google_sub = ?1').bind(id.sub).first();
    } else if (clash) return err(409, 'email_conflict');
  }
  if (!user) {
    await DB.prepare('INSERT INTO users (email, google_sub, created_at, last_seen_at, status) VALUES (?1, ?2, ?3, ?3, ?4)')
      .bind(id.email, id.sub, t, 'active').run();
    user = await DB.prepare('SELECT id, email, status FROM users WHERE google_sub = ?1').bind(id.sub).first();
  } else {
    if (user.status !== 'active') return err(403, 'user_blocked');
    if (user.email !== id.email) {
      const clash = await DB.prepare('SELECT id FROM users WHERE email = ?1 AND id != ?2').bind(id.email, user.id).first();
      if (clash) return err(409, 'email_conflict');
    }
    await DB.prepare('UPDATE users SET last_seen_at = ?1, email = ?2 WHERE id = ?3').bind(t, id.email, user.id).run();
    user.email = id.email;
  }
  // כניסה מחדש באותו דפדפן סוגרת את ההפעלה הקודמת שלו (לא של מכשירים אחרים)
  const old = readCookie(request, COOKIE);
  if (old) await DB.prepare('DELETE FROM sessions WHERE token_hash = ?1').bind(await sha256hex(old)).run();
  // שמירת נתונים: הפעלות שפגו ו«ראה» מעל 30 יום — של כל המשתמשים (אינדקסים sessions_exp, seen_ts)
  await DB.batch([
    DB.prepare('DELETE FROM sessions WHERE expires_at <= ?1').bind(t),
    DB.prepare('DELETE FROM seen WHERE first_ts <= ?1').bind(t - SEEN_DAYS * DAY),
  ]);
  const s = await createSession(env, user.id);
  return json({ ok: true, email: user.email }, 200, { 'set-cookie': [sessionCookie(s.token, s.maxAgeSec), clearNonceCookie()] });
}
