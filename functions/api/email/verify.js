// POST /api/email/verify  {token} — הקישור מהמייל (#vt=) ⇒ הלקוח שולח את האסימון ⇒ הפעלה (D413, T296).
// חד-פעמי: UPDATE … WHERE used_at IS NULL AND expires_at > now — רק בקשה אחת מצליחה גם במקביל. משתמש קיים לפי המייל ⇒ אותו משתמש;
// חדש ⇒ google_sub = 'em:'+מייל (0002). אחרי הצלחה — כל שאר האסימונים הפתוחים של אותו מייל נמחקים.
// ה3: האסימון קשור לעוגיית __Host-geo_em של הדפדפן שביקש. עוגייה תואמת ⇒ ממשיכים. אחרת ⇒ 409 {error:'confirm_needed', email:<מוסתר>}
//     בלי לשרוף את האסימון; רק בקשה שנייה עם confirm:true (לחיצה של הקורא על «להשלים כניסה») ממשיכה.
import { json, err, readJson, bodyStatus, emailAllowed, rateLimited, now, sha256hex, TOKEN_RE, createSession, sessionCookie, readCookie, COOKIE, EMBIND_COOKIE, clearEmbindCookie } from '../../_lib/core.js';

export function maskEmail(e) { const [a, d] = String(e).split('@'); return (a ? a[0] : '') + '***@' + (d || ''); }

export async function onRequestPost({ request, env }) {
  const t = now(env);
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  if (rateLimited('emailverify:' + ip, 20, 600000, t)) return err(429, 'rate_limited', { 'retry-after': '600' });
  const { body, error } = await readJson(request, 1024);
  if (error) return err(bodyStatus(error), error);
  const token = body && body.token;
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return err(400, 'bad_token');
  const DB = env.DB, h = await sha256hex(token);
  if (body.confirm !== true) {
    const row = await DB.prepare('SELECT email, bind_hash FROM email_tokens WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2').bind(h, t).first();
    const bc = readCookie(request, EMBIND_COOKIE);
    if (row && !(bc && TOKEN_RE.test(bc) && row.bind_hash && row.bind_hash === await sha256hex(bc)))
      return json({ error: 'confirm_needed', email: maskEmail(row.email) }, 409);
  }
  const upd = await DB.prepare('UPDATE email_tokens SET used_at = ?1 WHERE token_hash = ?2 AND used_at IS NULL AND expires_at > ?1').bind(t, h).run();
  if (!upd || !upd.meta || upd.meta.changes !== 1) {
    const row = await DB.prepare('SELECT used_at, expires_at FROM email_tokens WHERE token_hash = ?1').bind(h).first();
    return err(401, !row ? 'token_invalid' : row.used_at ? 'token_used' : 'token_expired');
  }
  const tok = await DB.prepare('SELECT email, username FROM email_tokens WHERE token_hash = ?1').bind(h).first();
  if (!emailAllowed(env, tok.email)) return err(403, 'email_not_allowed');   // הרשימה השתנתה בין השליחה לאימות
  let user = await DB.prepare('SELECT id, email, status FROM users WHERE email = ?1').bind(tok.email).first();
  if (user && user.status !== 'active') return err(403, 'user_blocked');
  if (!user) {
    await DB.prepare('INSERT INTO users (email, google_sub, created_at, last_seen_at, status, username) VALUES (?1, ?2, ?3, ?3, ?4, ?5)')
      .bind(tok.email, 'em:' + tok.email, t, 'active', tok.username).run();
    user = await DB.prepare('SELECT id, email, status FROM users WHERE email = ?1').bind(tok.email).first();
  } else {
    await DB.prepare('UPDATE users SET last_seen_at = ?1, username = ?2 WHERE id = ?3').bind(t, tok.username, user.id).run();
  }
  await DB.prepare('DELETE FROM email_tokens WHERE email = ?1 AND used_at IS NULL').bind(tok.email).run();
  const old = readCookie(request, COOKIE);
  if (old) await DB.prepare('DELETE FROM sessions WHERE token_hash = ?1').bind(await sha256hex(old)).run();
  const s = await createSession(env, user.id);
  return json({ ok: true, email: user.email, username: tok.username }, 200, { 'set-cookie': [sessionCookie(s.token, s.maxAgeSec), clearEmbindCookie()] });
}
