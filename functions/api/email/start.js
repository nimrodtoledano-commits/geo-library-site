// POST /api/email/start  {username, email} — כניסה עם שם משתמש + מייל (D413): שולח קישור אימות חד-פעמי למייל (T296).
// האסימון: 32 בתים אקראיים; במסד רק גיבוב SHA-256; תוקף 15 דקות; שימוש אחד (verify.js). הקישור מוביל לאתר עם #vt=<אסימון>
// (פרגמנט — לא נשלח לשרת ביומני גישה/Referer). הקישור קשור לדפדפן שביקש (עוגייה __Host-geo_em, במסד רק גיבוב — REVIEW_CLIENT ה3):
// בדפדפן אחר (או סורק קישורים שמריץ JS) verify עונה 409 confirm_needed **בלי לשרוף** את האסימון, וממשיך רק אחרי לחיצה (confirm:true).
// ה4: אותה תשובה 200 לכל מייל תקין — מייל שלא ברשימה / חסום לא נשלח אליו כלום, אבל התשובה זהה (לא מסגיר מי רשום).
import { json, err, readJson, bodyStatus, emailAllowed, rateLimited, now, newToken, sha256hex, embindCookie } from '../../_lib/core.js';
import { getMailer, verifyMail } from '../../_lib/mailer.js';

export const EMAIL_TOKEN_MIN = 15;
const PER_EMAIL_HOUR = 3;                       // גלובלי (במסד), לא לכל מופע
const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const USER_RE = /^[\p{L}\p{N}][\p{L}\p{N} _\-]{0,30}[\p{L}\p{N}]$/u;   // 2–32 תווים, אותיות/ספרות בכל שפה, רווח _ - באמצע; בלי נקודה (ש6: «שלום evil.com,» במייל)

export function normEmail(v) { const s = String(v || '').trim().toLowerCase(); return s.length <= 254 && EMAIL_RE.test(s) ? s : null; }
export function normUser(v) { const s = String(v || '').replace(/\s+/g, ' ').trim(); return USER_RE.test(s) ? s : null; }

function siteBase(env, request) {
  const s = String(env.SITE_URL || '').trim().replace(/\/+$/, '');
  return /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(\/[\w\-./]*)?$/.test(s) ? s : new URL(request.url).origin;
}

export async function onRequestPost({ request, env }) {
  const t = now(env);
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  if (rateLimited('emailstart:' + ip, 5, 600000, t)) return err(429, 'rate_limited', { 'retry-after': '600' });
  const { body, error } = await readJson(request, 2048);
  if (error) return err(bodyStatus(error), error);
  const email = normEmail(body && body.email), username = normUser(body && body.username);
  if (!username) return err(400, 'bad_username');
  if (!email) return err(400, 'bad_email');
  const mailer = getMailer(env, request);
  if (!mailer) return err(503, 'mail_unavailable');           // כללי לשרת (לא תלוי במייל) — לא מסגיר דבר
  const DB = env.DB;
  const bind = newToken();
  const OK = () => json({ ok: true, sent: true, ttl_min: EMAIL_TOKEN_MIN }, 200, { 'set-cookie': embindCookie(bind) });   // ה4: תשובה אחת לכולם
  const recent = await DB.prepare('SELECT COUNT(*) AS n FROM email_tokens WHERE email = ?1 AND created_at > ?2').bind(email, t - 3600000).first('n');
  if (recent >= PER_EMAIL_HOUR) return err(429, 'too_many_mails', { 'retry-after': '3600' });
  if (!emailAllowed(env, email)) return OK();                  // לא ברשימה — לא נשלח, אותה תשובה
  const blocked = await DB.prepare("SELECT 1 AS b FROM users WHERE email = ?1 AND status != 'active'").bind(email).first();
  if (blocked) return OK();                                    // חסום — לא נשלח, אותה תשובה
  await DB.prepare('DELETE FROM email_tokens WHERE expires_at <= ?1').bind(t - 86400000).run();   // ניקוי: מה שפג לפני יותר מיום
  const token = newToken(), h = await sha256hex(token);
  await DB.prepare('INSERT INTO email_tokens (token_hash, email, username, created_at, expires_at, bind_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
    .bind(h, email, username, t, t + EMAIL_TOKEN_MIN * 60000, await sha256hex(bind)).run();
  try {
    await mailer.send(verifyMail({ to: email, username, link: siteBase(env, request) + '/#vt=' + token, minutes: EMAIL_TOKEN_MIN }));
  } catch (e) {
    await DB.prepare('DELETE FROM email_tokens WHERE token_hash = ?1').bind(h).run();
    console.error('api_error', '/api/email/start', 'mail_failed');
    return err(502, 'mail_failed');
  }
  return OK();
}
