// ממשק «שולח מייל» מופשט לכניסה עם שם משתמש + מייל (D413, T296). אין כאן שירות אמיתי ואין סוד.
// ממשק: { name, async send({to, subject, text, html}) } ⇒ {ok:true} או זורק.
// בחירה (getMailer):
//   env.__mailer            — מימוש מדומה לבדיקות (db/test) ולשרת המדומה המקומי; אובייקט עם send().
//   MAIL_MODE=dev-console   — רק כשהבקשה ל-localhost/127.0.0.1 (wrangler pages dev): הקישור נרשם ביומן המקומי. בכל מארח אחר — מתעלמים (לא דולף ליומני ייצור).
//   כל דבר אחר              — null ⇒ /api/email/start מחזיר 503 mail_unavailable. חיבור שירות אמיתי — ops/users/DEPLOY_STEPS.md «שליחת מייל» (פעולת בעלים).
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function getMailer(env, request) {
  if (env && env.__mailer && typeof env.__mailer.send === 'function') return env.__mailer;
  const host = new URL(request.url).hostname;
  if (env && env.MAIL_MODE === 'dev-console' && LOCAL_HOSTS.has(host)) {
    return { name: 'dev-console', async send(m) { console.log('[dev-mail] to=' + m.to + ' link=' + m.link); return { ok: true }; } };
  }
  return null;
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// תוכן המייל — עברית, טקסט פשוט + HTML מינימלי. הקישור הוא הדבר היחיד שחשוב; בלי מעקב, בלי תמונות.
export function verifyMail({ to, username, link, minutes }) {
  const subject = 'קישור כניסה — ספריית למידה גאופוליטית';
  const text = `שלום ${username},\n\nלכניסה לספרייה לוחצים על הקישור (בתוקף ${minutes} דקות, לשימוש אחד):\n${link}\n\nלא ביקשת? אפשר להתעלם מהמייל.`;
  const html = `<div dir="rtl" style="font-family:sans-serif;font-size:16px;line-height:1.5"><p>שלום ${esc(username)},</p>` +
    `<p>לכניסה לספרייה לוחצים על הקישור (בתוקף ${minutes} דקות, לשימוש אחד):</p><p><a href="${esc(link)}">כניסה לספרייה</a></p>` +
    `<p style="color:#666">לא ביקשת? אפשר להתעלם מהמייל.</p></div>`;
  return { to, subject, text, html, link };
}
