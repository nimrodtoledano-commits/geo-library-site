// GET /api/me — מי מחובר (401 בלי הפעלה תקפה). DELETE /api/me — «מחק את החשבון שלי»: כל השורות של המשתמש.
import { json, err, currentUser, clearCookie } from '../_lib/core.js';

export async function onRequestGet({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  return json({ email: u.email, username: u.username, created_at: u.created_at });
}

export async function onRequestDelete({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  const DB = env.DB;
  await DB.batch([
    DB.prepare('DELETE FROM seen WHERE user_id = ?1').bind(u.id),
    DB.prepare('DELETE FROM seen_nsn WHERE user_id = ?1').bind(u.id),
    DB.prepare('DELETE FROM prefs WHERE user_id = ?1').bind(u.id),
    DB.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(u.id),
    DB.prepare('DELETE FROM email_tokens WHERE email = ?1').bind(u.email),
    DB.prepare('DELETE FROM users WHERE id = ?1').bind(u.id),
  ]);
  return json({ ok: true, deleted: true }, 200, { 'set-cookie': clearCookie() });
}
