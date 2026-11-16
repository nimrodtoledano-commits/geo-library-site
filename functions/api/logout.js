// POST /api/logout — סוגר את ההפעלה הנוכחית ומוחק את העוגייה. בלי הפעלה — עדיין 200 (אידמפוטנטי).
import { json, readCookie, sha256hex, clearCookie, COOKIE } from '../_lib/core.js';

export async function onRequestPost({ request, env }) {
  const token = readCookie(request, COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?1').bind(await sha256hex(token)).run();
  return json({ ok: true }, 200, { 'set-cookie': clearCookie() });
}
