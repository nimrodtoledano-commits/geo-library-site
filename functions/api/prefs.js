// /api/prefs — העדפות המשתמש המחובר כאובייקט JSON אחד (עד 4KB בבתים).
// GET ⇒ {prefs, updated_at}  ·  PUT {prefs:{...}} ⇒ מחליף את כולו.
import { json, err, currentUser, readJson, bodyStatus, byteLen, rateLimited, now } from '../_lib/core.js';

const MAX_PREFS = 4096;

export async function onRequestGet({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  const r = await env.DB.prepare('SELECT json, updated_at FROM prefs WHERE user_id = ?1').bind(u.id).first();
  return json({ prefs: r ? JSON.parse(r.json) : {}, updated_at: r ? r.updated_at : null });
}

export async function onRequestPut({ request, env }) {
  const u = await currentUser(request, env);
  if (!u) return err(401, 'not_signed_in');
  const t = now(env);
  if (rateLimited('prefs:' + u.id, 30, 60000, t)) return err(429, 'rate_limited', { 'retry-after': '60' });
  const { body, error } = await readJson(request, 8192);
  if (error) return err(bodyStatus(error), error);
  const p = body && body.prefs;
  if (!p || typeof p !== 'object' || Array.isArray(p)) return err(400, 'bad_prefs');
  const s = JSON.stringify(p);
  if (byteLen(s) > MAX_PREFS) return err(413, 'prefs_too_large');   // בבתים (עברית = 2 בתים לתו)
  await env.DB.prepare(`INSERT INTO prefs (user_id, json, updated_at) VALUES (?1, ?2, ?3)
     ON CONFLICT(user_id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at`).bind(u.id, s, t).run();
  return json({ ok: true, prefs: p, updated_at: t });
}
