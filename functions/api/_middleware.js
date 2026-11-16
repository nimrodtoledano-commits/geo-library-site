// שכבה משותפת לכל /api/*: הגבלת קצב, בדיקת Origin לכל כתיבה, מסד מחובר, תפיסת שגיאות (ביומן — רק קוד שגיאה).
import { err, originOk, rateLimited, now } from '../_lib/core.js';

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function onRequest(context) {
  const { request, env } = context;
  const t = now(env);
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  const path = new URL(request.url).pathname;
  if (rateLimited('all:' + ip, 120, 60000, t)) return err(429, 'rate_limited', { 'retry-after': '60' });
  if (UNSAFE.has(request.method) && !originOk(request, env)) return err(403, 'bad_origin');
  if (!env.DB) return err(503, 'server_misconfigured');
  try {
    return await context.next();
  } catch (e) {
    console.error('api_error', path, (e && e.code) || 'exception');
    return err(500, 'server_error');
  }
}
