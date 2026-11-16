// POST /api/nonce — nonce חד-פעמי לכניסת Google (ש12 של סוקר האבטחה, REVIEW_USERS).
// מחזיר {nonce} ושם אותו בעוגייה __Host-geo_nonce (HttpOnly, 10 דקות). הלקוח מעביר אותו ל-google.accounts.id.initialize({nonce});
// /api/login דורש שה-nonce שבאסימון יהיה זהה לעוגייה. POST (ולא GET) — כך ה-middleware בודק Origin, ותצוגה מקדימה/סורק לא מנפיקים עוגייה.
import { json, newToken, nonceCookie, NONCE_SEC } from '../_lib/core.js';

export async function onRequestPost() {
  const nonce = newToken();
  return json({ nonce, ttl: NONCE_SEC }, 200, { 'set-cookie': nonceCookie(nonce) });
}
