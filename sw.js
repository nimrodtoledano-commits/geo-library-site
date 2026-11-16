// D58: FCM (התראות פוש ברקע) — firebase compat 10.12.2
try{ importScripts('fb/firebase-app-compat.js','fb/firebase-messaging-compat.js');
  firebase.initializeApp({"apiKey": "AIzaSyD5bPA9wPvrvMDu_UGnp56Dc4X2AsJZ_vc", "authDomain": "geo-library-ae71a.firebaseapp.com", "projectId": "geo-library-ae71a", "storageBucket": "geo-library-ae71a.firebasestorage.app", "messagingSenderId": "446620064046", "appId": "1:446620064046:web:98a3ac6bf0df20b8dcc2bf"}); firebase.messaging(); }catch(e){}
self.addEventListener('notificationclick',e=>{ const u=(e.notification&&e.notification.data&&e.notification.data.FCM_MSG&&e.notification.data.FCM_MSG.notification&&e.notification.data.FCM_MSG.notification.click_action)||(e.notification&&e.notification.data&&(e.notification.data.link||(e.notification.data.FCM_MSG&&e.notification.data.FCM_MSG.data&&e.notification.data.FCM_MSG.data.link)))||'./'; e.notification.close(); e.waitUntil(clients.openWindow(u)); });
// s101 · מעטפת לפי חותמת + תמונות לפי תוכן (tools/build_public.py)
const SC = self.registration.scope, SHELL_P = 'geo-shell-', IMG_C = 'geo-img-1';
const SHELL = ['index.html', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'fb/firebase-app-compat.js', 'fb/firebase-firestore-compat.js', 'fb/firebase-messaging-compat.js'];
const IMG_RX = /^img\/([0-9a-f]{64})\.(?:jpg|png|webp|gif)$/, IMG_G = /img\/[0-9a-f]{64}\.(?:jpg|png|webp|gif)/g;
const abs = p => new URL(p, SC).href, IDX = abs('index.html');
const hex = async b => [...new Uint8Array(await crypto.subtle.digest('SHA-256', b))].map(x => x.toString(16).padStart(2, '0')).join('');
async function shellName(){ const ks = (await caches.keys()).filter(k => k.indexOf(SHELL_P) === 0).sort(); return ks.length ? ks[ks.length - 1] : null; }
const STAMP_MS = 2500;   // T282: כמה מחכים לחותמת בניווט לפני שמגישים מהמטמון (רשת איטית)
const INDEX_MS = 8000;   // סבב 2: כמה מחכים ל-index חדש שלם (4MB דחוס; ברשת סלולרית איטית יותר — המטמון עכשיו, החדש נשמר ברקע לפתיחה הבאה; הערכה)
async function stamp(){
  const r = await fetch(abs('VERSION_STAMP.json'), {cache: 'no-store'}); if(!r.ok) return null;
  const st = await r.json();
  return (st && /^[\w.-]{1,40}$/.test(String(st.version || '')) && /^[0-9a-f]{64}$/.test(String(st.index_sha256 || ''))) ? st : null;
}
const nameOf = st => SHELL_P + st.version + '-' + st.index_sha256.slice(0, 12);   // s101 סוקר N1: אותו שם גרסה עם index אחר ⇒ מטמון אחר ⇒ מתעדכן
let chain = Promise.resolve();   // T282: בדיקות בתור אחד (לא במקביל) — השנייה רואה שהמעטפת כבר עודכנה ויוצאת בלי הורדה
function check(st, ib){ const p = chain.then(() => doCheck(st, ib)).catch(() => {}); chain = p; return p; }
async function doCheck(st0, ib0){
  const st = st0 || await stamp(); if(!st) return;
  const name = nameOf(st), cur = await shellName();
  if(cur === name && await (await caches.open(name)).match(IDX)) return imgs(name, false);
  let ib = (ib0 && await hex(ib0) === st.index_sha256) ? ib0 : null;
  if(ib0 && !ib) return;   // T282: הגוף שהוגש בניווט לא תואם לחותמת (פריסה באמצע) ⇒ לא מורידים שוב עכשיו; ננסה בפתיחה הבאה
  if(!ib)
  // התקנה ראשונה: הדף כבר הורד בניווט (לרוב לכתובת ה-scope עצמה) ⇒ קודם ממטמון ה-HTTP, ורק אחר כך מהרשת; עדכון ⇒ no-store בלבד. תמיד אימות sha256.
  for(const [u, mode] of (cur ? [[IDX, 'no-store']] : [[SC, 'force-cache'], [IDX, 'force-cache'], [IDX, 'no-store']])){
    try{ const x = await fetch(u, {cache: mode}); if(!x.ok) continue; const b = await x.arrayBuffer(); if(await hex(b) === st.index_sha256){ ib = b; break; } }catch(e){}
  }
  if(!ib) return;   // לא תואם / רשת נפלה ⇒ נשארים על הישן; ננסה בפתיחה הבאה
  const c = await caches.open(name);
  for(const p of SHELL){ if(p === 'index.html') continue;
    try{ const x = await fetch(abs(p), {cache: cur ? 'no-store' : 'force-cache'}); if(x.ok) await c.put(abs(p), x); }catch(e){} }
  await c.put(IDX, new Response(ib, {headers: {'Content-Type': 'text/html; charset=utf-8'}}));
  for(const k of await caches.keys()) if(k !== name && k !== IMG_C && k.indexOf('geo-') === 0) await caches.delete(k);
  return imgs(name, true, ib);
}
// T282: ניווט לדף הראשי ⇒ [תשובה, עבודת רקע]. אותה גרסה / אין רשת ⇒ מטמון; גרסה חדשה ⇒ הרשת זורמת לדף ובמקביל נשמרת (אחרי sha256).
async function nav(q){
  let n = null, m = null;   // המעטפת השלמה האחרונה (מטמון שנבנה עכשיו ועוד בלי index.html — מדלגים עליו לקודמת)
  try{ for(const k of (await caches.keys()).filter(k => k.indexOf(SHELL_P) === 0).sort().reverse()){ m = await (await caches.open(k)).match(IDX); if(m){ n = k; break; } } }catch(err){}
  if(!m) return [await fetch(q), check()];   // ביקור ראשון / אין מעטפת — כמו קודם
  const sp = stamp().catch(() => null), st = await Promise.race([sp, new Promise(r => setTimeout(() => r(0), STAMP_MS))]);
  if(st === 0) return [m, sp.then(s => s && check(s))];   // רשת איטית: המטמון עכשיו, אותה חותמת ממשיכה ברקע (פתיחה הבאה) — בלי בקשה שנייה
  if(!st || nameOf(st) === n) return [m, st ? check(st) : Promise.resolve()];   // אין רשת / אותה גרסה ⇒ מטמון, בלי הורדת index
  let x = null; try{ x = await fetch(IDX, {cache: 'no-store'}); }catch(err){}
  if(!x || !x.ok) return [m, check(st)];
  // סבב 2 (סוקר APP): לא מזרימים ישר לדף — הורדה שנקטעה באמצע נתנה דף לבן. מחכים לגוף השלם עד INDEX_MS ומאמתים sha256 מול החותמת;
  // איטי ⇒ המטמון עכשיו, וההורדה הזו ממשיכה ברקע ונשמרת (הפתיחה הבאה = החדשה, בלי הורדה שנייה) · נקטע / sha לא תואם ⇒ המטמון.
  const bp = x.arrayBuffer(), ib = await Promise.race([bp.catch(() => null), new Promise(r => setTimeout(() => r(0), INDEX_MS))]);
  if(ib === 0) return [m, bp.then(b => check(st, b)).catch(() => {})];
  if(!ib || await hex(ib) !== st.index_sha256) return [m, Promise.resolve()];
  // תשובה חדשה (לא x עצמו): כתובת אחרי הפניה (Cloudflare /index.html ⇒ /) אסורה בתשובה לניווט
  return [new Response(ib, {headers: {'Content-Type': 'text/html; charset=utf-8'}}), check(st, ib)];
}
async function imgs(name, prune, ib){
  if(!ib){ const m = await (await caches.open(name)).match(IDX); if(!m) return; ib = await m.arrayBuffer(); }
  const want = new Set((new TextDecoder().decode(ib).match(IMG_G) || []).map(abs)), c = await caches.open(IMG_C);
  if(prune) for(const q of await c.keys()) if(!want.has(q.url)) await c.delete(q);
  const have = new Set((await c.keys()).map(q => q.url)), L = [...want].filter(u => !have.has(u));
  const one = async () => { while(L.length){ const u = L.shift(); try{ const x = await fetch(u, {cache: 'no-cache'}); if(x.ok){ const b = await x.clone().arrayBuffer();   /* no-cache: גוף שגוי במטמון ה-HTTP לא חוזר */
      if(await hex(b) === IMG_RX.exec(u.slice(SC.length))[1]) await c.put(u, x); } }catch(e){} } };
  await Promise.all([one(), one()]);
}
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.indexOf(SHELL_P) !== 0 && k !== IMG_C).map(k => caches.delete(k))))
  .then(() => self.clients.claim()).then(() => { check(); })));
self.addEventListener('fetch', e => {
  const q = e.request; if(q.method !== 'GET' || q.url.indexOf(SC) !== 0) return;   // חוצה-מקור / מחוץ ל-scope — לא מיורט
  const rel = q.url.slice(SC.length).split('#')[0], path = rel.split('?')[0];
  if(/^(?:reels|e|site)\//.test(path) || path === 'sw.js' || path === 'VERSION_STAMP.json') return;
  if(IMG_RX.test(path)){
    const key = abs(path);
    const want = IMG_RX.exec(path)[1];   // s101 סוקר B2: שומרים רק גוף שה-sha256 שלו = השם (פורטל Wi-Fi / שגיאת פרוקסי לא נתקעים במטמון); N5: כשל מטמון ⇒ רשת
    e.respondWith(caches.open(IMG_C).then(c => c.match(key).then(m => m || fetch(q).then(x => {
      if(x.ok){ const cp = x.clone(), ct = x.headers.get('Content-Type') || '';
        const keep = b => hex(b).then(h => { if(h === want) return c.put(key, new Response(b, {headers: {'Content-Type': ct}})); return 0; });
        cp.arrayBuffer().then(keep).then(r => r === 0 && fetch(key, {cache: 'reload'}).then(y => y.ok && y.arrayBuffer().then(keep))).catch(() => {}); }
      return x; }))).catch(() => fetch(q)));
    return;
  }
  if(q.mode === 'navigate' && (path === '' || path === 'index.html')){   // T282: החותמת קודם, ואז מטמון או רשת — nav()
    let fin; e.waitUntil(new Promise(r => { fin = r; }));
    e.respondWith(nav(q).then(([res, bg]) => { fin(bg); return res; }, err => { fin(); throw err; }));
    return;
  }
  if(rel === path && SHELL.indexOf(path) >= 0){
    e.respondWith(shellName().then(n => n ? caches.open(n).then(c => c.match(abs(path))) : null).then(m => m || fetch(q)).catch(() => fetch(q)));
  }
});
