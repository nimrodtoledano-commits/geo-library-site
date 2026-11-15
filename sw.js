// D58: FCM (התראות פוש ברקע) — firebase compat 10.12.2
try{ importScripts('fb/firebase-app-compat.js','fb/firebase-messaging-compat.js');
  firebase.initializeApp({"apiKey": "AIzaSyD5bPA9wPvrvMDu_UGnp56Dc4X2AsJZ_vc", "authDomain": "geo-library-ae71a.firebaseapp.com", "projectId": "geo-library-ae71a", "storageBucket": "geo-library-ae71a.firebasestorage.app", "messagingSenderId": "446620064046", "appId": "1:446620064046:web:98a3ac6bf0df20b8dcc2bf"}); firebase.messaging(); }catch(e){}
self.addEventListener('notificationclick',e=>{ const u=(e.notification&&e.notification.data&&e.notification.data.FCM_MSG&&e.notification.data.FCM_MSG.notification&&e.notification.data.FCM_MSG.notification.click_action)||(e.notification&&e.notification.data&&(e.notification.data.link||(e.notification.data.FCM_MSG&&e.notification.data.FCM_MSG.data&&e.notification.data.FCM_MSG.data.link)))||'./'; e.notification.close(); e.waitUntil(clients.openWindow(u)); });
// D53: רשת קודם (תמיד הגרסה האחרונה), מטמון כגיבוי בלי חיבור
const C='geo-202611142025';
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{ if(e.request.method!=='GET') return;
  e.respondWith(fetch(e.request,{cache:'no-store'}).then(r=>{ const cp=r.clone(); caches.open(C).then(c=>c.put(e.request,cp)).catch(()=>{}); return r; })
    .catch(()=>caches.match(e.request))); });
