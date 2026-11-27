import os, secrets, requests, html, uuid, time, hashlib, re, io, zipfile
from urllib.parse import quote, urlsplit
from pathlib import Path
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
from flask import Flask, request, session, redirect, url_for, render_template, render_template_string, Response

load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 21 * 1024 * 1024  # allow 20 MiB media plus multipart overhead
# CYRUS_PERSISTENT_SESSION_FIX
_session_key = os.getenv("SECRET_KEY")
if not _session_key:
    _key_file = Path.home() / ".cyrus_session_secret"
    if not _key_file.exists():
        _key_file.write_text(secrets.token_hex(32))
        try:
            _key_file.chmod(0o600)
        except OSError:
            pass
    _session_key = _key_file.read_text().strip()

app.secret_key = _session_key
# نشست‌ها کوتاه‌تر و کوکی در استقرار HTTPS فقط از مسیر امن ارسال می‌شود.
app.permanent_session_lifetime = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "1").strip().lower() not in ("0", "false", "no", "off")
app.config["SESSION_COOKIE_NAME"] = "cyrus_session"

@app.route("/manifest.webmanifest")
def cyrus_manifest():
    manifest = {
        "name": "CYRUS | پیوند پارسیان",
        "short_name": "CYRUS",
        "description": "پیام‌رسان پارسی با شکوه هخامنشی",
        "lang": "fa", "dir": "rtl", "start_url": "/home", "scope": "/",
        "display": "standalone", "orientation": "portrait",
        "background_color": "#0d1722", "theme_color": "#0d1722",
        "icons": [{"src": "/static/cyrus-app-icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}]
    }
    return app.response_class(__import__("json").dumps(manifest, ensure_ascii=False), mimetype="application/manifest+json")

@app.route("/service-worker.js")
def cyrus_service_worker():
    worker = r"""const CACHE='cyrus-static-v1';
const STATIC=['/static/cyrus-app-icon.svg','/static/cyrus-cylinder.jpg','/static/cyrus-tomb.jpg'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(STATIC)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
 const u=new URL(e.request.url);
 if(e.request.method!=='GET'||u.origin!==self.location.origin||!u.pathname.startsWith('/static/'))return;
 e.respondWith(caches.match(e.request).then(cached=>cached||fetch(e.request).then(r=>{if(r.ok){const copy=r.clone();caches.open(CACHE).then(c=>c.put(e.request,copy));}return r;})));
});"""
    return Response(worker, mimetype="application/javascript", headers={"Cache-Control":"no-cache","Service-Worker-Allowed":"/"})

@app.before_request
def cyrus_refresh_auth_session():
    if not session.get("access_token"):
        return

    expires_at = float(session.get("token_expires_at", 0) or 0)
    if expires_at > time.time() + 300:
        return

    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return

    try:
        response = requests.post(
            URL + "/auth/v1/token?grant_type=refresh_token",
            json={"refresh_token": refresh_token},
            headers={"apikey": KEY, "Content-Type": "application/json"},
            timeout=20
        )
        data = response.json()
        if response.status_code == 200 and data.get("access_token"):
            session["access_token"] = data["access_token"]
            session["refresh_token"] = data.get("refresh_token") or refresh_token
            session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
            session.permanent = True
        else:
            session["token_expires_at"] = time.time() + 60
    except Exception:
        session["token_expires_at"] = time.time() + 60

URL = os.getenv("SUPABASE_URL", "").rstrip("/")
KEY = os.getenv("SUPABASE_KEY", "")

@app.before_request
def cyrus_update_last_seen():
    if not session.get("access_token") or not session.get("user_id"):
        return
    if request.path.startswith("/static/"):
        return
    now = time.time()
    if now - float(session.get("last_seen_ping_at", 0) or 0) < 60:
        return
    try:
        response = requests.patch(
            URL + "/rest/v1/cyrus_profiles",
            params={"id": "eq." + str(session.get("user_id"))},
            json={"last_seen_at": datetime.now().astimezone().isoformat()},
            headers={
                "apikey": KEY,
                "Authorization": "Bearer " + session["access_token"],
                "Content-Type": "application/json",
                "Prefer": "return=minimal"
            },
            timeout=8
        )
        if response.ok:
            session["last_seen_ping_at"] = now
    except Exception:
        pass

@app.before_request
def cyrus_protect_state_changes():
    # مرورگرهای جدید مبدأ درخواست‌های تغییردهندهٔ داده را اعلام می‌کنند.
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    fetch_site = str(request.headers.get("Sec-Fetch-Site") or "").lower()
    if fetch_site == "cross-site":
        return "درخواست از مبدأ غیرمجاز پذیرفته نشد", 403
    origin = request.headers.get("Origin", "").strip()
    referer = request.headers.get("Referer", "").strip()
    source = origin or referer
    if not source:
        # برای مرورگرها/کلاینت‌های قدیمی که این سرآیندها را نمی‌فرستند،
        # سازگاری حفظ می‌شود؛ SameSite=Lax همچنان فعال است.
        return
    try:
        parsed = urlsplit(source)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return "مبدأ درخواست معتبر نیست", 403
        if parsed.netloc.lower() != request.host.lower():
            return "درخواست از مبدأ غیرمجاز پذیرفته نشد", 403
        if request.is_secure and parsed.scheme != "https":
            return "درخواست ناامن پذیرفته نشد", 403
    except Exception:
        return "مبدأ درخواست معتبر نیست", 403


@app.before_request
def cyrus_validate_form_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    # همهٔ ارسال‌های فرم مرورگر، حتی فرم خالی، باید توکن معتبر داشته باشند.
    content_type = str(request.mimetype or "").lower()
    is_browser_form = content_type in ("application/x-www-form-urlencoded", "multipart/form-data")
    if is_browser_form:
        expected = str(session.get("csrf_token") or "")
        supplied = str(request.form.get("csrf_token") or "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            return "اعتبار درخواست فرم تأیید نشد؛ صفحه را تازه‌سازی کنید", 403


@app.after_request
def cyrus_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(self), geolocation=(self)")
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.after_request
def cyrus_disable_dynamic_page_cache(response):
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

BASE = """
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#0d1722">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="icon" href="/static/cyrus-app-icon.svg" type="image/svg+xml">
<title>CYRUS | شاهنشاهی ارتباطات</title>
<style>
*{box-sizing:border-box}
:root{--gold:#e2b85f;--blue:#278bdc;--panel:rgba(9,15,25,.88);--muted:#b0b2b7}
body{margin:0;min-height:100vh;background:linear-gradient(rgba(3,7,15,.30),rgba(3,7,15,.48)),url('/static/cyrus-iran-panorama.jpg') center center/cover fixed;color:#f5eddd;font-family:Tahoma,Arial}
body:before{content:"";position:fixed;inset:0;background:rgba(3,7,15,.48);z-index:-1}
a{text-decoration:none;color:inherit}
.top{height:88px;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;background:rgba(5,10,20,.82);border-bottom:1px solid #987039;backdrop-filter:blur(8px)}
.brand{display:flex;align-items:center;gap:13px}
.emblem{width:58px;height:58px;border:2px solid var(--gold);border-radius:50%;display:grid;place-items:center;color:var(--gold);font-size:30px;background:rgba(12,17,25,.8);box-shadow:0 0 18px #a8783544}
.emblem img{width:100%;height:100%;object-fit:cover;border-radius:50%}

.logo{font-family:Georgia,serif;font-size:30px;letter-spacing:4px;color:var(--gold);font-weight:bold}
.sub{font-size:10px;color:#d5b777;margin-top:5px}
.top-actions{display:flex;gap:20px;align-items:center;color:var(--gold);font-size:27px}
.container{max-width:650px;margin:auto;padding-bottom:105px}
.welcome{padding:20px 18px 12px;text-shadow:0 2px 8px #000}
.welcome h2{font-size:17px;color:var(--gold);margin:0 0 7px}
.welcome p{font-size:11px;color:#d0c3a7;margin:0}
.searchbar{margin:8px 16px 16px;padding:14px 17px;border:1px solid #a17a3e;border-radius:28px;background:rgba(5,12,22,.83);color:#c5c2bd;display:flex;gap:13px;align-items:center;font-size:13px}
.searchbar span{font-size:24px;color:var(--gold)}
.tabs{display:flex;gap:9px;padding:0 15px 15px;overflow-x:auto}
.tab{flex:1;text-align:center;white-space:nowrap;padding:12px 12px;border-radius:28px;background:rgba(8,14,23,.88);border:1px solid #66502e;color:#ddd;font-size:12px}
.tab.active{background:linear-gradient(110deg,#a77a32,#f0c76e);border-color:#f5d37f;color:#17120b;font-weight:bold;box-shadow:0 5px 20px #bd8b3833}
.section-title{margin-top:8px;padding:13px 18px;color:var(--gold);font-size:13px;text-align:center;border-top:1px solid #9a733c;background:rgba(5,10,18,.65)}
.chat-list{min-height:270px}
.empty{margin:10px 18px 25px;padding:28px 20px;text-align:center;color:#ddd;background:rgba(5,10,18,.76);border:1px solid #80602e;border-radius:17px;backdrop-filter:blur(5px)}
.empty-icon{font-size:54px;color:var(--gold);margin-bottom:13px}
.empty h3{font-size:17px;color:var(--gold);font-weight:normal}
.empty p{font-size:12px;line-height:2;color:#c1c2c5}
.action{display:block;margin:18px auto 0;max-width:260px;padding:13px 20px;background:linear-gradient(100deg,#a4772d,#f0c66c);color:#17120a;border-radius:28px;font-size:13px;font-weight:bold}
.chat-row{display:flex;align-items:center;gap:13px;padding:15px 18px;background:rgba(8,14,23,.8);border-bottom:1px solid #5c482b}
.avatar{width:49px;height:49px;flex-shrink:0;border-radius:50%;display:grid;place-items:center;background:#182334;border:1px solid #b18a4c;color:var(--gold);font-size:23px}
.chat-info{flex:1;min-width:0}
.chat-name{font-size:14px;color:#f0d9a7;margin-bottom:7px}
.chat-preview{font-size:11px;color:#c0c0c0;overflow:hidden;text-overflow:ellipsis}
.card{margin:25px 16px;padding:23px;background:rgba(7,13,23,.9);border:1px solid #92703c;border-radius:17px;backdrop-filter:blur(8px)}
h2{color:var(--gold);text-align:center}
input{width:100%;padding:14px;margin:8px 0;background:#090f1b;border:1px solid #80643b;border-radius:9px;color:white;font-size:15px}
button{width:100%;padding:14px;margin-top:12px;border:0;border-radius:25px;background:linear-gradient(90deg,#9b702b,#e4c879);color:#17120a;font-weight:bold;font-size:15px}
.muted{text-align:center;color:#b8b8bb;font-size:12px;line-height:2}
.error{color:#ff7777;text-align:center;font-size:12px}
.form-link{color:#e9c16e}
.bottom{position:fixed;bottom:0;left:0;right:0;height:78px;background:rgba(5,10,18,.96);border-top:1px solid #987039;display:flex;justify-content:space-around;align-items:center;z-index:5;backdrop-filter:blur(10px)}
.bottom a{display:flex;flex:1;height:100%;flex-direction:column;justify-content:center;align-items:center;gap:5px;color:#c5a66c;font-size:10px}
.bottom a span{font-size:24px}
.bottom a.current{color:#ffcf70;border-bottom:3px solid #e7b950;background:linear-gradient(0deg,#a77a321f,transparent)}
@media(min-width:700px){.container{max-width:650px}.top{padding-right:max(20px,calc((100% - 650px)/2));padding-left:max(20px,calc((100% - 650px)/2))}}

body {
 background-image: linear-gradient(rgba(0,0,0,.30),rgba(0,0,0,.48)),url('/static/cyrus-tomb.jpg') !important;
 background-position: center center !important;
 background-size: cover !important;
 background-attachment: fixed !important;
 background-repeat: no-repeat !important;
}


/* CYRUS Rubika-like compact messenger layout */
.top {
  height: 60px;
  padding: 8px 14px;
  background: rgba(5,12,22,.96);
  border-bottom: 1px solid #203b59;
}
.brand { gap: 9px; }
.emblem {
  width: 40px;
  height: 40px;
  font-size: 21px;
  border-color: #287fc2;
  box-shadow: none;
}
.logo {
  font-size: 21px;
  letter-spacing: 2px;
  color: #e5bd69;
}
.sub { display: none; }
.top-actions { gap: 18px; font-size: 25px; }
.container {
  max-width: 650px;
  padding-bottom: 80px;
}
.welcome { display: none; }
.searchbar {
  margin: 10px 12px;
  padding: 11px 15px;
  border: 0;
  border-radius: 12px;
  background: #101d2c;
  color: #b7c7d8;
}
.searchbar span { color: #5ba8e8; }
.tabs {
  gap: 0;
  padding: 0 12px 8px;
  border-bottom: 1px solid #20364b;
}
.tab {
  flex: 1;
  padding: 11px 5px;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: #aab9c8;
  font-size: 12px;
}
.folder-unread {
  display: inline-flex;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  margin-inline-start: 5px;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  background: #2797e5;
  color: #fff;
  font-size: 10px;
  font-weight: bold;
  vertical-align: middle;
}
.tab.active {
  color: #69b9f7;
  background: transparent;
  border-bottom: 2px solid #3297df;
  box-shadow: none;
}
.chat-list { min-height: 220px; }
.chat-row {
  gap: 12px;
  padding: 12px 14px;
  background: rgba(7,15,25,.94);
  border-bottom: 1px solid #1c2b3b;
}
.avatar {
  width: 50px;
  height: 50px;
  border: 0;
  background: #18324b;
  color: #78bdf0;
  font-size: 22px;
}
.chat-name {
  color: #e5edf5;
  font-size: 14px;
  margin-bottom: 6px;
}
.chat-preview { color: #8ea2b5; font-size: 12px; }
.unread-badge{min-width:22px;height:22px;padding:0 6px;border-radius:12px;background:#2797e5;color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:bold}
.empty {
  margin: 16px 12px;
  padding: 25px 18px;
  background: #0d1927;
  border: 1px solid #20364b;
  border-radius: 14px;
}
.empty h3 { color: #7dbce9; }
.bottom {
  height: 65px;
  background: #07111d;
  border-top: 1px solid #20364b;
}
.bottom a {
  gap: 4px;
  color: #8fa5b8;
  font-size: 10px;
}
.bottom a span { font-size: 23px; }
.bottom a.current {
  color: #65b9f5;
  border-bottom: 2px solid #3297df;
  background: transparent;
}
body {
  background-image: linear-gradient(rgba(0,0,0,.42),rgba(0,0,0,.58)),url('/static/cyrus-tomb.jpg') !important;
}

</style>
</head>
<body>
{{ header|safe }}
{{ content|safe }}
{{ nav|safe }}
<div id="cyrusInstallBar" style="display:none;position:fixed;z-index:999;left:12px;right:12px;bottom:calc(82px + env(safe-area-inset-bottom));padding:12px 14px;border:1px solid #35516a;border-radius:16px;background:#101d2b;box-shadow:0 8px 30px #0008;align-items:center;gap:10px;color:#eaf2f8"><span style="font-size:22px">𓊹</span><span style="flex:1;font-size:13px">نصب CYRUS روی گوشی</span><button id="cyrusInstallBtn" style="border:0;border-radius:20px;padding:9px 15px;background:#278bdc;color:#fff;font-weight:bold">نصب</button><button id="cyrusInstallClose" aria-label="بستن" style="border:0;background:transparent;color:#9fb1c2;font-size:20px">×</button></div>
<script>
window.addEventListener('pageshow',function(event){
 const navEntry=performance.getEntriesByType('navigation')[0];
 if((event.persisted||(navEntry&&navEntry.type==='back_forward'))&&(location.pathname==='/'||location.pathname==='/home'))location.reload();
});
(function(){
 let deferred=null;
 const bar=document.getElementById('cyrusInstallBar'),btn=document.getElementById('cyrusInstallBtn'),close=document.getElementById('cyrusInstallClose');
 if('serviceWorker' in navigator)navigator.serviceWorker.register('/service-worker.js').catch(()=>{});
 if(!bar||!btn)return;
 window.addEventListener('beforeinstallprompt',function(e){
  e.preventDefault();deferred=e;
  if(!sessionStorage.getItem('cyrus-install-dismissed'))bar.style.display='flex';
 });
 btn.addEventListener('click',async function(){
  if(!deferred)return;
  deferred.prompt();await deferred.userChoice;deferred=null;bar.style.display='none';
 });
 close.addEventListener('click',function(){
  bar.style.display='none';sessionStorage.setItem('cyrus-install-dismissed','1');
 });
 if(window.matchMedia('(display-mode: standalone)').matches||window.navigator.standalone)bar.style.display='none';
})();
</script>
</body>
</html>
"""

def page(content):
    # افزودن خودکار توکن ضد CSRF به همه فرم‌های POST که از پوستهٔ اصلی عبور می‌کنند.
    csrf_token = session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        session["csrf_token"] = csrf_token
    csrf_input = '<input type="hidden" name="csrf_token" value="' + html.escape(csrf_token, quote=True) + '">'
    content = re.sub(
        r"""(<form\b(?=[^>]*\bmethod\s*=\s*["']?post\b)[^>]*>)""",
        lambda match: match.group(1) + csrf_input,
        str(content),
        flags=re.IGNORECASE
    )
    nav = ""
    header = ""
    current = request.path
    is_home = current in ("/", "/home")
    is_chat = current.startswith("/chat/") or current.startswith("/conversation/") or (current.startswith("/user/") and request.args.get("from_chat") == "1")
    if is_home:
        header = """
        <header class="top cyrus-home-top">
         <div class="brand">
          <div class="emblem"><img src="/static/cyrus-cylinder.jpg" alt="منشور کوروش بزرگ"></div>
          <div><div class="logo">CYRUS</div><div class="sub">پیوند پارسیان · شکوه هخامنشی</div></div>
         </div>
         <div class="top-actions"><a href="/search" aria-label="جستجو">⌕</a></div>
        </header>"""
    if session.get("access_token") and not is_chat:
        items = [
            ("/home", '<path d="M3 10.8 12 3l9 7.8"/><path d="M5.5 9.5V21h13V9.5M9.5 21v-6h5v6"/>', "بارگاه"),
            ("/contacts", '<path d="M16 21v-1.5a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4V21"/><circle cx="9.5" cy="7" r="4"/><path d="M17 3.5a4 4 0 0 1 0 7.5M21 21v-1.5a4 4 0 0 0-3-3.87"/>', "خویشان"),
            ("/search", '<circle cx="10.8" cy="10.8" r="7.2"/><path d="m16.2 16.2 5 5"/>', "کاوش"),
            ("/settings", '<path d="M12 2.8v2.1m0 14.2v2.1M4.9 4.9l1.5 1.5m11.2 11.2 1.5 1.5M2.8 12h2.1m14.2 0h2.1M4.9 19.1l1.5-1.5M17.6 6.4l1.5-1.5"/><circle cx="12" cy="12" r="5.2"/>', "تنظیمات")
        ]
        links = ""
        for href, icon, label in items:
            active = "current" if current == href or (href == "/home" and current == "/") else ""
            links += f'<a class="{active}" href="{href}" aria-label="{label}"><svg class="nav-svg" viewBox="0 0 24 24" aria-hidden="true">{icon}</svg><span>{label}</span></a>'
        nav = f'<style>.bottom{{height:76px;padding:5px 3px calc(5px + env(safe-area-inset-bottom));background:rgba(5,12,22,.97);border-top:1px solid #263c51;box-shadow:0 -8px 28px #0003}}.bottom a{{gap:4px;font-size:10px;color:#91a6b9;transition:color .18s,background .18s}}.bottom a span{{font-size:10px;line-height:1.3}}.bottom .nav-svg{{width:25px;height:25px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;transition:transform .18s}}.bottom a.current{{color:#e5bd69;border-bottom:0;background:linear-gradient(0deg,#d6a84a19,transparent)}}.bottom a.current .nav-svg{{color:#e5bd69;transform:translateY(-2px);filter:drop-shadow(0 2px 5px #c79b3b55)}}.bottom a.current:after{{content:"";position:absolute;bottom:0;width:32px;height:3px;border-radius:3px 3px 0 0;background:#d8b45f}}.bottom a{{position:relative}}</style><nav class="bottom">{links}</nav>'
    return render_template_string(BASE, content=content, nav=nav, header=header)

def auth_request(path, data):
    try:
        r = requests.post(URL + path, json=data,
            headers={"apikey": KEY, "Content-Type": "application/json"}, timeout=20)
        return r.status_code, r.json() if r.content else {}
    except Exception:
        return 0, {}


@app.route("/")
def splash():
    if session.get("access_token"):
        return redirect(url_for("home"))
    return render_template("splash.html")

@app.route("/home")
def home():
    if not session.get("access_token"):
        return redirect(url_for("login"))

    categories = {
        "all": ("همه", "هنوز گفتگویی ندارید", "گفتگوها، گروه‌ها و کانال‌های شما اینجا نمایش داده می‌شوند"),
        "private": ("خصوصی", "هنوز گفتگوی خصوصی ندارید", "گفتگوهای دونفره شما اینجا نمایش داده می‌شوند"),
        "group": ("گروه‌ها", "هنوز عضو گروهی نیستید", "گروه‌های شما اینجا نمایش داده می‌شوند"),
        "channel": ("کانال‌ها", "هنوز کانالی ندارید", "کانال‌های شما اینجا نمایش داده می‌شوند")
    }

    selected = request.args.get("type", "all")
    if selected not in categories:
        selected = "all"

    title, empty_title, empty_text = categories[selected]

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"]
    }

    conversations = []
    latest_messages = {}
    unread_counts = {}
    error = ""

    try:
        memberships = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={
                "select": "conversation_id,last_read_at",
                "user_id": "eq." + session["user_id"]
            },
            headers=headers,
            timeout=20
        )

        if not memberships.ok:
            raise Exception("دریافت عضویت‌ها ناموفق بود")

        membership_rows = memberships.json()
        room_ids = list(dict.fromkeys(
            str(x["conversation_id"])
            for x in membership_rows
            if x.get("conversation_id")
        ))
        read_markers = {
            str(x.get("conversation_id")): x.get("last_read_at")
            for x in membership_rows
        }
        unread_counts = {cid: 0 for cid in room_ids}
        if room_ids:
            try:
                unread_params = {
                    "select": "conversation_id,created_at",
                    "conversation_id": "in.(" + ",".join(room_ids) + ")",
                    "sender_id": "neq." + str(session["user_id"]),
                    "order": "created_at.desc",
                    "limit": "5000"
                }
                unread_response = requests.get(
                    URL + "/rest/v1/cyrus_messages",
                    params=unread_params,
                    headers=headers,
                    timeout=20
                )
                if unread_response.ok:
                    for msg in unread_response.json():
                        if not isinstance(msg, dict):
                            continue
                        cid = str(msg.get("conversation_id", ""))
                        marker_raw = read_markers.get(cid)
                        created_raw = msg.get("created_at")
                        if cid not in unread_counts or not created_raw:
                            continue
                        try:
                            created_dt = datetime.fromisoformat(str(created_raw).replace("Z", "+00:00"))
                            if created_dt.tzinfo is None:
                                created_dt = created_dt.replace(tzinfo=timezone.utc)
                            created_dt = created_dt.astimezone(timezone.utc)
                        except (TypeError, ValueError):
                            continue
                        marker_dt = None
                        if marker_raw:
                            try:
                                marker_dt = datetime.fromisoformat(str(marker_raw).replace("Z", "+00:00"))
                                if marker_dt.tzinfo is None:
                                    marker_dt = marker_dt.replace(tzinfo=timezone.utc)
                                marker_dt = marker_dt.astimezone(timezone.utc)
                            except (TypeError, ValueError):
                                marker_dt = None
                        if marker_dt is None or created_dt > marker_dt:
                            unread_counts[cid] += 1
            except Exception:
                pass

        if room_ids:
            rooms = requests.get(
                URL + "/rest/v1/cyrus_conversations",
                params={
                    "select": "id,title,type,created_at",
                    "id": "in.(" + ",".join(room_ids) + ")",
                    "order": "created_at.desc"
                },
                headers=headers,
                timeout=20
            )

            if not rooms.ok:
                raise Exception("دریافت گفتگوها ناموفق بود")

            conversations = rooms.json()

            messages = requests.get(
                URL + "/rest/v1/cyrus_messages",
                params={
                    "select": "conversation_id,content,message_type,created_at",
                    "conversation_id": "in.(" + ",".join(room_ids) + ")",
                    "order": "created_at.desc",
                    "limit": "500"
                },
                headers=headers,
                timeout=20
            )

            if messages.ok:
                for msg in messages.json():
                    cid = str(msg.get("conversation_id", ""))
                    if cid not in latest_messages:
                        latest_messages[cid] = msg

    except Exception:
        error = "دریافت گفتگوها انجام نشد؛ اتصال یا دسترسی دیتابیس را بررسی کنید"

    folder_unread = {key: 0 for key in categories}
    for room in conversations:
        room_id = str(room.get("id") or "")
        room_type = str(room.get("type") or "private")
        count = int(unread_counts.get(room_id, 0))
        folder_unread["all"] += count
        if room_type in folder_unread and room_type != "all":
            folder_unread[room_type] += count

    tabs = "".join(
        f'<a class="tab {"active" if key == selected else ""}" href="/home?type={key}">{item[0]}'
        + (f'<span class="folder-unread">{min(99, folder_unread[key])}</span>' if folder_unread[key] > 0 else "")
        + '</a>'
        for key, item in categories.items()
    )

    conversations.sort(
        key=lambda room: str(
            (latest_messages.get(str(room.get("id") or ""), {}) or {}).get("created_at")
            or room.get("created_at") or ""
        ),
        reverse=True
    )

    rows = ""

    for room in conversations:
        room_type = str(room.get("type") or "private")
        search_extra = ""

        if selected != "all" and room_type != selected:
            continue

        room_id = str(room.get("id") or "")
        try:
            uuid.UUID(room_id)
        except ValueError:
            continue

        # گفتگوی خصوصیِ خالی تا ارسال اولین پیام در بارگاه نمایش داده نشود.
        if room_type == "private" and room_id not in latest_messages:
            continue

        if room_type == "group":
            icon = "𓅃"
            room_title = room.get("title") or "گروه جدید"
        elif room_type == "channel":
            icon = "𓆃"
            room_title = room.get("title") or "کانال جدید"
        else:
            icon = "𓂀"
            room_title = room.get("title") or "گفتگوی خصوصی"

        msg = latest_messages.get(room_id, {})
        preview = str(msg.get("content") or "هنوز پیامی ارسال نشده")
        if len(preview) > 65:
            preview = preview[:65] + "..."

        unread = int(unread_counts.get(room_id, 0))
        unread_badge = f'<span class="unread-badge">{unread}</span>' if unread else ""
        avatar_color_list = [
            "#b85c78", "#4f8fbd", "#8d6bb8", "#3d9b87",
            "#c18a45", "#6b83c9", "#ba6650", "#658d52",
            "#a65caa", "#4b9ba8", "#a28a48", "#65758f"
        ]
        color_seed = sum((i + 1) * ord(ch) for i, ch in enumerate(room_id))
        avatar_color = avatar_color_list[color_seed % len(avatar_color_list)]
        avatar_html = (
            f'<div class="avatar" style="background:{avatar_color};border-color:{avatar_color}">{icon}</div>'
        )

        if room_type == "private":
            try:
                member_response = requests.get(
                    URL + "/rest/v1/cyrus_members",
                    params={
                        "select": "user_id",
                        "conversation_id": "eq." + room_id
                    },
                    headers=headers,
                    timeout=15
                )
                other_user_id = ""
                if member_response.ok:
                    for member in member_response.json():
                        candidate = str(member.get("user_id") or "")
                        if candidate and candidate != str(session.get("user_id") or ""):
                            other_user_id = candidate
                            break

                if other_user_id:
                    profile_response = requests.get(
                        URL + "/rest/v1/cyrus_profiles",
                        params={
                            "select": "display_name,username,avatar_url",
                            "id": "eq." + other_user_id,
                            "limit": "1"
                        },
                        headers=headers,
                        timeout=15
                    )
                    if profile_response.ok and profile_response.json():
                        person = profile_response.json()[0]
                        person_name = str(person.get("display_name") or person.get("username") or room_title)
                        room_title = person_name
                        try:
                            saved_contact_response = requests.get(
                                URL + "/rest/v1/cyrus_contacts",
                                params={"select":"contact_name","owner_id":"eq."+str(session.get("user_id") or ""),"contact_user_id":"eq."+other_user_id,"limit":"1"},
                                headers=headers, timeout=12
                            )
                            if saved_contact_response.ok and saved_contact_response.json():
                                room_title = str(saved_contact_response.json()[0].get("contact_name") or room_title)
                        except Exception:
                            pass
                        search_extra = room_title + " " + str(person.get("username") or "")
                        avatar_url = str(person.get("avatar_url") or "")
                        if avatar_url:
                            avatar_html = (
                                '<div class="avatar cyrus-real-avatar">'
                                f'<img src="{html.escape(avatar_url, quote=True)}" alt="{html.escape(person_name, quote=True)}">'
                                '</div>'
                            )
                        else:
                            first_letter = html.escape(person_name[:1] or icon)
                            person_seed = sum((i + 1) * ord(ch) for i, ch in enumerate(other_user_id))
                            person_color = avatar_color_list[person_seed % len(avatar_color_list)]
                            avatar_html = (
                                f'<div class="avatar" style="background:{person_color};border-color:{person_color}">'
                                f'{first_letter}</div>'
                            )
            except Exception:
                pass

        rows += f"""
        <div class="chat-row cyrus-chat-row" data-room-id="{room_id}" data-unread="{unread}" data-title="{html.escape(str(room_title), quote=True)}" data-search="{html.escape(str(room_title) + " " + preview + " " + search_extra, quote=True).lower()}"
             role="link" tabindex="0" aria-label="بازکردن گفتگوی {html.escape(str(room_title), quote=True)}"
             onclick="if(!event.target.closest('.cyrus-remove-chat,.cyrus-archive-chat,.cyrus-pin-chat,.cyrus-mute-chat'))window.location.href='/chat/{room_id}'"
             onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();window.location.href='/chat/{room_id}'}}"
             style="cursor:pointer">
          {avatar_html}
          <div class="chat-info">
            <div class="chat-name">{html.escape(str(room_title))}</div>
            <div class="chat-preview">{html.escape(preview)}</div>
          </div>
          {unread_badge}
          <button type="button" class="cyrus-archive-chat" data-room-id="{room_id}" onclick="event.stopPropagation();cyrusArchiveToggle(this)">آرشیو</button>
          <button type="button" class="cyrus-pin-chat" data-room-id="{room_id}" onclick="event.stopPropagation();cyrusTogglePinned(this)" aria-label="سنجاق گفتگو">سنجاق</button>
          <button type="button" class="cyrus-mute-chat" data-room-id="{room_id}" onclick="event.stopPropagation();cyrusToggleMuted(this)" aria-label="بی‌صدا کردن گفتگو">بی‌صدا</button>
          <form method="post" action="/chat/{room_id}/remove" class="cyrus-remove-chat" onclick="event.stopPropagation()" onsubmit='event.stopPropagation();return confirm("این گفتگو فقط از فهرست شما حذف شود؟ پیام‌ها و حساب مخاطب حذف نمی‌شوند.")'>
            <button type="submit">حذف گفتگو</button>
          </form>
        </div>"""

    if not rows and not error:
        rows = '<div class="empty"><h3>هیچ گفتگویی موجود نیست</h3></div>'

    content = f"""
    <div class="container">

      <style>
        .top{{height:66px;padding:8px 16px}}
        .top .emblem,.top .sub,.top-actions a[href="/settings"]{{display:none!important}}
        .top .brand{{gap:0}}
        .top .logo{{font-family:Tahoma,Arial,sans-serif;font-size:23px;letter-spacing:2px}}
        .top-actions{{gap:0}}
        .top-actions a[href="/search"]{{font-size:29px;padding:8px}}
        .cyrus-real-avatar{{overflow:hidden;padding:0}}
        .cyrus-real-avatar img{{width:100%;height:100%;object-fit:cover;border-radius:50%}}
        .cyrus-chat-row .avatar{{font-weight:bold;color:#fff;cursor:pointer}}
        .cyrus-chat-row:focus-visible{{outline:2px solid #3297df;outline-offset:-2px}}
        .cyrus-chat-row .chat-info{{cursor:pointer}}
      </style>
      <div class="tabs">{tabs}<a class="tab" href="/home?view=archive">آرشیو</a></div>

      <div class="cyrus-list-tools">
        <input id="cyrus-list-search" type="search" placeholder="جستجو در گفتگوها…" aria-label="جستجو در گفتگوها">
        <button type="button" id="cyrus-unread-filter" aria-pressed="false">فقط خوانده‌نشده‌ها</button>
        <select id="cyrus-list-sort" aria-label="ترتیب گفتگوها"><option value="recent">جدیدترین</option><option value="oldest">قدیمی‌ترین</option><option value="pinned">سنجاق‌شده‌ها</option></select>
        <button type="button" id="cyrus-clear-list-filters">پاک‌کردن فیلترها</button>
      </div>
      <div class="chat-list" id="cyrus-main-chat-list">{rows}</div>
      <script>
      const CYRUS_ARCHIVE_KEY = 'cyrus_archived_chats_v1';
      function cyrusArchivedIds(){{
        try{{const v=JSON.parse(localStorage.getItem(CYRUS_ARCHIVE_KEY)||'[]');return Array.isArray(v)?v.map(String):[];}}
        catch(_e){{return [];}}
      }}
      function cyrusApplyArchiveView(){{
        cyrusApplyListTools();
      }}
      function cyrusArchiveToggle(button){{
        const id=button.dataset.roomId;let ids=cyrusArchivedIds();
        if(ids.includes(id))ids=ids.filter(x=>x!==id);else ids.push(id);
        localStorage.setItem(CYRUS_ARCHIVE_KEY,JSON.stringify(ids));
        cyrusApplyArchiveView();
      }}
      const CYRUS_PIN_KEY='cyrus_pinned_chats_v1',CYRUS_MUTE_KEY='cyrus_muted_chats_v1';
      const CYRUS_LIST_PREFS_KEY='cyrus_chat_list_preferences_v1';
      function cyrusLoadListPrefs(){{
        try{{const p=JSON.parse(localStorage.getItem(CYRUS_LIST_PREFS_KEY)||'{{}}');const q=document.getElementById('cyrus-list-search'),u=document.getElementById('cyrus-unread-filter'),o=document.getElementById('cyrus-list-sort');if(q&&typeof p.query==='string')q.value=p.query;if(u&&p.unread===true){{u.setAttribute('aria-pressed','true');u.textContent='نمایش همه گفتگوها';}}if(o&&['recent','oldest','pinned'].includes(p.sort))o.value=p.sort;}}catch(_e){{}}
      }}
      function cyrusSaveListPrefs(){{
        const q=document.getElementById('cyrus-list-search'),u=document.getElementById('cyrus-unread-filter'),o=document.getElementById('cyrus-list-sort');
        try{{localStorage.setItem(CYRUS_LIST_PREFS_KEY,JSON.stringify({{query:q?.value||'',unread:u?.getAttribute('aria-pressed')==='true',sort:o?.value||'recent'}}));}}catch(_e){{}}
      }}
      function cyrusReadSet(key){{try{{const v=JSON.parse(localStorage.getItem(key)||'[]');return new Set(Array.isArray(v)?v.map(String):[]);}}catch(_e){{return new Set();}}}}
      function cyrusWriteSet(key,set){{localStorage.setItem(key,JSON.stringify(Array.from(set)));}}
      function cyrusTogglePinned(button){{const id=button.dataset.roomId,set=cyrusReadSet(CYRUS_PIN_KEY);set.has(id)?set.delete(id):set.add(id);cyrusWriteSet(CYRUS_PIN_KEY,set);cyrusApplyListTools();}}
      function cyrusToggleMuted(button){{const id=button.dataset.roomId,set=cyrusReadSet(CYRUS_MUTE_KEY);set.has(id)?set.delete(id):set.add(id);cyrusWriteSet(CYRUS_MUTE_KEY,set);cyrusApplyListTools();}}
      function cyrusApplyListTools(){{
        const rows=Array.from(document.querySelectorAll('.cyrus-chat-row'));
        const pins=cyrusReadSet(CYRUS_PIN_KEY),mutes=cyrusReadSet(CYRUS_MUTE_KEY);
        const term=(document.getElementById('cyrus-list-search')?.value||'').trim().toLowerCase();
        const onlyUnread=document.getElementById('cyrus-unread-filter')?.getAttribute('aria-pressed')==='true';
        const sort=document.getElementById('cyrus-list-sort')?.value||'recent';
        const archiveView=new URLSearchParams(location.search).get('view')==='archive';
        rows.forEach(row=>{{
          const id=row.dataset.roomId,archived=cyrusArchivedIds().includes(id),unread=Number(row.dataset.unread||0)>0;
          const pinned=pins.has(id),muted=mutes.has(id);
          row.classList.toggle('cyrus-is-pinned',pinned);row.classList.toggle('cyrus-is-muted',muted);row.classList.toggle('cyrus-is-unread',unread);
          const pb=row.querySelector('.cyrus-pin-chat'),mb=row.querySelector('.cyrus-mute-chat');
          if(pb)pb.textContent=pinned?'برداشتن سنجاق':'سنجاق';
          if(mb)mb.textContent=muted?'فعال‌کردن صدا':'بی‌صدا';
          const match=(row.dataset.search||'').includes(term);
          row.style.display=((archiveView===archived)&&match&&(!onlyUnread||unread)&&(sort!=='pinned'||pinned))?'':'none';
          if(pb)pb.setAttribute('aria-pressed',String(pinned));if(mb)mb.setAttribute('aria-pressed',String(muted));
        }});
        const list=document.getElementById('cyrus-main-chat-list');
        if(list){{const visible=rows.filter(r=>r.style.display!=='none');visible.sort((a,b)=>{{
          if(sort==='pinned')return (pins.has(b.dataset.roomId)?1:0)-(pins.has(a.dataset.roomId)?1:0);
          if(sort==='oldest')return rows.indexOf(b)-rows.indexOf(a);
          return (pins.has(b.dataset.roomId)?1:0)-(pins.has(a.dataset.roomId)?1:0)||rows.indexOf(a)-rows.indexOf(b);
        }}).forEach(r=>list.appendChild(r));}}
        const empty=list&&list.querySelector('.cyrus-archive-empty');
        if(list&&!rows.some(r=>r.style.display!=='none')){{let e=empty;if(!e){{e=document.createElement('div');e.className='empty cyrus-archive-empty';list.appendChild(e);}}e.textContent=archiveView?'گفتگوی آرشیوشده‌ای ندارید':'گفتگویی مطابق فیلترها پیدا نشد';e.style.display='block';}}
        else if(empty)empty.style.display='none';
        cyrusSaveListPrefs();
      }}
      cyrusLoadListPrefs();
      document.getElementById('cyrus-list-search')?.addEventListener('input',cyrusApplyListTools);
      document.getElementById('cyrus-unread-filter')?.addEventListener('click',function(){{const on=this.getAttribute('aria-pressed')!=='true';this.setAttribute('aria-pressed',String(on));this.textContent=on?'نمایش همه گفتگوها':'فقط خوانده‌نشده‌ها';cyrusApplyListTools();}});
      document.getElementById('cyrus-list-sort')?.addEventListener('change',cyrusApplyListTools);
      document.addEventListener('keydown',function(e){{const tag=document.activeElement?.tagName;if(e.key==='Escape'&&tag!=='INPUT'&&tag!=='TEXTAREA'&&tag!=='SELECT'){{const q=document.getElementById('cyrus-list-search');if(q&&q.value){{q.value='';cyrusApplyListTools();}}}}if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){{const q=document.getElementById('cyrus-list-search');if(q){{e.preventDefault();q.focus();q.select();}}}}if(e.key==='/'&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!['INPUT','TEXTAREA','SELECT'].includes(tag)){{const q=document.getElementById('cyrus-list-search');if(q){{e.preventDefault();q.focus();}}}}}});
      document.getElementById('cyrus-clear-list-filters')?.addEventListener('click',function(){{const q=document.getElementById('cyrus-list-search');if(q)q.value='';const f=document.getElementById('cyrus-unread-filter');if(f){{f.setAttribute('aria-pressed','false');f.textContent='فقط خوانده‌نشده‌ها';}}const sort=document.getElementById('cyrus-list-sort');if(sort)sort.value='recent';cyrusApplyListTools();}});
      cyrusApplyArchiveView();cyrusApplyListTools();
      </script>
      <style>
        .cyrus-chat-row{{position:relative;touch-action:pan-y;min-height:64px;padding:8px 12px;background:transparent;border:0;border-bottom:1px solid #24313d;border-radius:0;box-shadow:none;gap:10px}} .cyrus-chat-row .avatar{{width:42px;height:42px;min-width:42px;flex:0 0 42px;font-size:18px}} .cyrus-chat-row .chat-info{{min-width:0;flex:1;padding:0 2px}} .cyrus-chat-row .chat-name{{font-size:14px;font-weight:600;color:#e8edf3;line-height:1.5}} .cyrus-chat-row .chat-preview{{font-size:12px;color:#94a5b4;line-height:1.45;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}} .cyrus-chat-row .unread-badge{{min-width:18px;height:18px;padding:0 5px;font-size:10px;display:flex;align-items:center;justify-content:center;border-radius:10px}} .cyrus-chat-row .cyrus-remove-chat button{{font-size:11px;padding:5px 8px}}
        .cyrus-archive-chat{{width:auto;flex:0 0 auto;margin:0;padding:7px 9px;border:1px solid #34516a;border-radius:9px;background:#12263a;color:#b8d8ef;font-size:11px}}
        .cyrus-list-tools{{display:flex;gap:6px;align-items:center;padding:9px 12px;flex-wrap:wrap}}
        .cyrus-list-tools input{{flex:1 1 100%;min-width:0;margin:0;padding:10px 12px;background:#0b1826;border:1px solid #29445c;border-radius:10px;color:#fff;font:12px Tahoma}}
        .cyrus-list-tools button,.cyrus-list-tools select{{width:auto;flex:1 1 auto;margin:0;padding:8px 9px;background:#102337;border:1px solid #29445c;border-radius:9px;color:#b9d4e8;font:11px Tahoma}}
        .cyrus-pin-chat,.cyrus-mute-chat{{width:auto;flex:0 0 auto;margin:0;padding:7px 8px;background:#102337;border:1px solid #29445c;border-radius:9px;color:#b9d4e8;font:10px Tahoma}}
        .cyrus-chat-row.cyrus-is-pinned .chat-name:before{{content:'📌 ';font-size:10px}}
        .cyrus-chat-row.cyrus-is-muted .chat-preview:after{{content:'  · بی‌صدا';color:#6e91aa;font-size:10px}}
        .cyrus-chat-row.cyrus-is-unread{{background:rgba(31,93,139,.13)}}
        .cyrus-remove-chat{{display:none;margin:0}}
        .cyrus-remove-chat button{{width:auto;margin:0;padding:7px 10px;font-size:12px;background:#48252a;border:1px solid #a34a55;color:#ffd9dd}}
        .cyrus-chat-row.remove-open .cyrus-remove-chat{{display:block}}
      </style>
      <script>
      (()=>{{
        document.querySelectorAll('.cyrus-chat-row').forEach(row=>{{
          let timer=null;
          const start=()=>{{timer=setTimeout(()=>{{row.classList.add('remove-open');}},600);}};
          const cancel=()=>{{if(timer)clearTimeout(timer);timer=null;}};
          row.addEventListener('touchstart',start,{{passive:true}});
          row.addEventListener('touchend',cancel);
          row.addEventListener('touchmove',cancel,{{passive:true}});
          row.addEventListener('contextmenu',e=>{{e.preventDefault();row.classList.add('remove-open');}});
          row.addEventListener('click',e=>{{if(row.classList.contains('remove-open')&&!e.target.closest('.cyrus-remove-chat')){{e.preventDefault();row.classList.remove('remove-open');}}}});
        }});
      }})();
      </script>
      <p class="error">{html.escape(error)}</p>
    </div>
    """
    return page(content)


@app.route("/welcome")
def welcome():
    if session.get("access_token"):
        return redirect(url_for("home"))
    content = """
    <main class="container">
      <div class="card" style="text-align:center">
        <h2>به CYRUS خوش آمدید</h2>
        <p class="muted">پیوند پارسیان · شکوه هخامنشی</p>
        <a class="button" href="/register" style="display:block;text-decoration:none;margin:22px 0">
          ثبت‌نام
        </a>
        <p class="muted">
          <a class="form-link" href="/login">ورود به حساب قبلی</a>
        </p>
      </div>
    </main>
    """
    return page(content)

@app.route("/register", methods=["GET","POST"])
def register():
    error = ""
    if request.method == "POST":
        email = str(request.form.get("email") or "").strip().lower()
        password = request.form.get("password","")
        password_confirm = request.form.get("password_confirm","")
        username = str(request.form.get("username") or "").strip().lower()
        if not email or not password or not password_confirm or not username:
            error = "همه بخش‌ها را تکمیل کنید"
        elif len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            error = "نشانی ایمیل معتبر وارد کنید"
        elif not (3 <= len(username) <= 24 and all(ch.isalnum() or ch in "_-" for ch in username)):
            error = "نام کاربری باید ۳ تا ۲۴ نویسه و شامل حروف انگلیسی، عدد، خط تیره یا زیرخط باشد"
        elif len(password) < 8 or len(password) > 128:
            error = "گذرواژه باید بین ۸ تا ۱۲۸ نویسه باشد"
        elif password != password_confirm:
            error = "گذرواژه‌ها با یکدیگر مطابقت ندارند"
        else:
            code, data = auth_request("/auth/v1/signup", {"email":email,"password":password})
            if code in (200,201) and data.get("access_token"):
                # Start the newly registered account with a fresh session cookie.
                session.clear()
                session["access_token"] = data["access_token"]
                session["refresh_token"] = data.get("refresh_token", "")
                session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
                session.permanent = True
                session["user_id"] = data["user"]["id"]
                profile_created = False
                try:
                    profile_response = requests.post(
                        URL + "/rest/v1/cyrus_profiles",
                        json={"id":data["user"]["id"],"username":username,"display_name":username},
                        headers={"apikey":KEY,"Authorization":"Bearer "+data["access_token"],
                        "Content-Type":"application/json","Prefer":"resolution=merge-duplicates"},
                        timeout=20
                    )
                    profile_created = profile_response.ok
                except Exception:
                    profile_created = False

                # اگر نام کاربری تکراری باشد یا ارتباط لحظه‌ای قطع شود،
                # پروفایل با نام جایگزین امن ساخته می‌شود.
                if not profile_created:
                    profile_created = bool(cyrus_ensure_profile(email))
                if profile_created:
                    return redirect(url_for("home"))

                session.clear()
                error = "حساب ساخته شد، اما ایجاد نمایه کامل نشد. دوباره وارد شوید تا ساخت نمایه تکرار شود."
            if code in (200, 201) and data.get("user"):
                error = "حساب ساخته شد، اما تأیید ایمیل لازم است. تا زمانی که ایمیل تأیید دریافت و تأیید نشود، ورود انجام نمی‌شود."
            else:
                error = data.get("msg", data.get("message", "ثبت‌نام انجام نشد؛ تنظیمات ارسال ایمیل را بررسی کنید"))
    content = f"""
    <main class="container"><div class="card">
    <h2>پیوستن به CYRUS</h2><p class="muted">ساخت حساب کاربری</p>
    <p class="error">{html.escape(str(error))}</p>
    <form method="post">
    <input name="username" placeholder="نام کاربری" required>
    <input name="email" type="email" placeholder="ایمیل" required>
    <input name="password" type="password" placeholder="رمز عبور" required autocomplete="new-password">
    <input name="password_confirm" type="password" placeholder="تکرار رمز عبور" required autocomplete="new-password">
    <button>ایجاد حساب</button></form>
    <p class="muted"><a class="form-link" href="/login">قبلاً حساب ساخته‌اید؟ ورود</a></p>
    </div></main>"""
    return page(content)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    error = ""
    notice = ""
    if request.method == "POST":
        email = str(request.form.get("email") or "").strip().lower()
        if not email or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            error = "نشانی ایمیل معتبر وارد کنید"
        else:
            try:
                redirect_to = request.host_url.rstrip("/") + url_for("reset_password")
                code, data = auth_request(
                    "/auth/v1/recover?redirect_to=" + quote(redirect_to, safe=""),
                    {"email": email}
                )
                if code in (200, 204):
                    notice = "اگر این ایمیل در CYRUS ثبت شده باشد، پیوند بازیابی برای آن ارسال می‌شود. پوشه هرزنامه را هم بررسی کنید."
                else:
                    # Do not reveal whether an account exists.
                    notice = "در صورت وجود حساب، پیام بازیابی ارسال می‌شود. چند دقیقه بعد صندوق ایمیل را بررسی کنید."
            except Exception:
                error = "ارسال درخواست بازیابی انجام نشد؛ کمی بعد دوباره تلاش کنید"

    content = f"""
    <main class="container"><div class="card">
      <h2>بازیابی گذرواژه</h2>
      <p class="muted">ایمیل حساب خود را وارد کنید تا پیوند امن بازیابی برایتان ارسال شود.</p>
      <p class="error">{html.escape(error)}</p>
      <p class="muted" style="color:#9bd6b0">{html.escape(notice)}</p>
      <form method="post">
        <input name="email" type="email" placeholder="ایمیل حساب" required autocomplete="email" maxlength="254">
        <button type="submit">ارسال پیوند بازیابی</button>
      </form>
      <p class="muted"><a class="form-link" href="/login">بازگشت به ورود</a></p>
    </div></main>"""
    return page(content)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    error = ""
    success = ""
    if request.method == "POST":
        recovery_token = str(request.form.get("recovery_token") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("password_confirm") or ""
        if not recovery_token or len(recovery_token) > 4096:
            error = "پیوند بازیابی معتبر نیست یا منقضی شده است؛ دوباره درخواست بازیابی بدهید."
        elif len(password) < 8 or len(password) > 128:
            error = "گذرواژه باید بین ۸ تا ۱۲۸ نویسه باشد."
        elif password != confirm:
            error = "گذرواژه‌ها با یکدیگر مطابقت ندارند."
        else:
            try:
                update_response = requests.put(
                    URL + "/auth/v1/user",
                    json={"password": password},
                    headers={"apikey": KEY, "Authorization": "Bearer " + recovery_token,
                             "Content-Type": "application/json"},
                    timeout=20
                )
                if update_response.ok:
                    success = "گذرواژه با موفقیت تغییر کرد. اکنون با گذرواژه جدید وارد شوید."
                else:
                    error = "پیوند بازیابی منقضی یا نامعتبر است؛ دوباره درخواست پیوند بدهید."
            except Exception:
                error = "ارتباط با سرور برقرار نشد؛ دوباره تلاش کنید."

    content = f"""
    <main class="container"><div class="card">
      <h2>تعیین گذرواژه تازه</h2>
      <p class="muted">پیوند بازیابی را از ایمیل CYRUS باز کنید؛ سپس گذرواژه تازه را وارد کنید.</p>
      <p class="error">{html.escape(error)}</p>
      <p class="muted" style="color:#9bd6b0">{html.escape(success)}</p>
      <form method="post" id="cyrusResetPasswordForm">
        <input type="hidden" name="recovery_token" id="cyrusRecoveryToken">
        <input name="password" type="password" placeholder="گذرواژه تازه (حداقل ۸ نویسه)" required minlength="8" maxlength="128" autocomplete="new-password">
        <input name="password_confirm" type="password" placeholder="تکرار گذرواژه تازه" required minlength="8" maxlength="128" autocomplete="new-password">
        <button type="submit">تغییر گذرواژه</button>
      </form>
      <p class="muted" id="cyrusResetHint">در حال بررسی پیوند بازیابی…</p>
      <p class="muted"><a class="form-link" href="/login">بازگشت به ورود</a></p>
    </div></main>
    <script>
    (function(){{
      const params=new URLSearchParams(location.hash.slice(1));
      const token=params.get('access_token')||'';
      const type=params.get('type')||'';
      const field=document.getElementById('cyrusRecoveryToken');
      const form=document.getElementById('cyrusResetPasswordForm');
      const hint=document.getElementById('cyrusResetHint');
      if(token && (type==='recovery' || !type)){{
        field.value=token;
        hint.textContent='پیوند بازیابی شناسایی شد؛ گذرواژه تازه را وارد کنید.';
        history.replaceState(null,'',location.pathname+location.search);
      }}else if({str(bool(success)).lower()}){{
        form.style.display='none';hint.textContent='اکنون می‌توانید وارد حساب شوید.';
      }}else{{
        form.style.display='none';
        hint.textContent='پیوند معتبر پیدا نشد؛ از صفحه بازیابی، پیوند تازه دریافت کنید.';
      }}
      form.addEventListener('submit',function(e){{
        if(!field.value){{e.preventDefault();hint.textContent='پیوند بازیابی معتبر نیست.';}}
      }});
    }})();
    </script>"""
    return page(content)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        email = str(request.form.get("email") or "").strip().lower()
        if not email or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            error = "نشانی ایمیل معتبر وارد کنید"
        else:
            session.clear()
            session["cyrus_login_email"] = email
            return redirect(url_for("login_password"))

    content = f"""
    <main class="container"><div class="card">
      <h2>ورود به CYRUS</h2>
      <p class="muted">ابتدا ایمیل حساب خود را وارد کنید</p>
      <p class="error">{html.escape(error)}</p>
      <form method="post">
        <input name="email" type="email" placeholder="ایمیل" required autocomplete="email">
        <button>ادامه</button>
      </form>
      <p class="muted"><a class="form-link" href="/register">ساخت حساب جدید</a></p>
      <p class="muted"><a class="form-link" href="/forgot-password">بازیابی گذرواژه فراموش‌شده</a></p>
    </div></main>
    """
    return page(content)


@app.route("/login/password", methods=["GET", "POST"])
def login_password():
    email = session.get("cyrus_login_email")
    if not email:
        return redirect(url_for("login"))

    error = ""
    if request.method == "POST":
        password = request.form.get("password", "")
        code, data = auth_request(
            "/auth/v1/token?grant_type=password",
            {"email": email, "password": password}
        )
        if code == 200 and data.get("access_token"):
            # Rotate the client session after successful authentication.
            session.clear()
            session["access_token"] = data["access_token"]
            session["refresh_token"] = data.get("refresh_token", "")
            session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
            session.permanent = True
            session["user_id"] = data["user"]["id"]
            cyrus_ensure_profile(email)
            session.pop("cyrus_login_email", None)
            return redirect(url_for("home"))
        error = "رمز عبور صحیح نیست؛ دوباره تلاش کنید"

    content = f"""
    <main class="container"><div class="card">
      <h2>رمز عبور</h2>
      <p class="muted">{html.escape(email)}</p>
      <p class="error">{html.escape(error)}</p>
      <form method="post">
        <input name="password" type="password" placeholder="رمز عبور" required autocomplete="current-password">
        <button>ورود به حساب</button>
      </form>
      <p class="muted"><a class="form-link" href="/login">بازگشت و تغییر ایمیل</a></p>
      <p class="muted"><a class="form-link" href="/forgot-password">گذرواژه را فراموش کرده‌اید؟</a></p>
    </div></main>
    """
    return page(content)


@app.route("/logout", methods=["POST"])
def logout():
    # Revoke the Supabase session server-side before clearing the local cookie.
    access_token = str(session.get("access_token") or "")
    if access_token and URL and KEY:
        try:
            requests.post(
                URL + "/auth/v1/logout",
                headers={"apikey": KEY, "Authorization": "Bearer " + access_token},
                timeout=12
            )
        except Exception:
            pass
    session.clear()
    response = redirect("/login")
    response.delete_cookie(
        app.config.get("SESSION_COOKIE_NAME", "cyrus_session"),
        path=app.config.get("SESSION_COOKIE_PATH", "/"),
        domain=app.config.get("SESSION_COOKIE_DOMAIN")
    )
    return response


@app.route("/search", methods=["GET"])
def search():
    if not session.get("access_token"):
        return redirect(url_for("login"))

    raw_query = request.args.get("q", "").strip()
    selected_type = request.args.get("type", "all")
    if selected_type not in ("all", "messages", "people", "groups", "channels"):
        selected_type = "all"
    query = "".join(
        ch for ch in raw_query
        if ch.isalnum() or ch in " _-@."
    )[:60].strip()

    people = []
    rooms = []
    joined_ids = set()
    error = ""

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"]
    }

    if query:
        try:
            # جستجوی کاربران از طریق تابع امن پایگاه داده
            people_response = requests.post(
                URL + "/rest/v1/rpc/cyrus_search_users",
                json={"p_query": query.lstrip("@")},
                headers={**headers, "Content-Type": "application/json"},
                timeout=20
            )
            if people_response.ok:
                result = people_response.json()
                people = result if isinstance(result, list) else (result.get("data", []) if isinstance(result, dict) else [])
                if not isinstance(people, list):
                    people = []
                people = [item for item in people if isinstance(item, dict)]

            # جستجوی گروه‌ها و کانال‌ها
            room_response = requests.get(
                URL + "/rest/v1/cyrus_conversations",
                params={
                    "select": "id,title,type,created_by,is_public",
                    "type": "in.(group,channel)",
                    "title": "ilike.*" + query + "*",
                    "order": "created_at.desc",
                    "limit": "100"
                },
                headers=headers,
                timeout=20
            )

            if room_response.ok:
                result = room_response.json()
                rooms = result if isinstance(result, list) else []
                if not isinstance(rooms, list):
                    rooms = []
                rooms = [item for item in rooms if isinstance(item, dict)]

            # تشخیص اینکه کاربر عضو کدام گفتگوهاست
            membership_response = requests.get(
                URL + "/rest/v1/cyrus_members",
                params={
                    "select": "conversation_id",
                    "user_id": "eq." + str(session.get("user_id", ""))
                },
                headers=headers,
                timeout=20
            )

            if membership_response.ok:
                membership_data = membership_response.json()
                if isinstance(membership_data, list):
                    joined_ids = {
                        str(item.get("conversation_id"))
                        for item in membership_data
                        if isinstance(item, dict) and item.get("conversation_id")
                    }

        except Exception:
            error = "جستجو با مشکل اتصال روبه‌رو شد"

    people_rows = ""
    for person in people:
        uid = str(person.get("id") or "")
        username = str(person.get("username") or "")
        name = str(person.get("display_name") or username or "کاربر")

        try:
            uuid.UUID(uid)
        except ValueError:
            continue

        people_rows += f"""
        <div class="chat-row search-result" data-kind="people">
          <div class="avatar">𓅃</div>
          <div class="chat-info">
            <div class="chat-name">{html.escape(name)}</div>
            <div class="chat-preview">@{html.escape(username)}</div>
          </div>
          <form method="post" action="/start-chat/{html.escape(uid, quote=True)}">
            <button type="submit">گفتگو</button>
          </form>
        </div>
        """

    room_rows = ""
    for room in rooms:
        rid = str(room.get("id") or "")
        if not room.get("is_public", False) and rid not in joined_ids:
            continue
        title = str(room.get("title") or "بدون نام")
        room_type = str(room.get("type") or "")
        room_kind = "channels" if room_type == "channel" else "groups"
        is_joined = rid in joined_ids

        try:
            uuid.UUID(rid)
        except ValueError:
            continue

        if room_type == "channel":
            icon = "𓆃"
            label = "کانال"
            if is_joined:
                action = f'<a class="action" href="/chat/{rid}">باز کردن</a>'
            else:
                action = f'<a class="action" href="/channels/join/{rid}">پیوستن</a>'
        else:
            icon = "𓅃"
            label = "گروه"
            if is_joined:
                action = f'<a class="action" href="/chat/{rid}">باز کردن</a>'
            else:
                action = '<span class="muted">گروه</span>'

        room_rows += f"""
        <div class="chat-row search-result" data-kind="{room_kind}">
          <div class="avatar">{icon}</div>
          <div class="chat-info">
            <div class="chat-name">{html.escape(title)}</div>
            <div class="chat-preview">{label}</div>
          </div>
          {action}
        </div>
        """

    message_rows = ""
    if query and joined_ids:
        try:
            message_response = requests.get(
                URL + "/rest/v1/cyrus_messages",
                params={
                    "select": "id,conversation_id,content,created_at",
                    "conversation_id": "in.(" + ",".join(sorted(joined_ids)) + ")",
                    "content": "ilike.*" + query.replace("*", "") + "*",
                    "order": "created_at.desc",
                    "limit": "50"
                },
                headers=headers, timeout=25
            )
            if message_response.ok and isinstance(message_response.json(), list):
                hits = message_response.json()
                room_ids_for_hits = list(dict.fromkeys(str(x.get("conversation_id") or "") for x in hits if x.get("conversation_id")))
                room_names = {}
                if room_ids_for_hits:
                    names_response = requests.get(URL + "/rest/v1/cyrus_conversations",
                        params={"select":"id,title","id":"in.(" + ",".join(room_ids_for_hits) + ")"},
                        headers=headers, timeout=20)
                    if names_response.ok and isinstance(names_response.json(), list):
                        room_names = {str(x.get("id")): str(x.get("title") or "گفتگو") for x in names_response.json() if isinstance(x, dict)}
                for hit in hits:
                    mid, rid = str(hit.get("id") or ""), str(hit.get("conversation_id") or "")
                    try:
                        uuid.UUID(mid); uuid.UUID(rid)
                    except ValueError:
                        continue
                    text_value = str(hit.get("content") or "")
                    snippet = text_value if len(text_value) <= 170 else text_value[:167] + "…"
                    message_rows += f"""
                    <a class="chat-row search-result search-message-result" data-kind="messages" href="/chat/{html.escape(rid, quote=True)}?message={html.escape(mid, quote=True)}">
                      <div class="avatar">⌕</div><div class="chat-info">
                        <div class="chat-name">{html.escape(room_names.get(rid, "گفتگو"))}</div>
                        <div class="chat-preview">{html.escape(snippet)}</div>
                      </div><span style="color:#70b7e7">‹</span></a>"""
        except Exception:
            pass

    if message_rows:
        room_rows += '<div class="section-title">پیام‌ها</div>' + message_rows
    if query and not people_rows and not room_rows and not error:
        empty = '<div class="empty"><h3>نتیجه‌ای پیدا نشد</h3></div>'
    else:
        empty = ""

    content = f"""
    <div class="container">
      <style>
        .cyrus-explore-search{{display:flex;align-items:center;gap:8px;margin:10px 12px 14px;padding:2px 12px;border-radius:22px;background:#101d2c;border:1px solid #263b50;min-height:42px}}
        .cyrus-explore-search input{{flex:1;min-width:0;width:auto;margin:0;background:transparent;border:0;outline:0;box-shadow:none;padding:8px 4px;color:#fff;font-size:13px}}
        .cyrus-explore-search button{{width:auto;margin:0;padding:6px 9px;background:transparent;border:0;box-shadow:none;font-size:25px;color:#6fb9ef}}
      </style>
      <form class="cyrus-explore-search" method="get" action="/search">
        <a href="/home" aria-label="بازگشت" style="font-size:25px;color:#70b7e7;padding:0 5px">‹</a>
        <input name="q" value="{html.escape(query, quote=True)}"
               placeholder="جستجوی افراد، گروه‌ها و کانال‌ها"
               type="search" autocomplete="off" autofocus>
        <button type="button" aria-label="پاک کردن" onclick="this.form.q.value=this.form.q.value.slice(0,0);this.form.q.focus()" style="width:auto;margin:0;padding:6px 8px;background:transparent;color:#70b7e7">×</button>
        <button type="submit" aria-label="جستجو">⌕</button>
      </form>

      <p class="error">{html.escape(error)}</p>

      <div class="search-category-tabs">
        <a class="{ 'active' if selected_type == 'all' else '' }" href="/search?q={html.escape(query, quote=True)}&type=all">همه</a>
        <a class="{ 'active' if selected_type == 'messages' else '' }" href="/search?q={html.escape(query, quote=True)}&type=messages">پیام‌ها</a>
        <a class="{ 'active' if selected_type == 'people' else '' }" href="/search?q={html.escape(query, quote=True)}&type=people">افراد</a>
        <a class="{ 'active' if selected_type == 'groups' else '' }" href="/search?q={html.escape(query, quote=True)}&type=groups">گروه‌ها</a>
        <a class="{ 'active' if selected_type == 'channels' else '' }" href="/search?q={html.escape(query, quote=True)}&type=channels">کانال‌ها</a>
      </div>
      <style>
        .search-category-tabs{{display:flex;gap:0;overflow-x:auto;border-bottom:1px solid #20364b;margin:0 12px 8px}}
        .search-category-tabs a{{padding:12px 10px;white-space:nowrap;color:#91a6b8;font-size:12px;border-bottom:2px solid transparent}}
        .search-category-tabs a:focus,.search-category-tabs a:hover,.search-category-tabs a.active{{color:#69b9f7;border-color:#3297df}}
      </style>
      <div class="chat-list">{people_rows}</div>
      <div class="chat-list">{room_rows}</div>

      <section id="cyrus-search-recent" style="display:none;padding:12px 15px 18px">
        <div class="section-title">جستجوهای اخیر</div><div id="cyrus-search-recent-list"></div>
      </section>
      {empty}
      <script>
      (function(){{
        const q={query!r}, kind={selected_type!r};
        const key='cyrus_global_search_recent_v1';
        const input=document.querySelector('.cyrus-explore-search input');
        const recent=document.getElementById('cyrus-search-recent');
        const list=document.getElementById('cyrus-search-recent-list');
        document.querySelectorAll('.search-result').forEach(el=>{{
          if(kind!=='all'&&el.dataset.kind!==kind)el.style.display='none';
        }});
        function read(){{try{{return JSON.parse(localStorage.getItem(key)||'[]').slice(0,8)}}catch(e){{return []}}}}
        if(q){{localStorage.setItem(key,JSON.stringify([q,...read().filter(x=>x!==q)].slice(0,8)));}}
        if(!q){{
          const items=read();
          if(items.length){{recent.style.display='block';items.forEach(value=>{{
            const row=document.createElement('div');row.style.cssText='padding:10px 0;color:#b6c6d4;font-size:13px';
            const link=document.createElement('a');link.href='/search?q='+encodeURIComponent(value);link.textContent='⌕  '+value;
            row.appendChild(link);list.appendChild(row);
          }});}}
        }}
        if(input)input.addEventListener('keydown',e=>{{if(e.key==='Enter'&&input.value.trim())localStorage.setItem(key,JSON.stringify([input.value.trim(),...read().filter(x=>x!==input.value.trim())].slice(0,8)));}});
      }})();
      </script>
    </div>
    """
    return page(content)


@app.route("/contacts")
def contacts():
    if not session.get("access_token"):
        return redirect("/login")

    query = request.args.get("q", "").strip()
    users = []
    error = request.args.get("error", "")

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"]
    }

    try:
        response = requests.post(
            URL + "/rest/v1/rpc/cyrus_search_users",
            json={"p_query": query or None},
            headers={**headers, "Content-Type": "application/json"},
            timeout=20
        )
        if response.ok:
            users = response.json()
        else:
            error = "دریافت کاربران انجام نشد؛ تابع جستجوی کاربران را در پایگاه داده فعال کنید"
    except Exception:
        error = "ارتباط با سرور برقرار نشد"

    # Enrich the directory with current avatar and presence data in one batched request.
    directory_profiles = {}
    directory_ids = []
    for item in users if isinstance(users, list) else []:
        if isinstance(item, dict) and item.get("id"):
            try:
                directory_ids.append(str(uuid.UUID(str(item.get("id")))))
            except (ValueError, TypeError):
                pass
    directory_ids = list(dict.fromkeys(directory_ids))[:100]
    if directory_ids:
        try:
            profile_response = requests.get(
                URL + "/rest/v1/cyrus_profiles",
                params={
                    "select": "id,avatar_url,last_seen_at",
                    "id": "in.(" + ",".join(directory_ids) + ")"
                },
                headers=headers,
                timeout=15
            )
            if profile_response.ok:
                directory_profiles = {
                    str(row.get("id") or ""): row
                    for row in profile_response.json()
                    if isinstance(row, dict)
                }
        except Exception:
            directory_profiles = {}

    def directory_presence(profile):
        seen = str((profile or {}).get("last_seen_at") or "").strip()
        if not seen:
            return "آخرین بازدید نامشخص", False
        try:
            seen_dt = datetime.fromisoformat(seen.replace("Z", "+00:00"))
            if seen_dt.tzinfo is None:
                seen_dt = seen_dt.replace(tzinfo=timezone.utc)
            age = max(0, (datetime.now(timezone.utc) - seen_dt.astimezone(timezone.utc)).total_seconds())
            if age <= 300:
                return "آنلاین", True
            if age < 86400:
                return "آخرین بازدید امروز", False
            if age < 7 * 86400:
                return "آخرین بازدید این هفته", False
            return "مدتی پیش", False
        except (TypeError, ValueError, OverflowError):
            return "آخرین بازدید نامشخص", False

    rows = ""
    for user in users:
        name = str(user.get("display_name") or user.get("username") or "کاربر")
        username = str(user.get("username") or "")
        bio = str(user.get("bio") or "عضو CYRUS")
        user_id = str(user.get("id") or "")

        if query and query.casefold() not in (name + " " + username).casefold():
            continue

        try:
            uuid.UUID(user_id)
        except ValueError:
            continue

        safe_id = html.escape(user_id, quote=True)
        profile = directory_profiles.get(user_id, {})
        avatar_url = str(profile.get("avatar_url") or "")
        presence_text, is_online = directory_presence(profile)
        avatar_html = (
            '<img src="' + html.escape(avatar_url, quote=True) + '" alt="" loading="lazy" '
            'style="width:100%;height:100%;object-fit:cover;border-radius:50%">'
            if avatar_url else "𓅃"
        )
        presence_color = "#79d6a4" if is_online else "#91a6b9"
        chat_href = "/start-chat/" + safe_id

        rows += f"""
        <div class="chat-row">
          <div class="avatar" style="position:relative;overflow:hidden">{avatar_html}
            <span aria-label="{html.escape(presence_text, quote=True)}" title="{html.escape(presence_text, quote=True)}"
              style="position:absolute;right:0;bottom:0;width:11px;height:11px;border-radius:50%;background:{presence_color};border:2px solid #101c29"></span>
          </div>
          <div class="chat-info">
            <div class="chat-name">{html.escape(name)}</div>
            <div class="chat-preview">@{html.escape(username)} · {html.escape(bio)}</div>
            <small style="color:{presence_color}">{html.escape(presence_text)}</small>
          </div>
          <a class="action" style="margin:0;padding:10px 12px;text-align:center" href="{chat_href}" aria-label="ارسال پیام به {html.escape(name, quote=True)}">پیام</a>
          <a class="action" style="margin:0;padding:10px 12px;text-align:center" href="/user/{safe_id}">پروفایل</a>
        </div>"""

    if not rows and not error:
        rows = '<div class="empty"><div class="empty-icon">𓅃</div><h3>مخاطبی پیدا نشد</h3><p>کاربران ثبت‌نام‌شده CYRUS در این بخش نمایش داده می‌شوند</p></div>'

    content = f"""
    <div class="container">
      <section class="welcome">
        <h2>خویشان پارسی</h2>
        <p>کاربران و همراهان CYRUS</p>
      </section>
      <div style="display:flex;gap:10px;margin:12px 16px">
        <a class="action" style="flex:1;margin:0;text-align:center" href="/rooms/create?type=group">𓅃 ساخت گروه</a>
        <a class="action" style="flex:1;margin:0;text-align:center" href="/rooms/create?type=channel">𓆃 ساخت کانال</a>
        <a class="action" style="flex:1;margin:0;text-align:center" href="/channels">کانال‌های عمومی</a>
      </div>

      <form class="card" method="get">
        <input name="q" value="{html.escape(query, quote=True)}" placeholder="جستجوی نام یا شناسه">
        <button>جستجو در مخاطبان</button>
      </form>
      <div class="section-title">𓅃 · کاربران عضو CYRUS</div>
      <div class="chat-list">{rows}</div>
      <p class="error">{html.escape(error)}</p>
    </div>"""
    return page(content)


@app.route("/user/<user_id>")
def public_user_profile(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return "شناسه کاربر نامعتبر است", 400
    own_id = str(session.get("user_id") or "")
    if user_id == own_id:
        return redirect("/settings")
    headers = {"apikey": KEY, "Authorization": "Bearer " + session["access_token"]}
    try:
        r = requests.get(URL + "/rest/v1/cyrus_profiles",
            params={"select":"id,username,display_name,bio,avatar_url","id":"eq."+user_id,"limit":"1"},
            headers=headers, timeout=20)
        if not r.ok or not r.json():
            return page('<div class="container card"><h3>پروفایل پیدا نشد</h3><a href="/contacts">بازگشت</a></div>'), 404
        p = r.json()[0]
    except Exception:
        return page('<div class="container card"><h3>ارتباط با سرور برقرار نشد</h3></div>'), 502

    name = str(p.get("display_name") or p.get("username") or "کاربر")
    username = str(p.get("username") or "")
    bio = str(p.get("bio") or "")
    avatar = str(p.get("avatar_url") or "")
    safe_id = html.escape(user_id, quote=True)
    avatar_html = ('<img src="' + html.escape(avatar, quote=True) + '" alt="">') if avatar else '<div class="profile-user-symbol">𓅃</div>'

    blocked_by_me = False
    is_contact = False
    contact_name = ""
    saved_profile = False
    try:
        block_check = requests.get(URL + "/rest/v1/cyrus_user_blocks",
            params={"select":"blocker_id","blocker_id":"eq."+own_id,"blocked_id":"eq."+user_id,"limit":"1"},
            headers=headers, timeout=15)
        blocked_by_me = bool(block_check.ok and block_check.json())
        contact_check = requests.get(URL + "/rest/v1/cyrus_contacts",
            params={"select":"contact_name","owner_id":"eq."+own_id,"contact_user_id":"eq."+user_id,"limit":"1"},
            headers=headers, timeout=15)
        if contact_check.ok and contact_check.json():
            is_contact = True
            contact_name = str(contact_check.json()[0].get("contact_name") or "")
        saved_check = requests.get(URL + "/rest/v1/cyrus_saved_profiles",
            params={"select":"id","owner_id":"eq."+own_id,"saved_user_id":"eq."+user_id,"limit":"1"},
            headers=headers, timeout=15)
        saved_profile = bool(saved_check.ok and saved_check.json())
    except Exception:
        pass

    display_name = contact_name or name
    block_label = "رفع مسدودیت" if blocked_by_me else "مسدود کردن کاربر"
    contact_action = (
        '<button type="button" onclick="document.getElementById(&quot;cyrusEditContact&quot;).open=true">ویرایش مخاطب</button>'
        if is_contact else
        f'<form method="post" action="/user/{safe_id}/contact"><button type="submit">افزودن مخاطب</button></form>'
    )
    saved_label = "حذف پروفایل ذخیره‌شده" if saved_profile else "ذخیره پروفایل"
    blocked_notice = '<p class="profile-blocked-note">این کاربر را مسدود کرده‌اید؛ امکان ارسال پیام نیست.</p>' if blocked_by_me else ""
    back_chat_id = str(request.args.get("from_chat") or "").strip()
    try:
        uuid.UUID(back_chat_id)
    except ValueError:
        back_chat_id = ""
    back_href = "/chat/" + back_chat_id if back_chat_id else "/home"
    send_link = "" if blocked_by_me else f'<a class="profile-primary-action" href="/start-chat/{safe_id}" aria-label="ارسال پیام" title="ارسال پیام">➤</a>'

    content = f"""<main class="container cyrus-user-profile" data-profile-user="{safe_id}">
      <style>
        .cyrus-user-profile{{padding:0 0 88px;max-width:560px;background:#0d1722;min-height:calc(100dvh - 76px)}}
        .user-profile-card{{position:relative;background:#111e2b;border:0;border-radius:0;padding:15px 16px 20px;overflow:visible}}
        .user-profile-top{{display:flex;align-items:center;justify-content:space-between;min-height:58px;direction:rtl}}
        .user-profile-photo{{width:58px;height:58px;flex:0 0 58px;border-radius:50%;overflow:hidden;border:2px solid #2d8ecb;background:#172a3a;display:grid;place-items:center}}
        .user-profile-photo img{{width:100%;height:100%;object-fit:cover}}
        .profile-user-symbol{{font-size:28px;color:#d8b46a}}
        .profile-more{{position:absolute;left:12px;top:12px;z-index:15}}
        .profile-back{{position:absolute;left:52px;top:12px;z-index:15;width:36px;height:36px;border-radius:50%;display:grid;place-items:center;color:#dce7ef;font-size:23px;text-decoration:none;background:#172838}}
        .profile-more summary{{list-style:none;width:36px;height:36px;border-radius:50%;display:grid;place-items:center;color:#dce7ef;font-size:25px;cursor:pointer}}
        .profile-more summary::-webkit-details-marker{{display:none}}
        .profile-more-menu{{position:absolute;left:0;top:39px;width:205px;padding:5px;background:#223344;border:1px solid #3a5267;border-radius:12px;box-shadow:0 8px 28px #0008;z-index:20}}
        .profile-more-menu form{{margin:0}}
        .profile-more-menu button,.profile-more-menu a{{display:block;width:100%;margin:0;padding:12px 13px;border:0;border-radius:8px;background:transparent;color:#e8eff5;text-align:right;font-size:13px;text-decoration:none}}
        .profile-more-menu button:active,.profile-more-menu a:active{{background:#344b5e}}
        .profile-more-menu .danger{{color:#f1aeb4}}
        .user-profile-name{{margin:13px 0 3px;text-align:right;color:#f0f4f7;font-size:20px;font-weight:500}}
        .user-profile-username{{text-align:right;color:#78b8e6;font-size:13px;direction:ltr;unicode-bidi:plaintext}}
        .user-profile-bio{{text-align:right;color:#c3cfda;font-size:14px;line-height:1.9;margin:11px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}}
        .profile-primary-action{{display:grid;place-items:center;margin:14px auto 18px;width:54px;height:54px;border-radius:50%;background:#248bd0;color:#fff;text-decoration:none;font-size:23px}}
        .profile-media-tabs{{display:flex;background:#111e2b;border-bottom:1px solid #263b50;margin-top:12px}}
        .profile-media-tabs button{{flex:1;margin:0;padding:12px 3px;border:0;border-radius:0;background:transparent;color:#8fa5b8;font-size:11px}}
        .profile-media-tabs button.active{{color:#69b9f7;border-bottom:2px solid #3297df}}
        .profile-media-content{{display:grid;grid-template-columns:repeat(auto-fill,minmax(104px,1fr));gap:9px;align-items:start;padding:14px;background:#0d1722}}\n        .profile-media-content[hidden]{{display:none}}\n        .profile-history-card img{{width:100px;height:100px;object-fit:cover;border-radius:10px}}\n        .profile-history-video{{width:100%;max-width:320px;border-radius:12px}}\n        .profile-history-file{{display:block;width:100%;padding:12px;background:#111e2b;border-radius:10px;color:#80c1f0;text-decoration:none;overflow-wrap:anywhere}}\n        .profile-history-audio{{max-width:100%}}\n        .profile-history-empty{{width:100%;text-align:center;color:#8fa5b8;font-size:12px;padding:18px}}
        .profile-blocked-note{{margin:12px 0 0;color:#f1aeb4;font-size:12px;text-align:center}}
        .profile-contact-edit{{margin-top:12px;background:#111e2b;border:1px solid #263b50;border-radius:12px;overflow:hidden}}
        .profile-contact-edit summary{{padding:14px;text-align:center;color:#82bfe8;cursor:pointer;list-style:none}}
        .profile-contact-edit summary::-webkit-details-marker{{display:none}}
        .profile-contact-edit form{{padding:12px 14px;border-top:1px solid #263b50}}
        .profile-contact-edit input{{width:100%;box-sizing:border-box;padding:12px;background:#0a1521;color:#fff;border:1px solid #2a4054;border-radius:9px}}
        .profile-contact-edit button{{margin-top:10px;width:100%;padding:12px;background:#248bd0;color:white;border:0;border-radius:9px}}
      </style>
      <section class="user-profile-card">
        <a class="profile-back" href="{back_href}" aria-label="بازگشت به گفتگو" title="بازگشت">➜</a>
        <div class="user-profile-top">
          <div class="user-profile-photo">{avatar_html}</div>
          <details class="profile-more">
            <summary aria-label="گزینه‌های بیشتر">⋮</summary>
            <div class="profile-more-menu">
              {contact_action}
              <form method="post" action="/user/{safe_id}/save-profile"><button type="submit">{saved_label}</button></form>
              <form method="post" action="/user/{safe_id}/block" onsubmit="return confirm('وضعیت مسدودسازی این کاربر تغییر کند؟')"><button class="danger" type="submit">{block_label}</button></form>
            </div>
          </details>
        </div>
        <h2 class="user-profile-name">{html.escape(display_name)}</h2>
        <div class="user-profile-username" role="button" tabindex="0" title="برای کپی نام کاربری لمس کنید" data-username="{html.escape(username, quote=True)}" onclick="cyrusCopyUsername(this)">@{html.escape(username)}</div>
        <p class="user-profile-bio">{html.escape(bio) if bio else "بیوگرافی اضافه نشده است"}</p>
      </section>
      {send_link}
      {blocked_notice}<div class="profile-media-tabs"><button class="active" type="button" data-tab="media">رسانه</button><button type="button" data-tab="links">پیوندها</button><button type="button" data-tab="files">فایل‌ها</button><button type="button" data-tab="music">موسیقی</button></div><small class="profile-history-count" id="profileHistoryCount" aria-live="polite"></small><div class="profile-media-content" id="profile-media-content">برای نمایش محتوای گفتگو، یکی از بخش‌ها را انتخاب کنید.</div>
      {('<details class="profile-contact-edit" id="cyrusEditContact"><summary>ویرایش مخاطب</summary><form method="post" action="/user/'+safe_id+'/contact/edit"><label>نام مخاطب</label><input name="contact_name" maxlength="60" value="'+html.escape(contact_name,quote=True)+'" placeholder="'+html.escape(name,quote=True)+'"><button type="submit">ذخیره نام مخاطب</button></form></details>') if is_contact else ""}
    </main>
    <script>
    function cyrusCopyUsername(el){{const u="@"+(el.dataset.username||"");if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(u).then(()=>{{el.title="نام کاربری کپی شد";}}).catch(()=>prompt("نام کاربری",u));else prompt("نام کاربری",u);}}
    document.querySelector('.user-profile-username')?.addEventListener('keydown',function(e){{if(e.key==='Enter'||e.key===' '){{e.preventDefault();cyrusCopyUsername(this);}}}});
    document.addEventListener('click',function(e){{if(!e.target.closest('.profile-more'))document.querySelectorAll('.profile-more[open]').forEach(x=>x.open=false);}});
    (function(){{
      const root=document.querySelector('.cyrus-user-profile'),box=document.getElementById('profile-media-content'),buttons=[...document.querySelectorAll('.profile-media-tabs button')];
      if(!root||!box||!buttons.length)return;
      let loaded=false,items=[];const countLabel=document.getElementById("profileHistoryCount");
      function make(tag,cls){{const el=document.createElement(tag);if(cls)el.className=cls;return el;}}
      function linkCard(url,label){{const a=make('a','profile-history-file');a.href=url;a.target='_blank';a.rel='noopener';a.textContent=label;return a;}}
      function render(key){{
        box.replaceChildren();
        const selected=[];
        if(key==='media')selected.push(...items.filter(x=>x.url&&/^(photo|image|video)$/i.test(x.type)));
        if(key==='music')selected.push(...items.filter(x=>x.url&&/^(audio|music|voice)$/i.test(x.type)));
        if(key==='files')selected.push(...items.filter(x=>x.url&&!/^(photo|image|video|audio|music|voice)$/i.test(x.type)));
        if(key==='links')items.forEach(x=>{{(x.content.match(/https?:\/\/[^\s<>]+|www\.[^\s<>]+/gi)||[]).forEach(u=>selected.push({{type:'link',url:u,content:u}}));}});
        const seen=new Set();const unique=selected.filter(x=>{{const key=String(x.url||x.content||"");if(seen.has(key))return false;seen.add(key);return true;}});selected.splice(0,selected.length,...unique);if(countLabel)countLabel.textContent=selected.length+" مورد";
        selected.forEach(x=>{{
          let node;
          const url=String(x.url||'');
          const typ=String(x.type||'').toLowerCase();
          if(key==='links'){{let u=String(x.url||'');if(!/^https?:\/\//i.test(u))u='https://'+u;node=linkCard(u,x.content||u);}}
          else if(/^(photo|image)$/i.test(typ)){{node=make('a','profile-history-card');node.href=url;node.target='_blank';node.rel='noopener';const img=make('img');img.src=url;img.alt='تصویر گفتگو';img.loading='lazy';node.appendChild(img);}}
          else if(typ==='video'){{node=make('video','profile-history-video');node.src=url;node.controls=true;node.preload='metadata';node.playsInline=true;}}
          else if(/^(audio|music|voice)$/i.test(typ)){{node=make('audio','profile-history-audio');node.src=url;node.controls=true;node.preload='metadata';}}
          else node=linkCard(url,x.content||'فایل ارسال‌شده');
          box.appendChild(node);
        }});
        if(!selected.length){{const empty=make('p','profile-history-empty');empty.textContent='در این بخش موردی پیدا نشد';box.appendChild(empty);}}
      }}
      async function load(key){{
        if(!loaded){{box.textContent='در حال دریافت تاریخچه…';try{{const r=await fetch('/user/'+encodeURIComponent(root.dataset.profileUser)+'/shared-media',{{credentials:'same-origin'}});if(!r.ok)throw new Error('load');const d=await r.json();items=Array.isArray(d.items)?d.items:[];loaded=true;}}catch(e){{box.replaceChildren();const err=make('p','profile-history-empty');err.textContent='تاریخچهٔ رسانه در دسترس نیست';const retry=make('button');retry.type='button';retry.textContent='تلاش دوباره';retry.onclick=()=>{{loaded=false;load(key);}};box.append(err,retry);return;}}}}
        render(key);
      }}
      buttons.forEach(b=>{{b.setAttribute('aria-selected',b.classList.contains('active')?'true':'false');b.addEventListener('click',()=>{{buttons.forEach(x=>{{x.classList.toggle('active',x===b);x.setAttribute('aria-selected',x===b?'true':'false');}});load(b.dataset.tab||'media');}});}});
      load('media');
    }})();
    </script>"""
    return page(content)


@app.route("/user/<user_id>/shared-media")
def user_shared_media(user_id):
    if not session.get("access_token"):
        return Response('{"error":"unauthorized"}',status=401,mimetype="application/json")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return Response('{"error":"invalid user"}',status=400,mimetype="application/json")
    own_id=str(session.get("user_id") or "")
    if own_id==user_id:
        return Response('{"items":[]}',mimetype="application/json")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"]}
    try:
        own=requests.get(URL+"/rest/v1/cyrus_members",params={"select":"conversation_id","user_id":"eq."+own_id},headers=headers,timeout=15)
        target=requests.get(URL+"/rest/v1/cyrus_members",params={"select":"conversation_id","user_id":"eq."+user_id},headers=headers,timeout=15)
        own_ids={str(x.get("conversation_id") or "") for x in own.json()} if own.ok else set()
        target_ids={str(x.get("conversation_id") or "") for x in target.json()} if target.ok else set()
        shared=list(own_ids & target_ids)
        if not shared:
            return Response('{"items":[]}',mimetype="application/json")
        rooms=requests.get(URL+"/rest/v1/cyrus_conversations",params={"select":"id,type","id":"in.("+",".join(shared)+")","type":"eq.private"},headers=headers,timeout=15)
        if not rooms.ok or not rooms.json():
            return Response('{"items":[]}',mimetype="application/json")
        cid=str(rooms.json()[0].get("id") or "")
        messages=requests.get(URL+"/rest/v1/cyrus_messages",params={"select":"content,message_type,attachment_url,created_at","conversation_id":"eq."+cid,"order":"created_at.desc","limit":"100"},headers=headers,timeout=20)
        if not messages.ok:
            return Response('{"items":[]}',mimetype="application/json")
        items=[]
        for row in messages.json():
            items.append({"content":str(row.get("content") or "")[:4000],"type":str(row.get("message_type") or "text"),"url":str(row.get("attachment_url") or ""),"created_at":row.get("created_at")})
        return Response(__import__("json").dumps({"items":items},ensure_ascii=False),mimetype="application/json")
    except Exception:
        return Response('{"error":"server error"}',status=502,mimetype="application/json")


@app.route("/user/<user_id>/contact", methods=["POST"])
def add_user_contact(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    own_id = str(session.get("user_id") or "")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return "شناسه کاربر نامعتبر است", 400
    if user_id == own_id:
        return redirect("/settings")
    name = request.form.get("contact_name", "").strip()[:60] or None
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json","Prefer":"resolution=merge-duplicates,return=minimal"}
    try:
        result = requests.post(URL+"/rest/v1/cyrus_contacts",
            params={"on_conflict":"owner_id,contact_user_id"},
            json={"owner_id":own_id,"contact_user_id":user_id,"contact_name":name},
            headers=headers,timeout=20)
        if not result.ok:
            return page('<div class="container card"><p>افزودن مخاطب انجام نشد</p><a href="/user/'+user_id+'">بازگشت</a></div>'),400
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'),502
    return redirect("/user/"+user_id)


@app.route("/user/<user_id>/contact/edit", methods=["POST"])
def edit_user_contact(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    own_id = str(session.get("user_id") or "")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return "شناسه کاربر نامعتبر است",400
    contact_name = request.form.get("contact_name","").strip()[:60] or None
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json","Prefer":"return=minimal"}
    try:
        changed = requests.patch(URL+"/rest/v1/cyrus_contacts",
            params={"owner_id":"eq."+own_id,"contact_user_id":"eq."+user_id},
            json={"contact_name":contact_name},headers=headers,timeout=20)
        if not changed.ok:
            return page('<div class="container card"><p>ویرایش مخاطب انجام نشد</p><a href="/user/'+user_id+'">بازگشت</a></div>'),400
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'),502
    return redirect("/user/"+user_id)


@app.route("/user/<user_id>/save-profile", methods=["POST"])
def toggle_saved_profile(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    own_id = str(session.get("user_id") or "")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return "شناسه کاربر نامعتبر است",400
    if user_id == own_id:
        return redirect("/settings")
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json","Prefer":"return=minimal"}
    params = {"owner_id":"eq."+own_id,"saved_user_id":"eq."+user_id}
    try:
        existing = requests.get(URL+"/rest/v1/cyrus_saved_profiles",params={**params,"select":"id","limit":"1"},headers=headers,timeout=15)
        if not existing.ok:
            return page('<div class="container card"><p>بررسی پروفایل ذخیره‌شده ناموفق بود</p><a href="/user/'+user_id+'">بازگشت</a></div>'),400
        if existing.json():
            changed = requests.delete(URL+"/rest/v1/cyrus_saved_profiles",params=params,headers=headers,timeout=15)
        else:
            changed = requests.post(URL+"/rest/v1/cyrus_saved_profiles",json={"owner_id":own_id,"saved_user_id":user_id},headers=headers,timeout=15)
        if not changed.ok:
            return page('<div class="container card"><p>ذخیره پروفایل انجام نشد</p><a href="/user/'+user_id+'">بازگشت</a></div>'),400
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'),502
    return redirect("/user/"+user_id)


@app.route("/user/<user_id>/block", methods=["POST"])
def toggle_user_block(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    own_id = str(session.get("user_id") or "")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return "شناسه کاربر نامعتبر است", 400
    if user_id == own_id:
        return redirect("/profile")
    headers = {
        "apikey": KEY, "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json", "Prefer": "return=minimal"
    }
    params = {"blocker_id":"eq."+own_id, "blocked_id":"eq."+user_id}
    try:
        existing = requests.get(URL + "/rest/v1/cyrus_user_blocks",
            params={**params, "select":"blocker_id"}, headers=headers, timeout=20)
        if not existing.ok:
            return page('<div class="container card"><p>بررسی مسدودسازی ناموفق بود؛ دسترسی پایگاه داده را بررسی کنید.</p><a href="/user/'+user_id+'">بازگشت</a></div>'), 502
        if existing.json():
            changed = requests.delete(URL + "/rest/v1/cyrus_user_blocks",
                params=params, headers=headers, timeout=20)
        else:
            changed = requests.post(URL + "/rest/v1/cyrus_user_blocks",
                json={"blocker_id":own_id, "blocked_id":user_id},
                headers=headers, timeout=20)
        if not changed.ok:
            return page('<div class="container card"><p>تغییر وضعیت مسدودسازی انجام نشد.</p><a href="/user/'+user_id+'">بازگشت</a></div>'), 400
        from_chat = request.args.get("from_chat", "").strip()
        if from_chat:
            try:
                uuid.UUID(from_chat)
                return redirect(url_for("chat", conversation_id=from_chat))
            except ValueError:
                pass
        return redirect("/user/" + user_id)
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد.</p><a href="/user/'+user_id+'">بازگشت</a></div>'), 502


@app.route("/account/export")
def export_account_data():
    if not session.get("access_token"):
        return redirect("/login")
    own_id=str(session.get("user_id") or "")
    try:
        own_id=str(uuid.UUID(own_id))
    except ValueError:
        return "نشست حساب معتبر نیست",401
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Accept":"application/json"}
    def fetch_rows(table, params, label):
        collected=[]
        offset=0
        while True:
            query={**params,"limit":"1000","offset":str(offset)}
            response=requests.get(URL+"/rest/v1/"+table,params=query,headers={**headers,"Range":str(offset)+"-"+str(offset+999)},timeout=25)
            if not response.ok:
                raise RuntimeError(label+" unavailable")
            batch=response.json()
            if not isinstance(batch,list):
                raise RuntimeError(label+" invalid response")
            collected.extend(batch)
            if len(batch)<1000:
                break
            offset+=1000
            if offset>=10000:
                raise RuntimeError(label+" exceeds export safety limit")
        return collected
    try:
        profile=fetch_rows("cyrus_profiles",{"select":"*","id":"eq."+own_id},"profile")
        memberships=fetch_rows("cyrus_members",{"select":"*","user_id":"eq."+own_id},"memberships")
        room_ids=[]
        for row in memberships:
            try:
                room_ids.append(str(uuid.UUID(str(row.get("conversation_id") or ""))))
            except ValueError:
                continue
        room_ids=list(dict.fromkeys(room_ids))
        conversations=[]
        messages=[]
        reactions=[]
        for start in range(0,len(room_ids),35):
            batch=room_ids[start:start+35]
            expr="in.("+",".join(batch)+")"
            conversations.extend(fetch_rows("cyrus_conversations",{"select":"*","id":expr},"conversations"))
            messages.extend(fetch_rows("cyrus_messages",{"select":"*","conversation_id":expr,"order":"created_at.asc"},"messages"))
            # واکنش‌ها نیز بخشی از سابقهٔ گفتگو هستند و در نسخهٔ پشتیبان نگهداری می‌شوند.
            reactions.extend(fetch_rows("cyrus_message_reactions",{"select":"*","conversation_id":expr},"message reactions"))
        contacts=fetch_rows("cyrus_contacts",{"select":"*","owner_id":"eq."+own_id},"contacts")
        saved_messages=fetch_rows("cyrus_saved_messages",{"select":"*","user_id":"eq."+own_id},"saved messages")
        saved_profiles=fetch_rows("cyrus_saved_profiles",{"select":"*","owner_id":"eq."+own_id},"saved profiles")
        blocked_users=fetch_rows("cyrus_user_blocks",{"select":"*","blocker_id":"eq."+own_id},"blocked users")
        export_data={
            "profile":profile,"memberships":memberships,"conversations":conversations,
            "messages":messages,"message_reactions":reactions,"contacts":contacts,
            "saved_messages":saved_messages,"saved_profiles":saved_profiles,"blocked_users":blocked_users
        }
        json_module=__import__("json")
        canonical_data=json_module.dumps(export_data,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str)
        record_counts={key:len(value) if isinstance(value,list) else 1 for key,value in export_data.items()}
        payload={
            "product":"CYRUS","export_version":2,
            "exported_at":datetime.now(timezone.utc).isoformat(),
            "account":{"user_id":own_id,"email":str(session.get("cyrus_login_email") or "")},
            "data":export_data,
            "integrity":{
                "algorithm":"sha256",
                "data_sha256":hashlib.sha256(canonical_data.encode("utf-8")).hexdigest(),
                "record_counts":record_counts
            },
            "notes":["فقط اطلاعاتی صادر می‌شود که حساب فعلی طبق مجوزهای پایگاه داده اجازه خواندن آن را دارد.",
                     "برای بررسی سلامت داده‌ها، از SHA-256 بخش data با JSON مرتب‌شده و جداکننده‌های فشرده استفاده کنید.",
                     "فایل‌های پیوست به‌صورت نشانی ثبت شده‌اند و محتوای فایل‌ها داخل این خروجی قرار نگرفته است."]
        }
        body=json_module.dumps(payload,ensure_ascii=False,indent=2,default=str)
        filename="cyrus-account-export-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+".json"
        return Response(body,mimetype="application/json",headers={
            "Content-Disposition":'attachment; filename="'+filename+'"',
            "Cache-Control":"no-store, no-cache, must-revalidate"
        })
    except Exception:
        return page('<main class="container card"><h3>خروجی اطلاعات آماده نشد</h3><p>ارتباط با سرور یا دسترسی به بخشی از اطلاعات کامل نبود. برای جلوگیری از تحویل فایل ناقص، خروجی صادر نشد.</p><a href="/settings">بازگشت به تنظیمات</a></main>'),502


@app.route("/blocked-users")
def blocked_users():
    if not session.get("access_token"):
        return redirect("/login")
    own_id=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"]}
    rows_html=""
    error=""
    try:
        blocked=requests.get(URL+"/rest/v1/cyrus_user_blocks",
            params={"select":"blocked_id","blocker_id":"eq."+own_id,"limit":"500"},
            headers=headers,timeout=20)
        if not blocked.ok:
            raise RuntimeError("blocked list unavailable")
        rows=blocked.json()
        ids=list(dict.fromkeys(str(row.get("blocked_id") or "") for row in rows if row.get("blocked_id")))
        profiles={}
        if ids:
            result=requests.get(URL+"/rest/v1/cyrus_profiles",
                params={"select":"id,username,display_name,avatar_url","id":"in.("+",".join(ids)+")"},
                headers=headers,timeout=20)
            if not result.ok:
                raise RuntimeError("blocked profiles unavailable")
            profiles={str(item.get("id") or ""):item for item in result.json() if isinstance(item,dict)}
        for row in rows:
            uid=str(row.get("blocked_id") or "")
            try:
                safe_id=str(uuid.UUID(uid))
            except ValueError:
                continue
            profile=profiles.get(safe_id,{})
            name=html.escape(str(profile.get("display_name") or profile.get("username") or "کاربر"))
            username=html.escape(str(profile.get("username") or ""))
            avatar=str(profile.get("avatar_url") or "")
            avatar_html=('<img src="'+html.escape(avatar,quote=True)+'" alt="">' if avatar else '<span>♙</span>')
            rows_html+=(
                '<article class="blocked-user-row"><a class="blocked-user-identity" href="/user/'+safe_id+'">'
                '<span class="blocked-user-avatar">'+avatar_html+'</span><span><b>'+name+'</b>'
                +('<small>@'+username+'</small>' if username else '')+'</span></a>'
                '<form method="post" action="/blocked-users/'+safe_id+'/remove" onsubmit="return confirm(\'این کاربر از فهرست مسدودها خارج شود؟\')">'
                '<button type="submit">رفع مسدودیت</button></form></article>'
            )
    except Exception:
        error="فهرست کاربران مسدودشده دریافت نشد؛ اتصال یا دسترسی پایگاه داده را بررسی کنید."
    if not rows_html and not error:
        rows_html='<div class="blocked-empty"><span>𓊹</span><h3>فهرست مسدودی خالی است</h3><p>کاربرانی که مسدود می‌کنید اینجا نمایش داده می‌شوند.</p></div>'
    content=f"""
    <main class="container blocked-users-page">
      <style>
        .blocked-users-page{{max-width:560px;margin:12px auto;padding:14px 12px 90px;color:#edf3f8}}
        .blocked-users-head{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}
        .blocked-users-head a{{width:38px;height:38px;display:grid;place-items:center;border-radius:50%;background:#172b3d;color:#e8eef5;text-decoration:none;font-size:22px}}
        .blocked-users-head h2{{font-size:18px;font-weight:500;margin:0;color:#e5bd69}}
        .blocked-user-row{{display:flex;align-items:center;justify-content:space-between;gap:9px;padding:11px;margin:7px 0;background:#101f2e;border:1px solid #293f53;border-radius:14px}}
        .blocked-user-identity{{display:flex;align-items:center;gap:10px;min-width:0;color:#edf3f8;text-decoration:none}}
        .blocked-user-identity b,.blocked-user-identity small{{display:block;overflow-wrap:anywhere}}
        .blocked-user-identity small{{direction:ltr;text-align:right;color:#8fb7d5;font-size:11px;margin-top:3px}}
        .blocked-user-avatar{{width:42px;height:42px;flex:0 0 42px;border-radius:50%;overflow:hidden;background:#1b3043;color:#d8b45f;display:grid;place-items:center;font-size:21px}}
        .blocked-user-avatar img{{width:100%;height:100%;object-fit:cover}}
        .blocked-user-row form{{margin:0;flex:0 0 auto}}
        .blocked-user-row button{{margin:0;padding:9px 11px;border-radius:10px;background:#24394b;border:1px solid #49647b;color:#e9d49c;font:inherit;font-size:11px}}
        .blocked-empty{{text-align:center;padding:55px 18px;color:#9eb1c1;background:#101f2e;border:1px solid #293f53;border-radius:16px}}
        .blocked-empty span{{font-size:42px;color:#d8b45f}}.blocked-empty h3{{color:#e5bd69;font-size:16px;font-weight:500}}
        .blocked-users-error{{padding:14px;color:#ffaaa0;text-align:center}}
      </style>
      <header class="blocked-users-head"><a href="/settings" aria-label="بازگشت">‹</a><h2>کاربران مسدودشده</h2></header>
      {('<p class="blocked-users-error">'+html.escape(error)+'</p>') if error else rows_html}
    </main>"""
    return page(content)


@app.route("/blocked-users/<user_id>/remove", methods=["POST"])
def remove_blocked_user(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        user_id=str(uuid.UUID(user_id))
    except ValueError:
        return "شناسه کاربر نامعتبر است",400
    own_id=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Prefer":"return=minimal"}
    try:
        result=requests.delete(URL+"/rest/v1/cyrus_user_blocks",
            params={"blocker_id":"eq."+own_id,"blocked_id":"eq."+user_id},
            headers=headers,timeout=20)
        if not result.ok:
            return page('<main class="container card"><p>رفع مسدودیت انجام نشد.</p><a href="/blocked-users">بازگشت</a></main>'),400
        return redirect("/blocked-users?updated=1")
    except Exception:
        return page('<main class="container card"><p>ارتباط با سرور برقرار نشد.</p><a href="/blocked-users">بازگشت</a></main>'),502


@app.route("/message-to/<user_id>", methods=["POST"])
def message_to_user(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return "شناسه کاربر نامعتبر است", 400
    content = request.form.get("content", "").strip()
    if not content or len(content) > 4000:
        return redirect("/user/" + user_id)
    own_id = str(session.get("user_id") or "")
    headers = {"apikey": KEY, "Authorization": "Bearer " + session["access_token"], "Content-Type": "application/json", "Prefer": "return=minimal"}
    block_status = cyrus_block_status(user_id, headers)
    if block_status is None:
        return page('<div class="container card"><p>بررسی مسدودسازی با سرور انجام نشد؛ پیام ارسال نشد.</p><a href="/user/'+user_id+'">بازگشت</a></div>'), 503
    if block_status:
        return redirect("/user/" + user_id)
    try:
        created = requests.post(URL + "/rest/v1/rpc/create_direct_conversation", json={"other_user":user_id}, headers=headers, timeout=20)
        if not created.ok or not isinstance(created.json(), str):
            return page('<div class="container card"><p>ساخت گفتگو انجام نشد</p><a href="/contacts">بازگشت</a></div>'), 400
        room_id = str(uuid.UUID(created.json()))
        sent = requests.post(URL + "/rest/v1/cyrus_messages", json={"conversation_id":room_id,"sender_id":own_id,"content":content,"message_type":"text"}, headers=headers, timeout=20)
        if not sent.ok:
            return page('<div class="container card"><p>ارسال پیام ناموفق بود</p><a href="/user/'+user_id+'">بازگشت</a></div>'), 400
        return redirect(url_for("chat", conversation_id=room_id))
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'), 502


@app.route("/start-chat/<user_id>", methods=["GET", "POST"])
def start_chat(user_id):
    if not session.get("access_token"):
        return redirect("/login")
    own_id = str(session.get("user_id") or "")
    try:
        uuid.UUID(user_id)
    except ValueError:
        return redirect("/contacts?error=شناسه%20کاربر%20نامعتبر%20است")
    if user_id == own_id:
        return redirect("/settings")
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json"}
    try:
        blocked = requests.get(URL+"/rest/v1/cyrus_user_blocks",
            params={"select":"blocker_id","blocker_id":"eq."+own_id,"blocked_id":"eq."+user_id,"limit":"1"},
            headers=headers,timeout=15)
        reverse_blocked = requests.get(URL+"/rest/v1/cyrus_user_blocks",
            params={"select":"blocker_id","blocker_id":"eq."+user_id,"blocked_id":"eq."+own_id,"limit":"1"},
            headers=headers,timeout=15)
        if (blocked.ok and blocked.json()) or (reverse_blocked.ok and reverse_blocked.json()):
            return redirect("/user/"+user_id)
        created = requests.post(URL+"/rest/v1/rpc/create_direct_conversation",
            json={"other_user":user_id},headers=headers,timeout=20)
        if not created.ok:
            return page('<div class="container card"><p>ساخت گفتگو انجام نشد</p><a href="/user/'+user_id+'">بازگشت</a></div>'),400
        value = created.json()
        room_id = str(value.get("id") if isinstance(value,dict) else value)
        room_id = str(uuid.UUID(room_id))
        return redirect("/chat/"+room_id)
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p><a href="/user/'+user_id+'">بازگشت</a></div>'),502


@app.route("/conversation/<conversation_id>/profile")
def conversation_profile(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"]}
    try:
        r=requests.get(URL+"/rest/v1/cyrus_conversations",params={"select":"id,title,type,created_by,description,avatar_url,invite_code,is_public","id":"eq."+conversation_id,"limit":"1"},headers=headers,timeout=20)
        if not r.ok or not r.json():
            return page('<main class="container"><div class="empty">پروفایل مجموعه پیدا نشد</div></main>'),404
        room=r.json()[0]
        mr=requests.get(URL+"/rest/v1/cyrus_members",params={"select":"user_id,role","conversation_id":"eq."+conversation_id},headers=headers,timeout=20)
        members=mr.json() if mr.ok else []
        profiles={}
        ids=list(dict.fromkeys(str(m.get("user_id") or "") for m in members if m.get("user_id")))
        if ids:
            pr=requests.get(URL+"/rest/v1/cyrus_profiles",params={"select":"id,username,display_name,bio,avatar_url","id":"in.("+",".join(ids)+")"},headers=headers,timeout=20)
            if pr.ok: profiles={str(p.get("id")):p for p in pr.json() if isinstance(p,dict)}
    except Exception:
        return page('<main class="container"><div class="empty">ارتباط با سرور برقرار نشد</div></main>'),502
    kind={"group":"گروه","channel":"کانال"}.get(str(room.get("type") or ""),"گفتگوی خصوصی")
    title=html.escape(str(room.get("title") or "گفتگو"))
    desc=html.escape(str(room.get("description") or ""))
    avatar=str(room.get("avatar_url") or "")
    avatar_html=('<img src="'+html.escape(avatar,quote=True)+'" alt="">') if avatar else '<div class="rp-avatar-fallback">𓊹</div>'
    me=str(session.get("user_id") or "")
    owner=str(room.get("created_by") or "")==me
    myrole=next((str(m.get("role") or "") for m in members if str(m.get("user_id") or "")==me),"")
    manager=owner or myrole in ("owner","admin")
    gear='<a class="rp-gear" href="/rooms/'+html.escape(conversation_id,quote=True)+'/manage" aria-label="مدیریت کانال">⚙</a>' if manager else '<span class="rp-gear-space"></span>'
    code=str(room.get("invite_code") or "")
    invite=request.host_url.rstrip("/")+"/invite/"+code if code else ""
    invite_html=('<a class="rp-link" href="'+html.escape(invite,quote=True)+'">'+html.escape(invite)+'</a>' if invite else '<span class="rp-link">لینک در دسترس نیست</span>')
    rows=""
    for m in members:
        mid=str(m.get("user_id") or "")
        p=profiles.get(mid,{})
        nm=html.escape(str(p.get("display_name") or p.get("username") or "کاربر"))
        un=html.escape(str(p.get("username") or ""))
        role=str(m.get("role") or "member")
        roletext={"owner":"مالک","admin":"مدیر","member":"عضو"}.get(role,role)
        photo=str(p.get("avatar_url") or "")
        pic='<img src="'+html.escape(photo,quote=True)+'" alt="">' if photo else '<span class="rp-member-avatar">♙</span>'
        safe=html.escape(mid,quote=True)
        controls=""
        if manager and mid!=str(room.get("created_by") or ""):
            if owner and role=="member":
                controls+='<form method="post" action="/rooms/'+conversation_id+'/manage"><input type="hidden" name="action" value="promote"><input type="hidden" name="user_id" value="'+safe+'"><button>تعیین مدیر</button></form>'
            if owner and role=="admin":
                controls+='<form method="post" action="/rooms/'+conversation_id+'/manage"><input type="hidden" name="action" value="demote"><input type="hidden" name="user_id" value="'+safe+'"><button>عزل مدیر</button></form>'
            if owner or (myrole=="admin" and role=="member"):
                controls+='<form method="post" action="/rooms/'+conversation_id+'/manage" onsubmit="return confirm(\'عضو حذف شود؟\')"><input type="hidden" name="action" value="remove"><input type="hidden" name="user_id" value="'+safe+'"><button class="rp-danger">حذف از کانال</button></form>'
        rows+='<details class="rp-member"><summary>'+pic+'<span class="rp-member-name"><b>'+nm+'</b><small>'+('@'+un if un else '')+'</small></span><span class="rp-role">'+html.escape(roletext)+'</span></summary><div class="rp-actions"><a href="/user/'+safe+'?from_chat=1">مشاهده پروفایل</a>'+controls+'</div></details>'
    if not rows: rows='<p class="rp-empty">هنوز عضوی وجود ندارد</p>'
    content="""<main class="container cyrus-room-profile">
<style>
.cyrus-room-profile{padding:0 0 28px;background:#0d1722;min-height:calc(100dvh - 76px);color:#eaf1f6}
.rp-top{height:58px;display:flex;align-items:center;gap:12px;padding:0 14px;background:#172331;border-bottom:1px solid #263442}
.rp-back,.rp-gear{width:38px;height:38px;display:grid;place-items:center;border-radius:50%;color:#eaf2f8;background:#203243;font-size:24px}
.rp-title{flex:1;text-align:right;font-size:16px;font-weight:600}.rp-gear{color:#e5bd69;font-size:21px}.rp-gear-space{width:38px}
.rp-hero{padding:20px 16px 18px;background:#111e2b;border-bottom:1px solid #263442}
.rp-head{display:flex;align-items:center;gap:14px}.rp-head img,.rp-avatar-fallback{width:76px;height:76px;flex:0 0 76px;border-radius:50%;object-fit:cover;border:2px solid #2d8ecb;display:grid;place-items:center;font-size:32px;color:#d8b46a}
.rp-main{flex:1;min-width:0;text-align:right}.rp-main h2{margin:0;text-align:right;color:#eef4f8;font-size:20px;overflow-wrap:anywhere}.rp-kind{font-size:12px;color:#8ca8be;margin-top:6px}
.rp-link-label{font-size:12px;color:#8ca8be;margin:18px 0 5px}.rp-link{display:block;direction:ltr;text-align:left;overflow-wrap:anywhere;font-size:12px;color:#69b9f7;padding:10px 12px;background:#0a1521;border-radius:10px;border:1px solid #263b50}
.rp-bio{color:#c3cfda;font-size:14px;line-height:1.9;margin:15px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}
.rp-members-title{display:flex;justify-content:space-between;padding:16px 15px 10px;font-size:14px}.rp-search{display:block;width:calc(100% - 28px);margin:0 14px 10px;padding:12px 14px;background:#091521;border:1px solid #263b50;border-radius:12px;color:#fff;font:inherit}
.rp-member{background:#111e2b;border-bottom:1px solid #263442}.rp-member summary{display:flex;align-items:center;gap:11px;padding:12px 14px;list-style:none;cursor:pointer}.rp-member summary::-webkit-details-marker{display:none}
.rp-member img,.rp-member-avatar{width:44px;height:44px;flex:0 0 44px;border-radius:50%;object-fit:cover;background:#203243;display:grid;place-items:center;color:#d8b46a;font-size:22px}
.rp-member-name{display:flex;flex:1;min-width:0;flex-direction:column;gap:4px}.rp-member-name b{font-size:14px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rp-member-name small{font-size:11px;color:#8ea5b9;direction:ltr;text-align:right}.rp-role{font-size:11px;color:#7eb8e2;white-space:nowrap}
.rp-actions{padding:8px 14px 13px 69px;display:flex;flex-wrap:wrap;gap:7px}.rp-actions a,.rp-actions button{display:inline-block;width:auto;margin:0;padding:8px 11px;border:1px solid #2d455b;border-radius:9px;background:#20384d;color:#8dc9f5;text-decoration:none;font-size:12px}.rp-actions form{margin:0}.rp-actions .rp-danger{color:#f1aeb4}.rp-empty{padding:20px;text-align:center;color:#8fa5b8;font-size:13px}
</style>
<header class="rp-top"><a class="rp-back" href="/chat/__ID__" aria-label="بازگشت">‹</a><span class="rp-title">اطلاعات __KIND__</span>__GEAR__</header>
<section class="rp-hero"><div class="rp-head">__AVATAR__<div class="rp-main"><h2>__TITLE__</h2><div class="rp-kind">__KIND__ · __COUNT__ عضو</div></div></div><div class="rp-link-label">لینک کانال / دعوت</div>__LINK__<p class="rp-bio">__DESC__</p></section>
<div class="rp-members-title"><span>اعضا</span><span>__COUNT__</span></div><input class="rp-search" id="rp-search" placeholder="جستجوی اعضا"><section id="rp-list">__ROWS__</section></main>
<script>(function(){const i=document.getElementById("rp-search"),r=[...document.querySelectorAll(".rp-member")];i.addEventListener("input",()=>{const q=i.value.trim().toLocaleLowerCase();r.forEach(x=>x.style.display=x.textContent.toLocaleLowerCase().includes(q)?"":"none");});})();</script>"""
    for k,v in {"__ID__":html.escape(conversation_id,quote=True),"__KIND__":kind,"__GEAR__":gear,"__AVATAR__":avatar_html,"__TITLE__":title,"__COUNT__":str(len(members)),"__LINK__":invite_html,"__DESC__":desc or "توضیحی اضافه نشده است","__ROWS__":rows}.items():
        content=content.replace(k,v)
    return page(content)

def cyrus_format_message_text(value):
    text_value = str(value or "")
    pattern = re.compile(r"(?<![\w@])(?:https?://[^\s<>]+|www\.[^\s<>]+|@[A-Za-z0-9_]{3,24})", re.IGNORECASE)
    pieces = []
    cursor = 0
    for match in pattern.finditer(text_value):
        token = match.group(0)
        start, end = match.span()
        if token.startswith("@"):
            href = "/search?q=" + quote(token[1:])
            target = ""
        else:
            while token and token[-1] in ".,!?;:)]}،؛؟":
                token = token[:-1]
                end -= 1
            if not token:
                continue
            href = token if token.lower().startswith(("http://", "https://")) else "https://" + token
            target = ' target="_blank" rel="noopener noreferrer"'
        pieces.append(html.escape(text_value[cursor:start]).replace("\n", "<br>"))
        pieces.append('<a class="chat-inline-link" href="' + html.escape(href, quote=True) + '"' + target + ' onclick="event.stopPropagation()">' + html.escape(token) + '</a>')
        cursor = end
    pieces.append(html.escape(text_value[cursor:]).replace("\n", "<br>"))
    return "".join(pieces)


@app.route("/chat/<conversation_id>/search")
def search_chat_messages(conversation_id):
    if not session.get("access_token"):
        return app.response_class('{"error":"unauthorized"}', status=401, mimetype="application/json")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return app.response_class('{"error":"invalid_conversation"}', status=400, mimetype="application/json")

    query = str(request.args.get("q") or "").strip()
    query = re.sub(r"[^\w\s@.-]", " ", query, flags=re.UNICODE)
    query = " ".join(query.split())[:80]
    if len(query) < 2:
        return app.response_class('{"results":[]}', mimetype="application/json")

    headers = {"apikey": KEY, "Authorization": "Bearer " + session["access_token"]}
    user_id = str(session.get("user_id") or "")
    try:
        room_response = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={"select":"id,created_by,history_visible","id":"eq."+conversation_id,"limit":"1"},
            headers=headers, timeout=15
        )
        if not room_response.ok or not room_response.json():
            return app.response_class('{"error":"not_found"}', status=404, mimetype="application/json")
        room = room_response.json()[0]
        member_response = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={"select":"joined_at","conversation_id":"eq."+conversation_id,"user_id":"eq."+user_id,"limit":"1"},
            headers=headers, timeout=15
        )
        is_owner = str(room.get("created_by") or "") == user_id
        if not member_response.ok or (not member_response.json() and not is_owner):
            return app.response_class('{"error":"forbidden"}', status=403, mimetype="application/json")
        joined_at = member_response.json()[0].get("joined_at") if member_response.ok and member_response.json() else None
        params = {
            "select":"id,content,created_at,sender_id,message_type",
            "conversation_id":"eq."+conversation_id,
            "content":"ilike.*"+query+"*",
            "order":"created_at.desc",
            "limit":"50"
        }
        if not room.get("history_visible", True) and joined_at:
            params["created_at"] = "gte."+str(joined_at)
        result = requests.get(URL + "/rest/v1/cyrus_messages", params=params, headers=headers, timeout=20)
        if not result.ok:
            return app.response_class('{"error":"search_failed"}', status=502, mimetype="application/json")
        rows = []
        for item in result.json():
            rows.append({
                "id": str(item.get("id") or ""),
                "content": str(item.get("content") or "")[:240],
                "created_at": item.get("created_at"),
                "sender_id": str(item.get("sender_id") or ""),
                "message_type": str(item.get("message_type") or "text")
            })
        payload = __import__("json").dumps({"results":rows}, ensure_ascii=False)
        return app.response_class(payload, mimetype="application/json")
    except Exception:
        return app.response_class('{"error":"server_error"}', status=502, mimetype="application/json")


@app.route("/chat/<conversation_id>")
def chat(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")

    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"]
    }

    try:
        room = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={
                "select": "id,title,type,created_by,description,avatar_url,history_visible,invite_code",
                "id": "eq." + conversation_id
            },
            headers=headers,
            timeout=20
        )

        if not room.ok or not room.json():
            return page('<div class="container card"><h3>گفتگو پیدا نشد یا دسترسی ندارید</h3><a href="/contacts">بازگشت به خویشان</a></div>'), 404

        room_data_for_history = room.json()[0]
        current_user_for_history = str(session.get("user_id") or "")
        member_for_history = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={"select": "joined_at,role", "conversation_id": "eq." + conversation_id,
                    "user_id": "eq." + current_user_for_history, "limit": "1"},
            headers=headers, timeout=15
        )
        is_room_owner = str(room_data_for_history.get("created_by") or "") == current_user_for_history
        if not member_for_history.ok or (not member_for_history.json() and not is_room_owner):
            return page('<div class="container card"><h3>شما عضو این گفتگو نیستید</h3><a href="/contacts">بازگشت</a></div>'), 403
        member_history_row = member_for_history.json()[0] if member_for_history.ok and member_for_history.json() else {}
        joined_at_for_history = member_history_row.get("joined_at")
        # ورود به گفتگو یعنی پیام‌های قبلی تا این لحظه خوانده شده‌اند.
        if member_history_row:
            requests.patch(
                URL + "/rest/v1/cyrus_members",
            params={
                "conversation_id": "eq." + conversation_id,
                "user_id": "eq." + str(session.get("user_id"))
            },
            json={"last_read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            headers={**headers, "Content-Type": "application/json", "Prefer": "return=minimal"},
            timeout=20
            )
        message_before = str(request.args.get("before") or "").strip()
        message_before_valid = False
        if message_before:
            try:
                before_dt = datetime.fromisoformat(message_before.replace("Z","+00:00"))
                if before_dt.tzinfo is None:
                    before_dt = before_dt.replace(tzinfo=timezone.utc)
                message_before = before_dt.astimezone(timezone.utc).isoformat()
                message_before_valid = True
            except ValueError:
                message_before = ""
        message_params = {
            "select": "id,sender_id,content,message_type,attachment_url,created_at,edited_at,metadata",
            "conversation_id": "eq." + conversation_id,
            "order": "created_at.desc",
            "limit": "201"
        }
        if message_before_valid:
            message_params["created_at"] = "lt." + message_before
        response = requests.get(
            URL + "/rest/v1/cyrus_messages",
            params=message_params,
            headers=headers,
            timeout=20
        )

        if not response.ok:
            return page('<div class="container card"><p>دریافت پیام‌ها ناموفق بود</p></div>'), 502

        fetched_messages = response.json()
        has_older_messages = len(fetched_messages) > 200
        messages = list(reversed(fetched_messages[:200]))
        # Deep links can target messages older than the normal 200-message window.
        # Fetch only the requested message through the same authenticated/RLS client.
        requested_message_id = request.args.get("message", "").strip()
        if requested_message_id:
            try:
                uuid.UUID(requested_message_id)
                if not any(str(item.get("id") or "") == requested_message_id for item in messages):
                    target_response = requests.get(
                        URL + "/rest/v1/cyrus_messages",
                        params={
                            "select": "id,sender_id,content,message_type,attachment_url,created_at,edited_at,metadata",
                            "id": "eq." + requested_message_id,
                            "conversation_id": "eq." + conversation_id,
                            "limit": "1"
                        },
                        headers=headers,
                        timeout=15
                    )
                    if target_response.ok and target_response.json():
                        messages.append(target_response.json()[0])
                        messages.sort(key=lambda item: str(item.get("created_at") or ""))
            except ValueError:
                pass
        if not room_data_for_history.get("history_visible", True) and joined_at_for_history:
            try:
                joined_dt_for_history = datetime.fromisoformat(str(joined_at_for_history).replace("Z", "+00:00"))
                if joined_dt_for_history.tzinfo is None:
                    joined_dt_for_history = joined_dt_for_history.replace(tzinfo=timezone.utc)
                filtered_messages = []
                for item in messages:
                    item_dt = datetime.fromisoformat(str(item.get("created_at") or "").replace("Z", "+00:00"))
                    if item_dt.tzinfo is None:
                        item_dt = item_dt.replace(tzinfo=timezone.utc)
                    if item_dt.astimezone(timezone.utc) >= joined_dt_for_history.astimezone(timezone.utc):
                        filtered_messages.append(item)
                messages = filtered_messages
            except (TypeError, ValueError):
                messages = []
        reaction_map = {}
        try:
            reaction_message_ids = [str(item.get("id") or "") for item in messages if item.get("id")]
            if reaction_message_ids:
                reaction_response = requests.get(URL + "/rest/v1/cyrus_message_reactions",
                    params={"select":"message_id,user_id,emoji","conversation_id":"eq."+conversation_id,
                            "message_id":"in.("+",".join(reaction_message_ids)+")"},
                    headers=headers,timeout=15)
                if reaction_response.ok:
                    for reaction_row in reaction_response.json():
                        reaction_map.setdefault(str(reaction_row.get("message_id") or ""),[]).append(reaction_row)
        except Exception:
            reaction_map = {}
        requested_message_id = request.args.get("message", "").strip()
        if requested_message_id:
            try:
                uuid.UUID(requested_message_id)
                target_response = requests.get(
                    URL + "/rest/v1/cyrus_messages",
                    params={
                        "select": "id,sender_id,content,message_type,created_at,edited_at,metadata",
                        "id": "eq." + requested_message_id,
                        "conversation_id": "eq." + conversation_id,
                        "limit": "1"
                    },
                    headers=headers,
                    timeout=15
                )
                if target_response.ok and isinstance(target_response.json(), list) and target_response.json():
                    target_message = target_response.json()[0]
                    if not room_data_for_history.get("history_visible", True) and joined_at_for_history:
                        target_dt = datetime.fromisoformat(str(target_message.get("created_at") or "").replace("Z", "+00:00"))
                        joined_dt = datetime.fromisoformat(str(joined_at_for_history).replace("Z", "+00:00"))
                        if target_dt.tzinfo is None:
                            target_dt = target_dt.replace(tzinfo=timezone.utc)
                        if joined_dt.tzinfo is None:
                            joined_dt = joined_dt.replace(tzinfo=timezone.utc)
                        if target_dt.astimezone(timezone.utc) < joined_dt.astimezone(timezone.utc):
                            target_message = None
                    if target_message and not any(str(m.get("id") or "") == requested_message_id for m in messages):
                        messages.append(target_message)
                        messages.sort(key=lambda item: str(item.get("created_at") or ""))
            except ValueError:
                requested_message_id = ""
        pinned_message = next((m for m in messages if isinstance(m.get("metadata"), dict) and m["metadata"].get("pinned")), None)
        pinned_banner = (
            '<div class="card" style="border-color:#d8b46a;margin-bottom:10px">📌 پیام سنجاق‌شده: '
            + html.escape(str(pinned_message.get("content") or "")[:180]) + '</div>'
            if pinned_message else ""
        )
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'), 502

    current_user = str(session.get("user_id", "") or "")
    forward_options = '<option value="">مقصد انتقال را انتخاب کنید</option>'
    try:
        fm = requests.get(URL + "/rest/v1/cyrus_members",
            params={"select":"conversation_id","user_id":"eq."+current_user},
            headers=headers,timeout=15)
        fids = list(dict.fromkeys(str(x.get("conversation_id") or "") for x in fm.json()
            if x.get("conversation_id") and str(x.get("conversation_id")) != conversation_id)) if fm.ok else []
        if fids:
            fr = requests.get(URL + "/rest/v1/cyrus_conversations",
                params={"select":"id,title,type","id":"in.("+",".join(fids)+")"},
                headers=headers,timeout=15)
            if fr.ok:
                for dest in fr.json():
                    did=html.escape(str(dest.get("id") or ""),quote=True)
                    dtitle=html.escape(str(dest.get("title") or "گفتگو"))
                    forward_options += f'<option value="{did}">{dtitle}</option>'
    except Exception:
        pass
    # رسید خواندن پیام‌ها: زمان آخرین بازدید خوانده‌شدهٔ اعضای دیگر
    room_read_markers = []
    try:
        read_response = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={"select":"user_id,last_read_at","conversation_id":"eq."+conversation_id},
            headers=headers, timeout=15
        )
        if read_response.ok:
            room_read_markers = [
                row for row in read_response.json()
                if str(row.get("user_id") or "") != current_user
            ]
    except Exception:
        room_read_markers = []

    def cyrus_read_time(value):
        try:
            dt = datetime.fromisoformat(str(value or "").replace("Z","+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    # Group/channel messages need visible sender identity, not just anonymous bubbles.
    sender_profiles = {}
    if str(room_data_for_history.get("type") or "") in ("group", "channel"):
        sender_ids = list(dict.fromkeys(
            str(item.get("sender_id") or "") for item in messages
            if item.get("sender_id") and str(item.get("sender_id")) != current_user
        ))[:200]
        if sender_ids:
            try:
                sender_profile_response = requests.get(
                    URL + "/rest/v1/cyrus_profiles",
                    params={
                        "select": "id,display_name,username,avatar_url",
                        "id": "in.(" + ",".join(sender_ids) + ")"
                    },
                    headers=headers,
                    timeout=15
                )
                if sender_profile_response.ok:
                    sender_profiles = {
                        str(profile.get("id") or ""): profile
                        for profile in sender_profile_response.json()
                        if isinstance(profile, dict)
                    }
            except Exception:
                sender_profiles = {}

    message_rows = ""
    previous_message_date = None

    for msg in messages:
        mine = str(msg.get("sender_id") or "") == current_user
        css_class = "mine" if mine else "theirs"
        body = cyrus_format_message_text(msg.get("content") or "")
        attachment_url = str(msg.get("attachment_url") or "")
        message_kind = str(msg.get("message_type") or "text")
        if attachment_url:
            safe_attachment = html.escape(attachment_url, quote=True)
            file_meta = msg.get("metadata") if isinstance(msg.get("metadata"), dict) else {}
            safe_file_label = html.escape(str(file_meta.get("file_name") or msg.get("content") or "فایل"), quote=True)
            if message_kind == "photo":
                body = '<a href="' + safe_attachment + '" target="_blank" rel="noopener"><img class="cyrus-chat-photo" src="' + safe_attachment + '" alt="' + safe_file_label + '" loading="lazy"></a>' + (('<div>' + body + '</div>') if body else "")
            elif message_kind == "video":
                body = '<video class="cyrus-chat-video" controls preload="metadata" src="' + safe_attachment + '"></video>' + (('<div>' + body + '</div>') if body else "")
            elif message_kind == "audio":
                body = '<audio controls preload="metadata" src="' + safe_attachment + '"></audio>' + (('<div>' + body + '</div>') if body else "")
            else:
                body = '<a class="cyrus-chat-file" href="' + safe_attachment + '" target="_blank" rel="noopener" download="' + safe_file_label + '">📎 ' + safe_file_label + ' · دریافت فایل</a>' + (('<div>' + body + '</div>') if body and body != safe_file_label else "")
        stamp_raw = str(msg.get("created_at") or "")
        try:
            stamp_dt = datetime.fromisoformat(stamp_raw.replace("Z", "+00:00")).astimezone()
            stamp = html.escape(stamp_dt.strftime("%H:%M"))
            message_date = stamp_dt.date().isoformat()
            if message_date != previous_message_date:
                date_label = "امروز" if stamp_dt.date() == datetime.now().astimezone().date() else stamp_dt.strftime("%Y/%m/%d")
                message_rows += '<div class="chat-date-divider"><span>' + html.escape(date_label) + '</span></div>'
                previous_message_date = message_date
        except Exception:
            stamp = ""
        message_reactions = reaction_map.get(str(msg.get("id") or ""), [])
        reaction_counts = {}
        for reaction_row in message_reactions:
            reaction_emoji = str(reaction_row.get("emoji") or "")
            if reaction_emoji:
                reaction_counts[reaction_emoji] = reaction_counts.get(reaction_emoji, 0) + 1
        reaction_badges_html = '<div class="message-reaction-badges">' + ''.join(
            '<button type="button" class="message-reaction-badge'+(' mine' if str(row.get("user_id") or "") == current_user else '')+'" onclick="cyrusReactBadge(event,this)" data-emoji="'+html.escape(emoji,quote=True)+'">'+html.escape(emoji)+' <small>'+str(count)+'</small></button>'
            for emoji,count in reaction_counts.items()
        ) + '</div>' if reaction_counts else ""
        msg_id = html.escape(str(msg.get("id") or ""), quote=True)
        raw_content = html.escape(str(msg.get("content") or ""), quote=True)
        edited_label = " · ویرایش‌شده" if msg.get("edited_at") else ""
        read_status_html = ""
        if mine:
            created_for_receipt = cyrus_read_time(msg.get("created_at"))
            readers = sum(
                1 for row in room_read_markers
                if created_for_receipt and cyrus_read_time(row.get("last_read_at"))
                and cyrus_read_time(row.get("last_read_at")) >= created_for_receipt
            )
            if str(room_data_for_history.get("type") or "") == "private":
                read_status_html = '<span class="message-read-status" title="'+("خوانده‌شده" if readers else "ارسال‌شده")+'">'+("✓✓" if readers else "✓")+'</span>'
            elif readers:
                read_status_html = '<span class="message-read-status" title="تعداد اعضای خواننده">✓✓ '+str(readers)+'</span>'

        meta = msg.get("metadata") if isinstance(msg.get("metadata"), dict) else {}
        sender_label_html = ""
        if not mine and str(room_data_for_history.get("type") or "") in ("group", "channel"):
            sender_profile = sender_profiles.get(str(msg.get("sender_id") or ""), {})
            sender_name = str(sender_profile.get("display_name") or sender_profile.get("username") or "عضو")
            sender_avatar = str(sender_profile.get("avatar_url") or "")
            if sender_avatar:
                sender_avatar_html = '<img src="' + html.escape(sender_avatar, quote=True) + '" alt="" loading="lazy" style="width:20px;height:20px;border-radius:50%;object-fit:cover">'
            else:
                sender_avatar_html = '<span style="width:20px;height:20px;border-radius:50%;display:inline-grid;place-items:center;background:#29445a;color:#e5bd69;font-size:11px">𓅃</span>'
            sender_label_html = (
                '<div class="cyrus-message-sender" style="display:flex;align-items:center;gap:6px;margin:0 0 5px;color:#8fc9f2;font-size:11px">'
                + sender_avatar_html + '<span>' + html.escape(sender_name) + '</span></div>'
            )
        reply_source = html.escape(str(meta.get("reply_to_content") or ""))
        reply_target_id = html.escape(str(meta.get("reply_to_id") or ""), quote=True)
        reply_preview = (f'<button type="button" class="reply-preview" data-reply-target="{reply_target_id}" onclick="cyrusJumpToMessage(event,this)">↪ پاسخ به: {reply_source}</button>' if reply_source else "")
        message_created_iso = html.escape(str(msg.get("created_at") or ""), quote=True)
        forwarded_label = '<small class="forwarded-label">↗ پیام انتقال‌یافته</small>' if meta.get("forwarded_from_message_id") else ""
        pinned_label = '<small class="pinned-label">📌 سنجاق‌شده</small>' if meta.get("pinned") else ""
        controls = (
            f'<div class="message-context" aria-hidden="true">'
            '<div class="reaction-strip">'
            + ''.join(f'<button type="button" class="reaction-choice" onclick="cyrusReact(event,this)" aria-label="واکنش {emoji}">{emoji}</button>' for emoji in ["❤️","👍","👎","🔥","🥰","👏","🇮🇷"])
            + '</div><div class="context-actions">'
            + f'<button type="button" onclick="cyrusReply(this)" data-id="{msg_id}" data-content="{raw_content}"><span>↶</span> پاسخ</button>'
            + f'<button type="button" onclick="cyrusCopy(this)" data-content="{raw_content}"><span>▢</span> کپی</button>'
            + f'<form method="post" action="/chat/message/{msg_id}/save"><input type="hidden" name="conversation_id" value="{conversation_id}"><button type="submit"><span>♧</span> ذخیره در پیام‌های من</button></form>'
            + f'<button type="button" onclick="cyrusCopyTimestamp(this)" data-created="{message_created_iso}"><span>◷</span> کپی زمان</button>'
            + f'<button type="button" onclick="cyrusCopyMessageLink(this)" data-id="{msg_id}"><span>🔗</span> پیوند پیام</button>'
            + f'<button type="button" onclick="cyrusShareMessage(this)" data-content="{raw_content}" data-id="{msg_id}"><span>↗</span> اشتراک‌گذاری</button>'
            + f'<button type="button" onclick="cyrusToggleMessageSelection(this)" data-id="{msg_id}"><span>☑</span> انتخاب پیام</button>'
            + '<button type="button" onclick="cyrusShowForward(this)"><span>↪</span> هدایت</button>'
            + f'<form class="forward-form" method="post" action="/chat/message/{msg_id}/forward" style="display:none">'
            + f'<select name="conversation_id" required>{forward_options}</select><button type="submit">ارسال</button></form>'
            + (f'<form method="post" action="/chat/message/{msg_id}/pin">'
               f'<input type="hidden" name="conversation_id" value="{conversation_id}">'
               f'<button type="submit"><span>⌖</span> {"برداشتن سنجاق" if meta.get("pinned") else "سنجاق کردن"}</button></form>' if mine else "")
            + (f'<button type="button" onclick="cyrusEdit(this)"><span>✎</span> ویرایش</button>'
               f'<form method="post" action="/chat/message/{msg_id}/delete" '
               'onsubmit="return confirm(\'این پیام برای هر دو طرف حذف شود؟\')">'
               f'<input type="hidden" name="conversation_id" value="{conversation_id}">'
               '<button type="submit"><span>⌫</span> حذف</button></form>' if mine else "")
            + '</div></div>'
        )
        edit_form = ""
        if mine:
            edit_form = (
                f'<form class="edit-form" method="post" '
                f'action="/chat/message/{msg_id}/edit" style="display:none">'
                f'<input type="hidden" name="conversation_id" value="{conversation_id}">'
                '<input type="hidden" name="content">'
                '</form>'
            )

        message_rows += f"""
        <div id="message-{msg_id}" class="message {css_class}" data-content="{raw_content}" data-message-id="{msg_id}" data-conversation-id="{conversation_id}" onclick="cyrusOpenMessageMenu(event,this)" role="button" tabindex="0" onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();cyrusOpenMessageMenu(event,this)}}">
          {sender_label_html}{reply_preview}{forwarded_label}{pinned_label}
          <div class="message-body">{body}</div>
          {reaction_badges_html}
          <small>{stamp}{edited_label} {read_status_html}</small>
          {controls}
          {edit_form}
        </div>"""

    if not message_rows:
        message_rows = '<div class="empty">هنوز پیامی ارسال نشده؛ اولین پیام را بفرستید</div>'

    room_data = room.json()[0]
    room_type = str(room_data.get("type") or "")
    room_title_text = str(room_data.get("title") or "گفتگو")
    room_avatar_source = str(room_data.get("avatar_url") or "")
    room_subtitle = "گفتگوی خصوصی" if room_type == "private" else ("کانال" if room_type == "channel" else "گروه")
    room_last_seen = "آخرین بازدید نامشخص"
    room_blocked = False
    room_blocked_by_me = False
    room_blocked_by_other = False
    room_other_user_id = ""
    room_profile_href = "/conversation/" + conversation_id + "/profile"
    if room_type == "private":
        try:
            member_response = requests.get(
                URL + "/rest/v1/cyrus_members",
                params={"select":"user_id","conversation_id":"eq."+conversation_id},
                headers=headers, timeout=15
            )
            other_id = ""
            if member_response.ok:
                for member in member_response.json():
                    candidate = str(member.get("user_id") or "")
                    if candidate and candidate != str(current_user):
                        other_id = candidate
                        break
            if other_id:
                room_other_user_id = other_id
                person_response = requests.get(
                    URL + "/rest/v1/cyrus_profiles",
                    params={"select":"display_name,username,avatar_url,last_seen_at","id":"eq."+other_id,"limit":"1"},
                    headers=headers, timeout=15
                )
                if person_response.ok and person_response.json():
                    person = person_response.json()[0]
                    room_title_text = str(person.get("display_name") or person.get("username") or room_title_text)
                    room_avatar_source = str(person.get("avatar_url") or room_avatar_source)
                    try:
                        saved_contact_response = requests.get(
                            URL + "/rest/v1/cyrus_contacts",
                            params={"select":"contact_name","owner_id":"eq."+str(current_user),"contact_user_id":"eq."+other_id,"limit":"1"},
                            headers=headers, timeout=12
                        )
                        if saved_contact_response.ok and saved_contact_response.json():
                            room_title_text = str(saved_contact_response.json()[0].get("contact_name") or room_title_text)
                    except Exception:
                        pass
                    seen_raw = str(person.get("last_seen_at") or "").strip()
                    if seen_raw:
                        try:
                            seen_dt = datetime.fromisoformat(seen_raw.replace("Z", "+00:00"))
                            if seen_dt.tzinfo is None:
                                seen_dt = seen_dt.replace(tzinfo=timezone.utc)
                            seen_local = seen_dt.astimezone()
                            now_dt = datetime.now(timezone.utc)
                            age_seconds = max(0, (now_dt - seen_dt.astimezone(timezone.utc)).total_seconds())
                            if age_seconds <= 300:
                                room_last_seen = "آنلاین"
                            elif age_seconds < 7 * 86400:
                                room_last_seen = "آخرین بازدید " + seen_local.strftime("%Y/%m/%d · %H:%M")
                            elif age_seconds < 30 * 86400:
                                room_last_seen = "آخرین بازدید یک هفته پیش"
                            else:
                                room_last_seen = "مدتی پیش"
                        except (TypeError, ValueError, OverflowError):
                            room_last_seen = "آخرین بازدید نامشخص"
                    # Pair-level RPC checks both directions despite private block-table RLS.
                    block_status = cyrus_block_status(other_id, headers)
                    room_blocked = block_status is True
                    if room_blocked:
                        # RLS exposes only blocks created by the current account; identify which side blocked.
                        own_block = requests.get(
                            URL + "/rest/v1/cyrus_user_blocks",
                            params={"select":"blocker_id","blocker_id":"eq."+str(current_user),"blocked_id":"eq."+other_id,"limit":"1"},
                            headers=headers, timeout=12
                        )
                        room_blocked_by_me = bool(own_block.ok and own_block.json())
                        room_blocked_by_other = not room_blocked_by_me
                        room_last_seen = "این گفتگو مسدود است"
                    room_profile_href = "/user/" + other_id + "?from_chat=" + conversation_id
        except Exception:
            pass
    room_title = html.escape(room_title_text)
    room_description = html.escape(str(room_data.get("description") or ""))
    room_avatar_url = html.escape(room_avatar_source, quote=True)
    room_avatar = (
        f'<img src="{room_avatar_url}" alt="">'
        if room_avatar_url else '<div class="room-avatar-symbol">𓊹</div>'
    )
    room_invite_code = str(room_data_for_history.get("invite_code") or "")
    room_invite_url = request.host_url.rstrip("/") + "/invite/" + room_invite_code if room_invite_code else ""
    room_invite_safe = html.escape(room_invite_url, quote=True)
    if room_type in ("group", "channel"):
        can_manage_room = is_room_owner or str(member_history_row.get("role") or "") in ("owner","admin")
        room_manage_menu = '<a href="/rooms/' + html.escape(conversation_id,quote=True) + '/manage">مدیریت</a>' if can_manage_room else ''
        room_more_html = (
            '<div class="tg-chat-menu-wrap"><button type="button" class="chat-header-more" aria-label="گزینه‌های کانال" onclick="cyrusToggleRoomMenu(event)">⋮</button>'
            '<div class="tg-chat-menu" id="cyrusRoomMenu" hidden>'
            '<button type="button" onclick="cyrusToggleMute()">بی‌صدا کردن</button>'
            '<button type="button" onclick="cyrusTogglePin()">سنجاق / برداشتن سنجاق</button>'
            '<button type="button" onclick="cyrusSearchInChat()">جستجو در گفتگو</button>'
            '<form method="post" action="/chat/' + html.escape(conversation_id,quote=True) + '/mark-unread"><button type="submit">علامت‌گذاری به‌عنوان خوانده‌نشده</button></form>'
            '<a href="' + html.escape(room_profile_href,quote=True) + '">اطلاعات ' + ("گروه" if room_type=="group" else "کانال") + '</a>'
            + room_manage_menu
            + ('<button type="button" onclick="cyrusCopyRoomInvite()">کپی لینک دعوت</button>' if room_invite_url else '')
            + ('' if is_room_owner else '<form method="post" action="/rooms/' + html.escape(conversation_id,quote=True) + '/leave" onsubmit="return confirm(\'از این مجموعه خارج می‌شوید؟\')"><button type="submit">ترک ' + ("گروه" if room_type=="group" else "کانال") + '</button></form>')
            + '</div></div>'
        )
    else:
        room_more_html = (
            '<div class="tg-chat-menu-wrap"><button type="button" class="chat-header-more" aria-label="گزینه‌های گفتگو" onclick="cyrusToggleRoomMenu(event)">⋮</button>'
            '<div class="tg-chat-menu" id="cyrusRoomMenu" hidden>'
            '<button type="button" onclick="cyrusSearchInChat()">جستجو در گفتگو</button>'
            '<form method="post" action="/chat/' + html.escape(conversation_id,quote=True) + '/mark-unread"><button type="submit">علامت‌گذاری به‌عنوان خوانده‌نشده</button></form>'
            '<a href="' + html.escape(room_profile_href,quote=True) + '">اطلاعات مخاطب</a>'
            '</div></div>'
        )
    room_header = f"""
    <section class="room-header cyrus-chat-header">
      <a class="chat-back" href="/home" aria-label="بازگشت">➜</a>
      <a class="room-avatar" href="{html.escape(room_profile_href, quote=True)}">{room_avatar}</a>
      <a class="room-info" href="{html.escape(room_profile_href, quote=True)}">
        <h2>{room_title}</h2>
        <span class="room-type">{room_last_seen if room_type == 'private' else room_subtitle}</span>
      </a>
      {room_more_html}
    </section>
    <script>
      const cyrusRoomKey='cyrus-room-{conversation_id}';
      function cyrusSharedSet(key){{try{{const a=JSON.parse(localStorage.getItem(key)||'[]');return new Set(Array.isArray(a)?a.map(String):[]);}}catch(_e){{return new Set();}}}}
      function cyrusSharedToggle(key,id){{const a=cyrusSharedSet(key);a.has(id)?a.delete(id):a.add(id);localStorage.setItem(key,JSON.stringify([...a]));return a.has(id);}}
      function cyrusRoomToast(msg){{let t=document.getElementById('cyrusRoomToast');if(!t){{t=document.createElement('div');t.id='cyrusRoomToast';t.style.cssText='position:fixed;z-index:9999;bottom:90px;left:50%;transform:translateX(-50%);background:#14283b;border:1px solid #34516a;color:#e9f2fa;padding:11px 16px;border-radius:20px;font:13px Tahoma;box-shadow:0 8px 25px #0008';document.body.appendChild(t);}}t.textContent=msg;t.style.display='block';clearTimeout(t._timer);t._timer=setTimeout(()=>t.style.display='none',1800);}}
      function cyrusToggleRoomMenu(e){{e.stopPropagation();const m=document.getElementById('cyrusRoomMenu');if(m){{m.hidden=!m.hidden;if(!m.hidden){{const b=m.querySelector('button');if(b)b.focus();cyrusUpdateRoomMenu();}}}}}}
      function cyrusUpdateRoomMenu(){{const m=document.getElementById('cyrusRoomMenu');if(!m)return;const mute=cyrusSharedSet('cyrus_muted_chats_v1').has("{conversation_id}"),pin=cyrusSharedSet('cyrus_pinned_chats_v1').has("{conversation_id}");const bs=m.querySelectorAll('button');if(bs[0])bs[0].textContent=mute?'فعال‌کردن صدا':'بی‌صدا کردن';if(bs[1])bs[1].textContent=pin?'برداشتن سنجاق':'سنجاق گفتگو';}}
      document.addEventListener('click',function(e){{const m=document.getElementById('cyrusRoomMenu');if(m&&!e.target.closest('.tg-chat-menu-wrap'))m.hidden=true;}});
      document.addEventListener('keydown',function(e){{const m=document.getElementById('cyrusRoomMenu');if(e.key==='Escape'&&m&&!m.hidden){{m.hidden=true;const b=document.querySelector('.chat-header-more');if(b)b.focus();}}}});
      function cyrusCopyRoomInvite(){{const u="{room_invite_safe}";if(!u)return;const m=document.getElementById('cyrusRoomMenu');if(m)m.hidden=true;if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(u).then(()=>cyrusRoomToast('لینک دعوت کپی شد')).catch(()=>cyrusRoomCopyFallback(u));else cyrusRoomCopyFallback(u);}}
      function cyrusRoomCopyFallback(u){{const a=document.createElement('textarea');a.value=u;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();try{{const ok=document.execCommand('copy');cyrusRoomToast(ok?'لینک دعوت کپی شد':'لینک را دستی کپی کنید');if(!ok)prompt('لینک دعوت',u);}}catch(_e){{prompt('لینک دعوت',u);}}a.remove();}}
      function cyrusToggleMute(){{const v=cyrusSharedToggle('cyrus_muted_chats_v1',"{conversation_id}");cyrusUpdateRoomMenu();cyrusRoomToast(v?'گفتگو بی‌صدا شد':'صدای گفتگو فعال شد');}}
      function cyrusTogglePin(){{const v=cyrusSharedToggle('cyrus_pinned_chats_v1',"{conversation_id}");cyrusUpdateRoomMenu();cyrusRoomToast(v?'گفتگو سنجاق شد':'سنجاق گفتگو برداشته شد');}}
      let cyrusRoomSearchItems=[],cyrusRoomSearchIndex=-1,cyrusRoomSearchTerm='',cyrusRoomSearchLastFocus=null;
      function cyrusSearchInChat(){{const m=document.getElementById('cyrusRoomMenu');if(m)m.hidden=true;let box=document.getElementById('cyrusRoomSearch');if(!box){{box=document.createElement('div');box.id='cyrusRoomSearch';box.style.cssText='position:fixed;z-index:1000;top:70px;left:10px;right:10px;max-width:560px;margin:auto;padding:12px;background:#0d1b2a;border:1px solid #34516a;border-radius:14px;display:flex;gap:6px;align-items:center;box-shadow:0 8px 30px #0009';box.innerHTML='<input id="cyrusRoomSearchInput" aria-label="عبارت جستجو" placeholder="جستجو در همه پیام‌های گفتگو…" style="flex:1;min-width:0;background:#07121e;color:#fff;border:1px solid #30485e;border-radius:9px;padding:10px;font:14px Tahoma"><span id="cyrusRoomSearchCount" aria-live="polite" style="white-space:nowrap;color:#a9bed0;font:12px Tahoma">۰/۰</span><button type="button" id="cyrusRoomSearchPrev" aria-label="نتیجه قبلی" style="width:auto;margin:0;padding:8px">↑</button><button type="button" id="cyrusRoomSearchNext" aria-label="نتیجه بعدی" style="width:auto;margin:0;padding:8px">↓</button><button type="button" id="cyrusRoomSearchClose" aria-label="بستن" style="width:auto;margin:0;padding:8px;background:#25394d;color:#fff">×</button><div id="cyrusRoomSearchRemote" style="position:absolute;top:54px;right:0;left:0;max-height:55vh;overflow:auto;background:#102235;border:1px solid #34516a;border-radius:10px"></div>';document.body.appendChild(box);box.querySelector('#cyrusRoomSearchInput').addEventListener('input',()=>{{cyrusRoomSearchUpdate();clearTimeout(window.cyrusRemoteSearchTimer);window.cyrusRemoteSearchTimer=setTimeout(cyrusRoomRemoteSearch,350);}});box.querySelector('#cyrusRoomSearchInput').addEventListener('keydown',e=>{{if(e.key==='Enter'){{e.preventDefault();cyrusRoomSearchMove(e.shiftKey?-1:1);}}}});box.querySelector('#cyrusRoomSearchPrev').addEventListener('click',()=>cyrusRoomSearchMove(-1));box.querySelector('#cyrusRoomSearchNext').addEventListener('click',()=>cyrusRoomSearchMove(1));box.querySelector('#cyrusRoomSearchClose').addEventListener('click',cyrusRoomSearchClose);}}cyrusRoomSearchLastFocus=document.activeElement;box.style.display='flex';const input=box.querySelector('input');input.focus();input.select();if(input.value)cyrusRoomSearchUpdate();}}
      function cyrusRoomSearchUpdate(){{const input=document.getElementById('cyrusRoomSearchInput');cyrusRoomSearchTerm=(input.value||'').trim().toLocaleLowerCase();cyrusRoomSearchItems=Array.from(document.querySelectorAll('.message')).filter(x=>cyrusRoomSearchTerm&&x.textContent.toLocaleLowerCase().includes(cyrusRoomSearchTerm));cyrusRoomSearchIndex=cyrusRoomSearchItems.length?0:-1;const count=document.getElementById('cyrusRoomSearchCount');if(count)count.textContent=cyrusRoomSearchItems.length?('۱/'+cyrusRoomSearchItems.length):'۰/۰';const box=document.getElementById('cyrusRoomSearch');if(box)box.dataset.noResults=cyrusRoomSearchTerm&&!cyrusRoomSearchItems.length?'true':'false';cyrusRoomSearchShow();}}
      async function cyrusRoomRemoteSearch(){{const input=document.getElementById('cyrusRoomSearchInput'),panel=document.getElementById('cyrusRoomSearchRemote');if(!input||!panel)return;const q=input.value.trim();if(q.length<2){{panel.innerHTML='';return;}}panel.innerHTML='<div style="padding:10px;color:#9db2c4;font:12px Tahoma">در حال جستجو در تاریخچه…</div>';try{{const response=await fetch('/chat/{conversation_id}/search?q='+encodeURIComponent(q),{{credentials:'same-origin',headers:{{'Accept':'application/json'}}}});if(!response.ok)throw new Error('search');const data=await response.json();if(input.value.trim()!==q)return;const results=Array.isArray(data.results)?data.results:[];if(!results.length){{panel.innerHTML='<div style="padding:12px;color:#9db2c4;font:12px Tahoma">نتیجه‌ای پیدا نشد</div>';return;}}panel.innerHTML=results.map(item=>{{const id=encodeURIComponent(item.id||''),txt=String(item.content||'').replace(/[&<>"]/g,ch=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[ch]));const dt=item.created_at?new Date(item.created_at).toLocaleString('fa-IR'):'';return '<a href="/chat/{conversation_id}?message='+id+'" style="display:block;padding:10px 12px;border-bottom:1px solid #263d52;color:#e6edf4;text-decoration:none;font:12px Tahoma"><div style="color:#82bfe9;margin-bottom:4px">'+dt+'</div>'+txt+'</a>';}}).join('');}}catch(_e){{panel.innerHTML='<div style="padding:12px;color:#e6a5a5;font:12px Tahoma">جستجو انجام نشد؛ دوباره تلاش کنید</div>';}}}}
      function cyrusRoomSearchShow(){{document.querySelectorAll('.message').forEach(x=>{{x.style.outline='';x.style.outlineOffset='';x.removeAttribute('data-cyrus-search-active');}});if(cyrusRoomSearchIndex<0||!cyrusRoomSearchItems.length)return;const x=cyrusRoomSearchItems[cyrusRoomSearchIndex];x.style.outline='2px solid #e5bd69';x.style.outlineOffset='2px';x.setAttribute('data-cyrus-search-active','1');x.scrollIntoView({{behavior:'smooth',block:'center'}});const c=document.getElementById('cyrusRoomSearchCount');if(c)c.textContent=(cyrusRoomSearchIndex+1)+'/'+cyrusRoomSearchItems.length;}}
      function cyrusRoomSearchMove(step){{if(!cyrusRoomSearchItems.length)return;cyrusRoomSearchIndex=(cyrusRoomSearchIndex+step+cyrusRoomSearchItems.length)%cyrusRoomSearchItems.length;cyrusRoomSearchShow();}}
      function cyrusRoomSearchClose(){{const box=document.getElementById('cyrusRoomSearch');if(box){{box.style.display='none';box.dataset.noResults='false';}}document.querySelectorAll('.message').forEach(x=>{{x.style.outline='';x.style.outlineOffset='';x.removeAttribute('data-cyrus-search-active');}});cyrusRoomSearchItems=[];cyrusRoomSearchIndex=-1;cyrusRoomSearchTerm='';if(cyrusRoomSearchLastFocus&&cyrusRoomSearchLastFocus.focus)cyrusRoomSearchLastFocus.focus();}}
      document.addEventListener('keydown',function(e){{const box=document.getElementById('cyrusRoomSearch');if(e.key==='Escape'&&box&&box.style.display!=='none'){{e.preventDefault();cyrusRoomSearchClose();}}}});
      document.addEventListener('click',function(e){{const box=document.getElementById('cyrusRoomSearch');if(box&&box.style.display!=='none'&&!e.target.closest('#cyrusRoomSearch')&&!e.target.closest('#cyrusRoomMenu'))cyrusRoomSearchClose();}});
    </script>"""

    channel_can_post = True
    if room_type == "channel":
        channel_can_post = (
            str(room_data.get("created_by") or "") == str(current_user)
        )
        if not channel_can_post:
            member_check = requests.get(
                URL + "/rest/v1/cyrus_members",
                params={
                    "select": "role",
                    "conversation_id": "eq." + conversation_id,
                    "user_id": "eq." + str(current_user),
                    "limit": "1"
                },
                headers=headers,
                timeout=20
            )
            if member_check.ok and member_check.json():
                channel_can_post = (
                    member_check.json()[0].get("role") == "admin"
                )

    send_box = (
        f'<form class="media-picker-form" id="cyrusMediaUpload" method="post" enctype="multipart/form-data" action="/chat/{conversation_id}/upload">'
        '<input type="file" id="cyrusMediaInput" name="media" multiple accept="image/*,video/mp4,video/webm,audio/*,.pdf,.txt,.zip,.docx,.xlsx" hidden>'
        '<button type="submit" id="cyrusMediaSubmit" hidden>ارسال</button></form>'
        f'<form class="send-box" method="post" action="/chat/{conversation_id}/send">'
        '<div id="cyrusReplyBar" class="cyrus-reply-composer" style="display:none"><span id="cyrusReplyText"></span><button type="button" onclick="cyrusCancelReply()">×</button></div>'
        '<input type="hidden" name="reply_to_id" id="cyrusReplyId" value="">'
        '<button class="composer-emoji" type="button" aria-label="ایموجی" onclick="cyrusToggleEmoji(event)">☺</button>'
        '<div class="composer-emoji-panel" id="cyrusEmojiPanel" style="display:none"><emoji-picker id="cyrusFullEmojiPicker" locale="en"></emoji-picker></div>'
        '<script type="module" src="https://cdn.jsdelivr.net/npm/emoji-picker-element@1.29.1/index.js"></script>'
        '<div class="composer-attach-wrap"><button class="composer-attach" type="button" aria-label="پیوست" onclick="cyrusToggleAttach(event)">📎</button><div class="composer-attach-menu" id="cyrusAttachMenu" hidden>'
        '<button type="button" onclick="cyrusPickMedia(\'photo\')"><span>▧</span> عکس و ویدئو</button>'
        '<button type="button" onclick="cyrusPickMedia(\'music\')"><span>♫</span> موسیقی و صدا</button>'
        '<button type="button" onclick="cyrusPickMedia(\'file\')"><span>▤</span> فایل</button>'
        '<button type="button" onclick="cyrusShareLocation()"><span>⌖</span> موقعیت مکانی</button>'
        '<button type="button" onclick="cyrusShareContact()"><span>♙</span> مخاطب</button></div></div>'
        '<input type="hidden" name="client_nonce" value=""><input name="content" maxlength="4000" placeholder="پیام بنویسید..." autocomplete="off">'
        '<small class="cyrus-composer-counter" id="cyrusComposerCounter" aria-live="polite">۰ / ۴۰۰۰</small><span id="cyrusVoiceStatus" class="cyrus-voice-status" aria-live="polite"></span><button type="button" class="composer-voice" id="cyrusVoiceButton" aria-label="ضبط پیام صوتی" onclick="cyrusToggleVoiceRecord(this)">🎙</button><button type="button" id="cyrusVoiceCancel" class="composer-voice-cancel" hidden onclick="cyrusCancelVoiceRecord()">لغو ضبط</button><button class="composer-send" type="submit" aria-label="ارسال پیام" disabled>➤</button></form>'
        '<script>function cyrusToggleAttach(e){e.stopPropagation();const m=document.getElementById("cyrusAttachMenu");if(m)m.hidden=!m.hidden;}'
        'function cyrusPickMedia(k){const i=document.getElementById("cyrusMediaInput"),m=document.getElementById("cyrusAttachMenu");if(m)m.hidden=true;i.value="";i.multiple=true;i.accept=k==="photo"?"image/*,video/mp4,video/webm":k==="music"?"audio/*":"*/*";i.click();}'
        'function cyrusShareLocation(){const m=document.getElementById("cyrusAttachMenu");if(m)m.hidden=true;if(!navigator.geolocation){alert("موقعیت مکانی پشتیبانی نمی‌شود");return;}navigator.geolocation.getCurrentPosition(p=>{const i=document.querySelector(".send-box input[name=content]");i.value="موقعیت مکانی: https://maps.google.com/?q="+p.coords.latitude+","+p.coords.longitude;i.focus();},()=>alert("اجازهٔ مکان را به مرورگر بدهید"),{timeout:12000});}function cyrusShareContact(){const m=document.getElementById("cyrusAttachMenu");if(m)m.hidden=true;const n=prompt("نام مخاطب");if(!n)return;const p=prompt("شماره تماس");if(!p)return;const i=document.querySelector(".send-box input[name=content]");i.value="مخاطب: "+n+" | شماره: "+p;i.focus();}'
        """let cyrusRecorder=null,cyrusVoiceChunks=[],cyrusVoiceTimer=null,cyrusVoiceStartedAt=0,cyrusVoiceStream=null,cyrusVoiceCancelled=false;
function cyrusVoiceUi(recording,seconds){const b=document.getElementById("cyrusVoiceButton"),cancel=document.getElementById("cyrusVoiceCancel"),status=document.getElementById("cyrusVoiceStatus");if(b){b.textContent=recording?"■":"🎙";b.classList.toggle("recording",recording);b.setAttribute("aria-label",recording?"پایان ضبط و ارسال":"ضبط پیام صوتی");}if(cancel)cancel.hidden=!recording;if(status)status.textContent=recording?"در حال ضبط · "+Math.floor(seconds/60).toString().padStart(2,"0")+":"+Math.floor(seconds%60).toString().padStart(2,"0"):"";}
function cyrusStopVoiceTracks(){if(cyrusVoiceStream){cyrusVoiceStream.getTracks().forEach(t=>t.stop());cyrusVoiceStream=null;}if(cyrusVoiceTimer){clearInterval(cyrusVoiceTimer);cyrusVoiceTimer=null;}}
function cyrusCancelVoiceRecord(){if(!cyrusRecorder||cyrusRecorder.state==="inactive")return;cyrusVoiceCancelled=true;cyrusRecorder.stop();cyrusStopVoiceTracks();cyrusVoiceChunks=[];cyrusVoiceUi(false,0);}
async function cyrusToggleVoiceRecord(b){
 if(cyrusRecorder&&cyrusRecorder.state==="recording"){cyrusVoiceCancelled=false;cyrusRecorder.stop();return;}
 if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia||!window.MediaRecorder){alert("ضبط صدا در این مرورگر پشتیبانی نمی‌شود");return;}
 try{
  cyrusVoiceStream=await navigator.mediaDevices.getUserMedia({audio:true});
  cyrusVoiceChunks=[];cyrusVoiceCancelled=false;
  const preferred=["audio/webm;codecs=opus","audio/ogg;codecs=opus","audio/webm"];
  const mime=preferred.find(t=>MediaRecorder.isTypeSupported&&MediaRecorder.isTypeSupported(t));
  cyrusRecorder=new MediaRecorder(cyrusVoiceStream,mime?{mimeType:mime}:{});
  cyrusRecorder.ondataavailable=e=>{if(e.data&&e.data.size)cyrusVoiceChunks.push(e.data);};
  cyrusRecorder.onerror=()=>{cyrusVoiceCancelled=true;cyrusStopVoiceTracks();cyrusVoiceUi(false,0);alert("خطا در ضبط پیام صوتی");};
  cyrusRecorder.onstop=async()=>{
   const cancelled=cyrusVoiceCancelled,recorder=cyrusRecorder;
   cyrusStopVoiceTracks();cyrusVoiceUi(false,0);
   if(cancelled){cyrusVoiceChunks=[];return;}
   const blob=new Blob(cyrusVoiceChunks,{type:recorder.mimeType||"audio/webm"});cyrusVoiceChunks=[];
   if(!blob.size){alert("ضبط صدا خالی بود");return;}
   const ext=blob.type.includes("ogg")?"ogg":blob.type.includes("mp4")?"m4a":"webm";
   const status=document.getElementById("cyrusVoiceStatus"),button=document.getElementById("cyrusVoiceButton");
   if(button)button.hidden=true;
   if(status){
    status.textContent="";
    const preview=document.createElement("div");preview.style.cssText="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin:6px 0";
    const player=document.createElement("audio");player.controls=true;player.preload="metadata";player.src=URL.createObjectURL(blob);player.style.cssText="width:min(220px,55vw);height:34px";
    const send=document.createElement("button");send.type="button";send.textContent="ارسال صدا";send.style.cssText="border:0;border-radius:10px;padding:8px 11px;background:#268bd0;color:white";
    const discard=document.createElement("button");discard.type="button";discard.textContent="ضبط دوباره";discard.style.cssText="border:1px solid #754d4d;border-radius:10px;padding:8px 10px;background:#321e25;color:#ffb5a8";
    const cleanup=()=>{URL.revokeObjectURL(player.src);preview.remove();if(button){button.hidden=false;button.disabled=false;}};
    discard.addEventListener("click",()=>{cleanup();});
    const progress=document.createElement("progress");progress.max=100;progress.value=0;progress.style.cssText="width:100%;height:7px;display:none";
    const cancelUpload=document.createElement("button");cancelUpload.type="button";cancelUpload.textContent="لغو ارسال";cancelUpload.hidden=true;cancelUpload.style.cssText="border:1px solid #754d4d;border-radius:10px;padding:7px 9px;background:#321e25;color:#ffb5a8";
    let voiceXhr=null;
    cancelUpload.addEventListener("click",()=>{if(voiceXhr)voiceXhr.abort();});
    send.addEventListener("click",()=>{
     send.disabled=true;discard.disabled=true;send.textContent="در حال ارسال…";progress.style.display="block";cancelUpload.hidden=false;
     const uploadForm=document.getElementById("cyrusMediaUpload"),form=new FormData(uploadForm);form.delete("media");form.append("media",blob,"voice."+ext);
     if(button)button.disabled=true;
     voiceXhr=new XMLHttpRequest();voiceXhr.open("POST",uploadForm.action);voiceXhr.withCredentials=true;
     voiceXhr.upload.onprogress=e=>{if(e.lengthComputable)progress.value=Math.round(e.loaded/e.total*100);};
     voiceXhr.onload=()=>{if(voiceXhr.status>=200&&voiceXhr.status<400){cleanup();location.reload();}else{send.disabled=false;discard.disabled=false;send.textContent="تلاش دوباره";cancelUpload.hidden=true;alert("ارسال پیام صوتی ناموفق بود ("+voiceXhr.status+")");}};
     voiceXhr.onerror=()=>{send.disabled=false;discard.disabled=false;send.textContent="تلاش دوباره";cancelUpload.hidden=true;alert("ارتباط برای ارسال صدا برقرار نشد");};
     voiceXhr.onabort=()=>{send.disabled=false;discard.disabled=false;send.textContent="ارسال دوباره";cancelUpload.hidden=true;progress.style.display="none";progress.value=0;};
     voiceXhr.onloadend=()=>{voiceXhr=null;if(button)button.disabled=false;};
     voiceXhr.send(form);
    });
    preview.append(player,send,discard,progress,cancelUpload);status.appendChild(preview);
   }
  };
  cyrusRecorder.start(500);cyrusVoiceStartedAt=Date.now();cyrusVoiceUi(true,0);
  cyrusVoiceTimer=setInterval(()=>{const elapsed=Math.floor((Date.now()-cyrusVoiceStartedAt)/1000);cyrusVoiceUi(true,elapsed);if(elapsed>=300&&cyrusRecorder&&cyrusRecorder.state==="recording"){cyrusVoiceCancelled=false;cyrusRecorder.stop();}},250);
 }catch(err){cyrusStopVoiceTracks();cyrusVoiceUi(false,0);alert("برای ضبط صدا، اجازهٔ میکروفون را به مرورگر بدهید");}
}(function(){
 const form=document.getElementById("cyrusMediaUpload"),input=document.getElementById("cyrusMediaInput");
 if(!form||!input)return;
 const panel=document.createElement("div");panel.id="cyrusMediaProgress";panel.hidden=true;
 panel.style.cssText="position:fixed;z-index:9998;bottom:calc(82px + env(safe-area-inset-bottom));left:12px;right:12px;max-width:620px;margin:auto;padding:12px 14px;border:1px solid #34516a;border-radius:14px;background:#102235;color:#e6edf4;box-shadow:0 8px 28px #0009;font:13px Tahoma";
 const label=document.createElement("div");label.style.cssText="margin-bottom:8px";
 const bar=document.createElement("progress");bar.max=100;bar.value=0;bar.style.cssText="width:100%;height:8px;display:block;margin-bottom:9px";
 const cancel=document.createElement("button");cancel.type="button";cancel.textContent="لغو بارگذاری";cancel.style.cssText="border:1px solid #754d4d;border-radius:9px;padding:7px 12px;background:#321e25;color:#ffb5a8";
 panel.append(label,bar,cancel);document.body.appendChild(panel);
 let xhr=null;
 function finish(){xhr=null;cancel.disabled=false;input.disabled=false;}
 cancel.addEventListener("click",()=>{if(xhr)xhr.abort();});
 input.addEventListener("change",()=>{
  if(!input.files||!input.files.length)return;
  const count=input.files.length;
  if(count>10){alert("در هر نوبت حداکثر ۱۰ فایل می‌توانید انتخاب کنید");input.value="";return;}
  xhr=new XMLHttpRequest();xhr.open("POST",form.action);xhr.withCredentials=true;
  input.disabled=true;cancel.disabled=false;panel.hidden=false;bar.value=0;
  label.textContent="در حال آماده‌سازی "+count.toLocaleString("fa-IR")+" فایل…";
  xhr.upload.onprogress=e=>{if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100);bar.value=p;label.textContent="در حال بارگذاری فایل‌ها · "+p.toLocaleString("fa-IR")+"٪";}};
  xhr.onload=()=>{if(xhr.status>=200&&xhr.status<400){label.textContent="بارگذاری انجام شد؛ گفتگو در حال به‌روزرسانی است…";bar.value=100;location.reload();}else{panel.hidden=true;alert("بارگذاری ناموفق بود ("+xhr.status+")؛ فایل‌ها را دوباره انتخاب کنید.");input.value="";finish();}};
  xhr.onerror=()=>{panel.hidden=true;alert("ارتباط هنگام بارگذاری قطع شد؛ دوباره تلاش کنید.");input.value="";finish();};
  xhr.onabort=()=>{panel.hidden=true;label.textContent="بارگذاری لغو شد";input.value="";finish();};
  xhr.onloadend=()=>{if(xhr&&xhr.readyState===4&&xhr.status>=200&&xhr.status<400)finish();};
  xhr.send(new FormData(form));
 });
})();"""
        """(function(){
          const form=document.querySelector(".send-box"),input=form&&form.querySelector("input[name=content]"),send=form&&form.querySelector(".composer-send"),counter=document.getElementById("cyrusComposerCounter");
          if(!form||!input||!send)return;
          const match=form.action.match(/\\/chat\\/([^/]+)\\/send/),draftKey="cyrus-draft-"+(match?match[1]:"default");
          try{if(!input.value)input.value=localStorage.getItem(draftKey)||"";}catch(e){}
          function update(){const n=input.value.length;send.disabled=!input.value.trim();if(counter)counter.textContent=n.toLocaleString("fa-IR")+" / ۴۰۰۰";try{if(input.value)localStorage.setItem(draftKey,input.value);else localStorage.removeItem(draftKey);}catch(e){}}
          update();input.addEventListener("input",update);
          input.addEventListener("keydown",function(e){if(e.key==="Enter"&&(e.ctrlKey||e.metaKey)){e.preventDefault();if(!send.disabled)form.requestSubmit();}});
          form.addEventListener("submit",function(e){if(!input.value.trim()||form.dataset.sending==="1"){e.preventDefault();return;}form.dataset.sending="1";send.disabled=true;send.textContent="…";try{localStorage.removeItem(draftKey);}catch(err){}});
          const picker=document.getElementById("cyrusFullEmojiPicker");if(picker)picker.addEventListener("emoji-click",function(e){const emoji=e.detail&&e.detail.unicode;if(!emoji)return;const start=input.selectionStart??input.value.length,end=input.selectionEnd??start;input.setRangeText(emoji,start,end,"end");input.dispatchEvent(new Event("input",{bubbles:true}));input.focus();});
          document.addEventListener("keydown",function(e){if(e.key!=="Escape")return;const a=document.getElementById("cyrusAttachMenu"),p=document.getElementById("cyrusEmojiPanel");if(a)a.hidden=true;if(p)p.style.display="none";});
        })();
        document.addEventListener("click",function(e){const m=document.getElementById("cyrusAttachMenu"),p=document.getElementById("cyrusEmojiPanel");if(m&&!e.target.closest(".composer-attach-wrap"))m.hidden=true;if(p&&!e.target.closest(".composer-emoji")&&!e.target.closest(".composer-emoji-panel"))p.style.display="none";});</script>"""
        if (room_type != "channel" or channel_can_post) and not room_blocked else
        (
            ('<div class="cyrus-blocked-composer"><p>این کاربر را مسدود کرده‌اید.</p><form method="post" action="/user/' + html.escape(room_other_user_id, quote=True) + '/block?from_chat=' + html.escape(conversation_id, quote=True) + '"><button type="submit">رفع مسدودیت</button></form></div>' if room_blocked_by_me else
             '<div class="cyrus-blocked-composer"><p>امکان ارسال پیام وجود ندارد.</p></div>')
            if room_blocked else
            '<div class="cyrus-blocked-composer"><p>این کانال فقط برای مالک و مدیران امکان انتشار پیام دارد.</p></div>'
        )
    )

    room_manage_link = (
        f'<p><a href="/rooms/{conversation_id}/manage">مدیریت گروه یا کانال</a></p>'
        if room_type in ("group", "channel") else ""
    )

    older_messages_link = ""
    if has_older_messages and messages:
        oldest_stamp = str(messages[0].get("created_at") or "")
        older_url = url_for("chat",conversation_id=conversation_id,before=oldest_stamp)
        older_messages_link = '<a class="cyrus-older-messages" href="' + html.escape(older_url,quote=True) + '">↑ پیام‌های قدیمی‌تر</a>'
    newer_messages_link = '<a class="cyrus-older-messages" href="' + html.escape(url_for("chat",conversation_id=conversation_id),quote=True) + '">↓ بازگشت به پیام‌های جدیدتر</a>' if message_before_valid else ""
    content = f"""
    <div class="container">
      {room_header}
      {pinned_banner}
      {older_messages_link}{newer_messages_link}
      <style>
        .container:has(.cyrus-chat-header){{max-width:650px;min-height:calc(100dvh - 76px);padding:0 12px 12px;display:flex;flex-direction:column;background:linear-gradient(180deg,rgba(7,16,27,.76),rgba(5,12,21,.9));}}
        .cyrus-chat-header{{position:sticky;top:0;z-index:8;flex:0 0 auto;box-shadow:0 4px 16px #0003}}
        .messages-area{{flex:1 1 auto;min-height:45vh;}}.cyrus-older-messages{{display:block;width:max-content;max-width:90%;margin:10px auto;padding:9px 15px;border-radius:18px;background:#172b3d;border:1px solid #304b63;color:#9acdf2;text-decoration:none;font-size:12px;text-align:center}}
        .chat-date-divider{{display:flex;justify-content:center;margin:8px 0 12px;pointer-events:none}}
        .chat-date-divider span{{padding:5px 12px;border-radius:14px;background:#253646dd;color:#c4d3df;font-size:11px;}}
        .message{{max-width:min(84%,480px);padding:9px 12px 7px;backdrop-filter:blur(5px);transition:background .15s,border-color .15s}}
        .message .message-body{{white-space:normal;word-break:break-word;}}
        .message .message-body a.chat-inline-link{{color:#8acbff;text-decoration:underline;text-underline-offset:2px;}}
        .message small{{display:flex;align-items:center;justify-content:flex-end;gap:5px;direction:ltr}}
        .message.context-open{{z-index:12;border-color:#e2bd6b;box-shadow:0 4px 20px #0006}}
        .message.cyrus-message-selected{{outline:2px solid #55a9e8!important;background:#18314a!important}}
        .reply-preview{{display:block;width:100%;text-align:right;border:0;border-inline-start:3px solid #5ba8e8;background:#13283a;color:#9fd0f5;padding:6px 9px;margin:0 0 7px;border-radius:5px;font:inherit;font-size:11px;cursor:pointer;overflow-wrap:anywhere}}
        .send-box{{position:sticky;bottom:calc(8px + env(safe-area-inset-bottom));flex:0 0 auto;margin:8px 0 0;min-height:54px;border-radius:27px;background:#172432;border:1px solid #2b4053;box-shadow:0 4px 18px #0006;}}
        .media-upload-box{{display:flex;gap:8px;align-items:center;padding:7px 10px;margin:5px 0;border-radius:16px;background:#172432;border:1px solid #2b4053;}}
        .media-upload-label{{display:flex;gap:7px;align-items:center;flex:1;font-size:13px;color:#b8cbdc;}}
        .media-upload-label input{{max-width:170px;font-size:11px;}}
        .media-upload-box button{{border:0;border-radius:12px;padding:8px 12px;background:#268bd0;color:#fff;}}
        .cyrus-chat-photo{{display:block;max-width:min(65vw,320px);max-height:360px;border-radius:12px;object-fit:contain;}}
        .cyrus-chat-video{{display:block;width:min(65vw,320px);max-height:360px;border-radius:12px;}}
        .cyrus-chat-file{{display:inline-block;color:#8acbff;padding:8px 10px;border-radius:10px;background:#142b3d;}}
        .send-box input[name="content"]{{color:#edf4fa;line-height:1.5;}}.cyrus-composer-counter{{position:absolute;bottom:-18px;right:16px;color:#8fa5b8;font-size:10px;pointer-events:none}}.composer-send:disabled{{opacity:.45;cursor:default}}
        .composer-emoji,.composer-send{{width:38px;height:38px;flex:0 0 38px;display:grid;place-items:center;margin:0;padding:0;border-radius:50%;font-size:22px}}
        .composer-emoji{{background:transparent;color:#a9bdce;border:0}}
        .composer-send{{background:#268bd0;color:#fff;font-size:20px;transform:scaleX(-1)}}.composer-voice{{width:34px;height:34px;flex:0 0 34px;margin:0;padding:0;border:0;border-radius:50%;background:transparent;color:#a9bdce;font-size:19px}}.cyrus-voice-status{{font-size:10px;color:#8fc8f1;white-space:nowrap}}.composer-voice-cancel{{width:auto;padding:7px 9px;margin:0;border:1px solid #754d4d;border-radius:12px;background:#321e25;color:#ffb5a8;font-size:10px}}.composer-voice-cancel[hidden]{{display:none}}.composer-voice.recording{{background:#9d3434;color:#fff;animation:cyrusVoicePulse 1s infinite alternate}}@keyframes cyrusVoicePulse{{to{{opacity:.55}}}}
        .cyrus-reply-composer{{position:absolute;right:10px;left:10px;bottom:calc(100% + 8px);display:flex;align-items:center;justify-content:space-between;gap:8px;padding:9px 12px;border-right:3px solid #d8b46a;border-radius:10px;background:#172838;color:#d9c18c;font-size:12px;}}
        .cyrus-reply-composer button{{width:28px;min-width:28px;margin:0;padding:3px;background:transparent;color:#b6c8d8;font-size:20px}}
        .composer-emoji-panel{{position:absolute;bottom:calc(100% + 10px);right:6px;width:min(360px,calc(100vw - 20px));height:min(450px,62vh);padding:0;overflow:hidden;border-radius:16px;background:#203243;border:1px solid #3a5268;box-shadow:0 8px 28px #0008;z-index:20;display:none}}
        .composer-emoji-panel emoji-picker{{display:block;width:100%;height:100%;--background:#203243;--border-color:#3a5268;--input-border-color:#435b70;--input-font-color:#edf4fa;--button-hover-background:#334b60}}
        .send-box .composer-send:disabled{{opacity:.55;cursor:wait}}
        @media(max-width:520px){{.container:has(.cyrus-chat-header){{padding-inline:8px}}.message{{max-width:88%}}.messages-area{{gap:7px}}}}
        .room-header{{display:flex;align-items:center;gap:10px;padding:10px 12px;margin:0 -12px 10px;border:0;border-radius:0;background:#172331;min-height:70px}}
        .cyrus-blocked-composer{{position:sticky;bottom:calc(8px + env(safe-area-inset-bottom));margin:8px 0 0;padding:13px 16px;background:#172432;border:1px solid #2b4053;border-radius:24px;text-align:center;color:#a9bac8;font-size:13px}}
        .cyrus-blocked-composer p{{margin:0 0 8px;line-height:1.7}}
        .cyrus-blocked-composer form{{margin:0}}
        .cyrus-blocked-composer button{{width:auto;margin:0;padding:8px 18px;background:transparent;color:#69b9f7;border:0;border-radius:18px;font-size:14px}}

        .cyrus-chat-header .chat-back{{font-size:27px;color:#e9f0f5;padding:4px 7px;flex:0 0 auto}}
        .tg-chat-menu-wrap{{position:relative;flex:0 0 auto}}
        .tg-chat-menu-wrap .chat-header-more{{width:40px;height:40px;display:grid;place-items:center;background:transparent;border:0;border-radius:50%;color:#e9f0f5;font-size:25px;text-decoration:none;cursor:pointer}}
        .tg-chat-menu{{position:absolute;top:46px;left:0;min-width:190px;padding:6px;background:#1b2b3a;border:1px solid #31475a;border-radius:12px;box-shadow:0 8px 28px #0008;z-index:30}}
        .tg-chat-menu[hidden]{{display:none}}
        .tg-chat-menu a,.tg-chat-menu button{{display:block;width:100%;padding:12px 13px;background:transparent;border:0;border-radius:7px;text-align:right;color:#eaf1f6;text-decoration:none;font-size:14px;white-space:nowrap}}
        .tg-chat-menu a:active,.tg-chat-menu button:active{{background:#2b4053}}
        .tg-chat-menu form{{margin:0;border-top:1px solid #304252}}
        .tg-chat-menu form button{{color:#f28b82}}

        .room-avatar{{width:43px;height:43px;flex:0 0 43px;border-radius:50%;overflow:hidden;border:0;background:#26394a;display:flex;align-items:center;justify-content:center}}
        .room-avatar img{{width:100%;height:100%;object-fit:cover}}
        .room-avatar-symbol{{font-size:23px;color:#d8b46a}}
        .room-info{{min-width:0;flex:1;text-decoration:none}}
        .room-info h2{{margin:0 0 4px;font-size:16px;color:#f1f5f8;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
        .room-type{{font-size:12px;color:#94a7b7;display:block}}
        .room-info p{{display:none}}
        .chat-header-more{{font-size:25px;color:#d2dce5;padding:4px 7px}}

        .messages-area{{display:flex;flex-direction:column;gap:8px;padding:8px 2px 18px}}
        .message{{position:relative;max-width:84%;padding:10px 13px;border:1px solid transparent;border-radius:16px;background:#172432;overflow-wrap:anywhere;box-shadow:0 1px 2px #0003}}
        .message .message-body{{color:#edf4fa;font-size:14px;line-height:1.8}}
        .message small{{display:block;color:#93a8ba;font-size:10px;margin-top:5px;text-align:left}}
        .message{{cursor:pointer}}
        .message-context{{display:none;position:fixed;z-index:30;left:50%;bottom:calc(78px + env(safe-area-inset-bottom) + 12px);transform:translateX(-50%);width:min(355px,calc(100vw - 34px));filter:drop-shadow(0 12px 28px #0008);cursor:default}}
        .message.context-open .message-context{{display:block}}
        .reaction-strip{{display:flex;justify-content:space-around;align-items:center;gap:3px;padding:8px 9px;margin-bottom:8px;border-radius:30px;background:#253747;border:1px solid #354d61}}
        .message-reaction-badges{{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}}
        .message-reaction-badge{{display:inline-flex;align-items:center;gap:4px;margin:0;padding:3px 8px;border-radius:16px;border:1px solid #334b60;background:#203244;color:#eaf2f8;font-size:13px;line-height:1.2;cursor:pointer}}
        .message-reaction-badge.mine{{border-color:#3998dc;background:#234d6d}}
        .message-reaction-badge small{{display:inline!important;margin:0!important;color:#b6c9d9!important;font-size:10px!important;text-align:center!important}}

        .reaction-choice{{width:auto;min-width:0;margin:0;padding:3px 2px;background:transparent;border:0;border-radius:50%;font-size:25px;line-height:1.25}}
        .context-actions{{display:flex;flex-direction:column;padding:6px 0;border-radius:12px;background:#253747;border:1px solid #344b5e;overflow:hidden}}
        .context-actions>button,.context-actions form>button{{display:flex;align-items:center;gap:16px;width:100%;margin:0;padding:12px 18px;border:0;border-radius:0;background:transparent;color:#edf4f8;text-align:right;font-size:15px;font-weight:normal}}
        .context-actions button span{{width:24px;text-align:center;color:#9db2c2;font-size:20px}}
        .context-actions button:active{{background:#344b5e}}
        .context-actions form{{display:flex;flex-direction:column;gap:5px;margin:0}}
        .context-actions select{{width:calc(100% - 24px);margin:6px 12px;max-width:none;background:#0b1422;color:#fff;border:1px solid #526a7d;border-radius:7px;padding:9px}}
        .context-actions form>button{{justify-content:flex-start}}
        .cyrus-inchat-search{{display:flex;align-items:center;gap:6px;padding:8px 10px;background:#142231;border-bottom:1px solid #2b4054;position:sticky;top:0;z-index:35}}.cyrus-inchat-search input{{min-width:0;flex:1;background:#0a1521;color:#fff;border:1px solid #334b61;border-radius:10px;padding:9px;font-size:13px}}.cyrus-inchat-search button{{border:0;border-radius:8px;background:#24394b;color:#e5eef6;padding:7px 10px}}.cyrus-search-count{{font-size:11px;color:#a9bdce;white-space:nowrap}}.message.cyrus-search-hit{{outline:2px solid #caa65d;outline-offset:2px}}.message.cyrus-search-current{{outline:3px solid #42a5f5;outline-offset:3px}}.cyrus-scroll-latest{{position:fixed;right:16px;bottom:94px;z-index:30;width:42px;height:42px;border:1px solid #3b5368;border-radius:50%;background:#172a3b;color:#eaf4fc;font-size:22px;box-shadow:0 5px 18px #0006}}.cyrus-scroll-latest[hidden]{{display:none}}.cyrus-compose-counter{{position:absolute;left:54px;bottom:7px;color:#9db0c2;font-size:10px;pointer-events:none}}.cyrus-compose-counter[hidden]{{display:none}}
        .reply-preview{{padding:5px 8px;border-right:3px solid #d8b46a;color:#d8b46a;font-size:12px;margin-bottom:6px}}
        .forwarded-label,.pinned-label{{color:#d8b46a}}
        .message.mine{{align-self:flex-start;background:#173b59;border-color:#245b83;border-bottom-left-radius:5px}}
        .message.theirs{{align-self:flex-end;background:#172432;border-color:#263b4d;border-bottom-right-radius:5px}}
        .message.reacted:after{{content:attr(data-reaction);display:inline-block;margin-top:5px;padding:2px 7px;border-radius:14px;background:#253747;font-size:17px}}
        .send-box{{position:sticky;bottom:8px;display:flex;align-items:center;gap:8px;background:#0b1724;padding:8px 10px;border:1px solid #263e53;border-radius:24px;box-shadow:0 4px 18px #0005;z-index:4}}
        .container:has(.cyrus-chat-header){{padding-bottom:12px}}
        .messages-area{{padding-bottom:12px}}
        .send-box input[name="content"]{{flex:1;min-width:0;width:auto;margin:0;padding:12px 14px;border:0;background:transparent;border-radius:20px;font-size:14px}}
        .send-box>button{{width:auto;flex:0 0 auto;margin:0;padding:11px 17px;border-radius:22px;background:#248bd0;color:white;font-size:13px}}
        .message-actions button{{padding:6px 10px;font-size:11px;border-radius:16px;background:#10283b;color:#b9d9f0;border:1px solid #2b4c66}}
        .message-actions select{{font-size:11px;padding:6px}}
      </style>
      <div class="messages-area">{message_rows}</div>
      <script>
      function cyrusToggleEmoji(event) {{
        event.preventDefault();event.stopPropagation();
        const panel=document.getElementById("cyrusEmojiPanel");
        if(panel)panel.style.display=panel.style.display==="none"?"block":"none";
      }}
      function cyrusInsertEmoji(emoji,closePanel=true) {{
        const input=document.querySelector('.send-box input[name="content"]');
        const panel=document.getElementById("cyrusEmojiPanel");
        if(!input)return;
        const start=input.selectionStart===null?input.value.length:input.selectionStart;
        const end=input.selectionEnd===null?start:input.selectionEnd;
        input.value=input.value.slice(0,start)+emoji+input.value.slice(end);
        input.focus();input.setSelectionRange(start+emoji.length,start+emoji.length);
        input.dispatchEvent(new Event("input",{{bubbles:true}}));
        if(panel&&closePanel)panel.style.display="none";
      }}
      document.addEventListener('DOMContentLoaded',function(){{
        window.scrollTo(0,document.body.scrollHeight);
        const deepLinkedMessage=new URLSearchParams(window.location.search).get('message');
        if(deepLinkedMessage) {{
          requestAnimationFrame(()=>requestAnimationFrame(()=>{{
            const target=document.getElementById('message-'+deepLinkedMessage);
            if(target) {{
              target.scrollIntoView({{behavior:'smooth',block:'center'}});
              target.classList.add('search-jump-highlight');
              target.setAttribute('tabindex','-1');
              target.focus({{preventScroll:true}});
              clearTimeout(target._cyrusHighlightTimer);
              target._cyrusHighlightTimer=setTimeout(()=>target.classList.remove('search-jump-highlight'),3200);
            }} else if(typeof cyrusToast==='function') {{
              cyrusToast('پیام پیوندشده در این گفتگو پیدا نشد');
            }}
          }}));
        }}
        const picker=document.getElementById("cyrusFullEmojiPicker");
        if(picker)picker.addEventListener("emoji-click",function(event){{
          const value=event.detail&&event.detail.unicode;
          if(value)cyrusInsertEmoji(value,false);
        }});
        const form=document.querySelector(".send-box");
        if(form){{
          const input=form.querySelector('input[name="content"]');
          const nonceInput=form.querySelector('input[name="client_nonce"]');
          const sendButton=form.querySelector(".composer-send");
          const draftKey="cyrus-chat-draft-"+form.action.split("/").filter(Boolean).slice(-2, -1)[0];
          const makeNonce=()=>window.crypto&&crypto.randomUUID?crypto.randomUUID():(Date.now().toString(36)+Math.random().toString(36).slice(2));
          let pendingText=null;
          try{{
            const saved=JSON.parse(localStorage.getItem(draftKey)||"null");
            if(saved&&typeof saved.text==="string"&&saved.text){{
              input.value=saved.text;
              pendingText=saved.text;
              nonceInput.value=saved.nonce||makeNonce();
            }}
          }}catch(e){{}}
          if(!nonceInput.value)nonceInput.value=makeNonce();
          input.addEventListener("input",function(){{
            if(pendingText!==null&&input.value!==pendingText){{
              nonceInput.value=makeNonce();
              pendingText=null;
            }}
            try{{localStorage.setItem(draftKey,JSON.stringify({{text:input.value,nonce:nonceInput.value||makeNonce()}}));}}catch(e){{}}
          }});
          form.addEventListener("submit",async function(event){{
            if(form.dataset.sending==="1"){{event.preventDefault();return;}}
            const text=input.value.trim();
            if(!text)return;
            event.preventDefault();
            const nonce=nonceInput.value||makeNonce();
            nonceInput.value=nonce;
            pendingText=text;
            try{{localStorage.setItem(draftKey,JSON.stringify({{text:text,nonce:nonce}}));}}catch(e){{}}
            form.dataset.sending="1";
            if(sendButton)sendButton.disabled=true;
            input.value="";
            const payload=new FormData(form);
            payload.set("content",text);
            payload.set("client_nonce",nonce);
            try{{
              const response=await fetch(form.action,{{method:"POST",body:payload,credentials:"same-origin",redirect:"follow"}});
              if(!response.ok)throw new Error("send failed");
              try{{localStorage.removeItem(draftKey);}}catch(e){{}}
              pendingText=null;
              nonceInput.value=makeNonce();
              window.location.href=response.url||form.action;
            }}catch(e){{
              if(!input.value)input.value=text;
              pendingText=text;
              form.dataset.sending="";
              if(sendButton)sendButton.disabled=false;
              input.focus();
            }}
          }});
        }}
      }});
      function cyrusCloseMessageMenus(returnFocus=false) {{
        document.querySelectorAll('.message.context-open').forEach(el=>{{
          el.classList.remove('context-open');
          const menu=el.querySelector('.message-context');
          if(menu)menu.setAttribute('aria-hidden','true');
          el.setAttribute('aria-expanded','false');
          if(returnFocus)el.focus({{preventScroll:true}});
        }});
      }}
      function cyrusOpenMessageMenu(event,message) {{
        if(event.target.closest('.message-context')) return;
        if(event.target.closest('button,form,select,input,a')) return;
        if(window.getSelection&&String(window.getSelection()).trim())return;
        const clickedId=message&&message.dataset.messageId;
        if(event.type==='click'&&clickedId&&cyrusSelectedMessages.size) {{
          const rows=[...document.querySelectorAll('.message[data-message-id]')];
          const anchorIndex=rows.findIndex(row=>row.dataset.messageId===cyrusSelectionAnchorId);
          const targetIndex=rows.findIndex(row=>row.dataset.messageId===clickedId);
          if(event.shiftKey&&anchorIndex>=0&&targetIndex>=0) {{
            rows.slice(Math.min(anchorIndex,targetIndex),Math.max(anchorIndex,targetIndex)+1)
              .forEach(row=>cyrusSelectedMessages.add(row.dataset.messageId));
          }} else if(cyrusSelectedMessages.has(clickedId)) {{
            cyrusSelectedMessages.delete(clickedId);
          }} else {{
            cyrusSelectedMessages.add(clickedId);
          }}
          cyrusSelectionAnchorId=clickedId;
          cyrusUpdateMessageSelection();
          event.preventDefault();event.stopPropagation();
          return;
        }}
        cyrusCloseMessageMenus(false);
        message.classList.add('context-open');
        message.setAttribute('aria-expanded','true');
        const menu=message.querySelector('.message-context');
        if(menu){{menu.setAttribute('aria-hidden','false');const first=menu.querySelector('button');if(first&&event.type==='keydown')first.focus({{preventScroll:true}});}}
        event.stopPropagation();
      }}
      (function(){{
        let pressTimer=null,startX=0,startY=0,longPressed=false;
        document.querySelectorAll('.message').forEach(message=>{{
          message.setAttribute('aria-expanded','false');
          message.addEventListener('pointerdown',event=>{{
            if(event.pointerType==='mouse'||event.target.closest('.message-context,button,form,a,input,select'))return;
            startX=event.clientX;startY=event.clientY;longPressed=false;
            clearTimeout(pressTimer);
            pressTimer=setTimeout(()=>{{longPressed=true;cyrusOpenMessageMenu(event,message);}},560);
          }});
          ['pointerup','pointercancel','pointerleave'].forEach(type=>message.addEventListener(type,()=>clearTimeout(pressTimer)));
          message.addEventListener('pointermove',event=>{{if(Math.abs(event.clientX-startX)>12||Math.abs(event.clientY-startY)>12)clearTimeout(pressTimer);}});
          message.addEventListener('click',event=>{{if(longPressed){{event.preventDefault();event.stopPropagation();longPressed=false;}}}});
        }});
        document.addEventListener('keydown',event=>{{
          const opened=document.querySelector('.message.context-open');
          if(!opened)return;
          if(event.key==='Escape'){{event.preventDefault();cyrusCloseMessageMenus(true);return;}}
          const actions=[...opened.querySelectorAll('.message-context button:not([disabled])')];
          const at=actions.indexOf(document.activeElement);
          if(event.key==='ArrowDown'&&actions.length){{event.preventDefault();actions[(at+1)%actions.length].focus();}}
          if(event.key==='ArrowUp'&&actions.length){{event.preventDefault();actions[(at-1+actions.length)%actions.length].focus();}}
        }});
      }})();
      document.addEventListener('click',function(event){{
        if(!event.target.closest('.message.context-open'))cyrusCloseMessageMenus(false);
      }});
      async function cyrusReact(event,button) {{
        event.preventDefault();event.stopPropagation();
        const message=button.closest('.message');
        if(message)await cyrusSaveReaction(message,button.textContent.trim());
      }}
      async function cyrusReactBadge(event,button) {{
        event.preventDefault();event.stopPropagation();
        const message=button.closest('.message');
        if(message)await cyrusSaveReaction(message,button.dataset.emoji||button.textContent.trim().split(' ')[0]);
      }}
      async function cyrusSaveReaction(message,emoji) {{
        const form=new URLSearchParams();form.set('conversation_id',message.dataset.conversationId||'');form.set('emoji',emoji);
        try {{
          const response=await fetch('/chat/message/'+encodeURIComponent(message.dataset.messageId)+'/react',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'}},body:form.toString(),credentials:'same-origin'}});
          if(!response.ok)throw new Error('reaction failed');
          const data=await response.json();
          let badges=message.querySelector('.message-reaction-badges');
          if(!badges){{badges=document.createElement('div');badges.className='message-reaction-badges';message.querySelector('.message-body').after(badges);}}
          if(data.previous&&data.previous!==emoji){{const previous=[...badges.querySelectorAll('[data-emoji]')].find(x=>x.dataset.emoji===data.previous);if(previous){{if(Number(data.previous_count)>0){{const n=previous.querySelector('small');if(n)n.textContent=data.previous_count;}}else previous.remove();}}}}
          const current=[...badges.querySelectorAll('[data-emoji]')].find(x=>x.dataset.emoji===emoji);
          if(data.removed){{if(current)current.remove();}}
          else if(current){{const count=current.querySelector('small');if(count)count.textContent=data.count||'1';current.classList.add('mine');}}
          else{{const b=document.createElement('button');b.type='button';b.className='message-reaction-badge mine';b.dataset.emoji=emoji;b.onclick=function(e){{cyrusReactBadge(e,this)}};b.append(document.createTextNode(emoji+' '));const c=document.createElement('small');c.textContent=data.count||'1';b.append(c);badges.append(b);}}
          if(!badges.children.length)badges.remove();message.classList.remove('context-open');
        }}catch(e){{alert('ثبت واکنش انجام نشد؛ دوباره تلاش کنید.');}}
      }}
      (function(){{ 
        const msgs=[...document.querySelectorAll('.message')],input=document.querySelector('.send-box input[name="content"]'),form=input&&input.form,chatId="{conversation_id}";
        let searchBox=null,searchInput=null,matches=[],matchAt=0;
        function ensureSearch(){{
          if(searchBox)return;
          searchBox=document.createElement('div');searchBox.className='cyrus-inchat-search';
          searchBox.innerHTML='<input type="search" placeholder="جستجو در پیام‌های این گفتگو" aria-label="جستجو در گفتگو"><span class="cyrus-search-count">۰/۰</span><button type="button" data-dir="-1" aria-label="نتیجهٔ قبلی">↑</button><button type="button" data-dir="1" aria-label="نتیجهٔ بعدی">↓</button><button type="button" data-close aria-label="بستن جستجو">×</button>';
          const header=document.querySelector('.room-header');if(header)header.after(searchBox);
          searchInput=searchBox.querySelector('input');
          searchInput.addEventListener('input',runSearch);
          searchBox.querySelectorAll('[data-dir]').forEach(b=>b.addEventListener('click',()=>moveMatch(Number(b.dataset.dir))));
          searchBox.querySelector('[data-close]').addEventListener('click',closeSearch);
        }}
        function runSearch(){{
          const q=(searchInput.value||'').trim().toLocaleLowerCase();matches=[];
          msgs.forEach(m=>{{m.classList.remove('cyrus-search-hit','cyrus-search-current');if(q&&m.textContent.toLocaleLowerCase().includes(q))matches.push(m);}});
          matchAt=0;updateSearch();if(matches.length)showMatch(0);
        }}
        function updateSearch(){{const n=searchBox.querySelector('.cyrus-search-count');if(n)n.textContent=(matches.length?matchAt+1:0)+'/'+matches.length;}}
        function showMatch(i){{if(!matches.length)return;matchAt=(i+matches.length)%matches.length;matches.forEach((m,j)=>m.classList.toggle('cyrus-search-current',j===matchAt));matches.forEach(m=>m.classList.add('cyrus-search-hit'));matches[matchAt].scrollIntoView({{behavior:'smooth',block:'center'}});updateSearch();}}
        function moveMatch(d){{if(matches.length)showMatch(matchAt+d);}}
        function closeSearch(){{if(searchBox)searchBox.remove();searchBox=null;searchInput=null;msgs.forEach(m=>m.classList.remove('cyrus-search-hit','cyrus-search-current'));}}
        window.cyrusSearchInChat=function(){{ensureSearch();searchBox.hidden=false;searchInput.focus();}};
        document.addEventListener('keydown',e=>{{if(e.key==='Escape'&&searchBox)closeSearch();if(searchBox&&document.activeElement===searchInput&&e.key==='Enter'){{e.preventDefault();moveMatch(e.shiftKey?-1:1);}}}});
        const down=document.createElement('button');down.type='button';down.className='cyrus-scroll-latest';down.textContent='↓';down.title='رفتن به آخر گفتگو';down.setAttribute('aria-label','آخرین پیام‌ها');document.body.appendChild(down);
        function checkDown(){{down.hidden=window.scrollY+window.innerHeight>document.documentElement.scrollHeight-260;}}
        down.addEventListener('click',()=>window.scrollTo({{top:document.documentElement.scrollHeight,behavior:'smooth'}}));window.addEventListener('scroll',checkDown,{{passive:true}});checkDown();
        if(input){{const key='cyrus-draft-'+chatId;try{{const saved=localStorage.getItem(key);if(saved&&!input.value)input.value=saved;}}catch(e){{}}
          let counter=document.createElement('small');counter.className='cyrus-compose-counter';input.parentElement.appendChild(counter);
          function count(){{counter.textContent=input.value.length+'/4000';counter.hidden=input.value.length<3500;}}
          input.addEventListener('input',()=>{{try{{localStorage.setItem(key,input.value);}}catch(e){{}}count();}});count();
          if(form){{form.addEventListener('submit',()=>{{try{{localStorage.removeItem(key);}}catch(e){{}}}});input.addEventListener('keydown',e=>{{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){{e.preventDefault();form.requestSubmit();}}}});}}
        }}
      }})();
      function cyrusReply(button) {{
        document.getElementById("cyrusReplyId").value=button.dataset.id||"";
        document.getElementById("cyrusReplyText").textContent="پاسخ به: "+(button.dataset.content||"").slice(0,120);
        document.getElementById("cyrusReplyBar").style.display="block";
        cyrusCloseMessageMenus(false);
        document.querySelector('.send-box input[name="content"]').focus();
      }}
      function cyrusCancelReply() {{
        document.getElementById("cyrusReplyId").value="";
        document.getElementById("cyrusReplyBar").style.display="none";
      }}
      function cyrusToast(text) {{
        let toast=document.getElementById('cyrus-message-toast');
        if(!toast){{toast=document.createElement('div');toast.id='cyrus-message-toast';toast.setAttribute('role','status');toast.setAttribute('aria-live','polite');toast.style.cssText='position:fixed;left:50%;bottom:92px;transform:translateX(-50%);z-index:100;background:#13283a;border:1px solid #41617a;color:#eaf4fc;padding:10px 16px;border-radius:22px;font-size:12px;box-shadow:0 5px 20px #0007';document.body.appendChild(toast);}}
        toast.textContent=text;toast.hidden=false;clearTimeout(toast._timer);toast._timer=setTimeout(()=>toast.hidden=true,2100);
      }}
      async function cyrusCopy(button) {{
        const value=button.dataset.content||"";
        try {{
          if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(value);
          else{{const area=document.createElement('textarea');area.value=value;area.style.cssText='position:fixed;opacity:0';document.body.appendChild(area);area.select();const ok=document.execCommand('copy');area.remove();if(!ok)throw new Error('copy unavailable');}}
          cyrusToast('متن پیام کپی شد');cyrusCloseMessageMenus(false);
        }}catch(e){{window.prompt('متن پیام را برای کپی انتخاب کنید:',value);}}
      }}
      async function cyrusCopyValue(value,successText) {{
        try {{
          if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(value);
          else{{const area=document.createElement('textarea');area.value=value;area.style.cssText='position:fixed;opacity:0';document.body.appendChild(area);area.select();const ok=document.execCommand('copy');area.remove();if(!ok)throw new Error('copy unavailable');}}
          cyrusToast(successText);return true;
        }}catch(e){{window.prompt('متن را برای کپی انتخاب کنید:',value);return false;}}
      }}
      async function cyrusCopyTimestamp(button) {{
        const value=button.dataset.created||'';
        if(!value)return cyrusToast('زمان پیام در دسترس نیست');
        const date=new Date(value);
        const formatted=Number.isNaN(date.getTime())?value:date.toLocaleString('fa-IR');
        await cyrusCopyValue(formatted,'زمان پیام کپی شد');
        cyrusCloseMessageMenus(false);
      }}
      async function cyrusCopyMessageLink(button) {{
        const id=button.dataset.id||'';
        if(!id)return;
        const link=location.origin+location.pathname+'?message='+encodeURIComponent(id);
        await cyrusCopyValue(link,'پیوند پیام کپی شد');
        cyrusCloseMessageMenus(false);
      }}
      async function cyrusShareMessage(button) {{
        const id=button.dataset.id||'',text=button.dataset.content||'';
        const url=location.origin+location.pathname+'?message='+encodeURIComponent(id);
        try{{if(navigator.share){{await navigator.share({{title:'پیام در CYRUS',text:text,url:url}});cyrusCloseMessageMenus(false);return;}}}}
        catch(e){{if(e&&e.name==='AbortError')return;}}
        await cyrusCopyValue(url,'پیوند پیام برای اشتراک‌گذاری کپی شد');
        cyrusCloseMessageMenus(false);
      }}
      function cyrusJumpToMessage(event,button) {{
        event.preventDefault();event.stopPropagation();
        const id=button.dataset.replyTarget||'';
        const target=id&&document.getElementById('message-'+id);
        if(!target){{cyrusToast('پیام اصلی در این گفتگو موجود نیست');return;}}
        target.scrollIntoView({{behavior:'smooth',block:'center'}});
        target.classList.add('search-jump-highlight');
        clearTimeout(target._cyrusHighlightTimer);
        target._cyrusHighlightTimer=setTimeout(()=>target.classList.remove('search-jump-highlight'),2600);
        cyrusCloseMessageMenus(false);
      }}
      const cyrusSelectedMessages=new Set();
      let cyrusSelectionAnchorId=null;
      function cyrusSelectedMessageTexts() {{
        return [...document.querySelectorAll('.message[data-message-id]')]
          .filter(message=>cyrusSelectedMessages.has(message.dataset.messageId))
          .map(message=>message.dataset.content||'');
      }}
      let cyrusSelectionBar=null;
      function cyrusEnsureSelectionBar() {{
        if(cyrusSelectionBar)return;
        cyrusSelectionBar=document.createElement('div');
        cyrusSelectionBar.className='cyrus-selection-bar';
        cyrusSelectionBar.setAttribute('role','toolbar');
        cyrusSelectionBar.innerHTML='<span class="cyrus-selection-count" aria-live="polite">۰ پیام انتخاب شد</span><button type="button" data-select-all>انتخاب همه</button><button type="button" data-copy>کپی متن‌ها</button><button type="button" data-save>ذخیره منتخب‌ها</button><button type="button" data-delete>حذف پیام‌های من</button><button type="button" data-clear>لغو</button>';
        cyrusSelectionBar.style.cssText='position:fixed;z-index:50;bottom:calc(84px + env(safe-area-inset-bottom));left:12px;right:12px;display:flex;gap:8px;align-items:center;justify-content:center;padding:10px;background:#102033;border:1px solid #42617a;border-radius:18px;box-shadow:0 8px 30px #0008;color:#eaf3fa';
        cyrusSelectionBar.querySelector('[data-copy]').addEventListener('click',async()=>{{
          const texts=cyrusSelectedMessageTexts();
          if(texts.length)await cyrusCopyValue(texts.join('\n\n'),'متن پیام‌های انتخاب‌شده کپی شد');
        }});
        cyrusSelectionBar.querySelector('[data-select-all]').addEventListener('click',()=>{{
          document.querySelectorAll('.message[data-message-id]').forEach(message=>cyrusSelectedMessages.add(message.dataset.messageId));
          cyrusUpdateMessageSelection();
          cyrusToast('همه پیام‌های بارگذاری‌شده انتخاب شدند');
        }});
        cyrusSelectionBar.querySelector('[data-save]').addEventListener('click',()=>{{
          const ids=[...cyrusSelectedMessages];if(!ids.length)return;
          const first=document.querySelector('.message[data-message-id]'),conversationId=first&&first.dataset.conversationId;
          if(!conversationId)return cyrusToast('شناسه گفتگو در دسترس نیست');
          const form=document.createElement('form');form.method='post';form.action='/chat/'+encodeURIComponent(conversationId)+'/save-selected';
          ids.forEach(id=>{{const field=document.createElement('input');field.type='hidden';field.name='message_ids';field.value=id;form.appendChild(field);}});
          document.body.appendChild(form);form.submit();
        }});
        cyrusSelectionBar.querySelector('[data-delete]').addEventListener('click',()=>{{
          const ids=[...cyrusSelectedMessages];
          if(!ids.length||!confirm('پیام‌های انتخاب‌شده‌ای که متعلق به شما هستند حذف شوند؟ پیام‌های دیگران حذف نمی‌شوند.'))return;
          const first=document.querySelector('.message[data-message-id]');
          const conversationId=first&&first.dataset.conversationId;
          if(!conversationId)return cyrusToast('شناسه گفتگو در دسترس نیست');
          const form=document.createElement('form');form.method='post';form.action='/chat/'+encodeURIComponent(conversationId)+'/delete-selected';
          const room=document.createElement('input');room.type='hidden';room.name='conversation_id';room.value=conversationId;form.appendChild(room);
          ids.forEach(id=>{{const field=document.createElement('input');field.type='hidden';field.name='message_ids';field.value=id;form.appendChild(field);}});
          document.body.appendChild(form);form.submit();
        }});
        cyrusSelectionBar.querySelector('[data-clear]').addEventListener('click',cyrusClearMessageSelection);
        document.body.appendChild(cyrusSelectionBar);
      }}
      function cyrusUpdateMessageSelection() {{
        const count=cyrusSelectedMessages.size;
        document.querySelectorAll('.message[data-message-id]').forEach(m=>{{
          const selected=cyrusSelectedMessages.has(m.dataset.messageId);
          m.classList.toggle('cyrus-message-selected',selected);
          m.setAttribute('aria-selected',String(selected));
        }});
        if(!count){{if(cyrusSelectionBar)cyrusSelectionBar.remove();cyrusSelectionBar=null;return;}}
        cyrusEnsureSelectionBar();
        cyrusSelectionBar.querySelector('.cyrus-selection-count').textContent=new Intl.NumberFormat('fa-IR').format(count)+' پیام انتخاب شد';
      }}
      function cyrusToggleMessageSelection(button) {{
        const id=button.dataset.id||'';
        if(!id)return;
        if(cyrusSelectedMessages.has(id))cyrusSelectedMessages.delete(id);else cyrusSelectedMessages.add(id);
        cyrusSelectionAnchorId=id;
        cyrusUpdateMessageSelection();cyrusCloseMessageMenus(false);
      }}
      function cyrusClearMessageSelection() {{
        cyrusSelectedMessages.clear();cyrusSelectionAnchorId=null;cyrusUpdateMessageSelection();
      }}
      document.addEventListener('keydown',event=>{{
        if(event.key==='Escape'&&cyrusSelectedMessages.size)cyrusClearMessageSelection();
        if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='c'&&cyrusSelectedMessages.size) {{
          const active=document.activeElement;
          if(active&&['INPUT','TEXTAREA'].includes(active.tagName))return;
          event.preventDefault();
          const texts=[...cyrusSelectedMessages].map(id=>document.getElementById('message-'+id)).filter(Boolean).map(m=>m.dataset.content||'');
          if(texts.length)cyrusCopyValue(texts.join('\n\n'),'متن پیام‌های انتخاب‌شده کپی شد');
        }}
      }});
      window.addEventListener('scroll',()=>cyrusCloseMessageMenus(false),{{passive:true}});
      window.addEventListener('resize',()=>cyrusCloseMessageMenus(false));
      document.addEventListener('contextmenu',event=>{{
        const message=event.target.closest('.message');
        if(message&&!event.target.closest('.message-context,button,form,a,input,select')){{event.preventDefault();cyrusOpenMessageMenu(event,message);}}
      }});
      document.addEventListener('keydown',event=>{{
        if((event.key==='ContextMenu'||(event.shiftKey&&event.key==='F10'))&&document.activeElement?.classList.contains('message')){{event.preventDefault();cyrusOpenMessageMenu(event,document.activeElement);}}
      }});
      function cyrusShowForward(button) {{
        const form=button.parentElement.querySelector(".forward-form");
        if(form){{form.style.display=form.style.display==="none"?"flex":"none";if(form.style.display!=="none")form.querySelector('select')?.focus();}}
      }}
      function cyrusEdit(button) {{
        const message = button.closest('.message');
        cyrusCloseMessageMenus(false);
        const value = prompt('متن پیام را ویرایش کنید:', message.dataset.content);
        if (value === null || !value.trim()) return;
        const form = message.querySelector('.edit-form');
        form.querySelector('[name="content"]').value = value.trim();
        form.submit();
      }}
      // دریافت نزدیک‌به‌زنده پیام‌های تازه؛ هنگام مخفی بودن صفحه متوقف می‌شود.
      (function(){{
        const endpoint='/chat/{conversation_id}/updates';
        // اعلان اختیاری پیام تازه؛ فعال‌سازی فقط با انتخاب مستقیم کاربر انجام می‌شود.
        let cyrusNotifyEnabled=false;
        try{{
          cyrusNotifyEnabled=localStorage.getItem('cyrus-chat-notifications')==='1';
          if('Notification' in window){{
            const notifyButton=document.createElement('button');
            notifyButton.type='button';
            notifyButton.textContent=cyrusNotifyEnabled?'🔔 اعلان‌ها روشن':'🔕 اعلان‌ها خاموش';
            notifyButton.setAttribute('aria-label','تنظیم اعلان پیام‌های جدید');
            notifyButton.style.cssText='position:fixed;z-index:1200;top:12px;left:12px;border:1px solid #987039;border-radius:18px;padding:7px 11px;background:#101d2b;color:#f3dfb1;font:12px Tahoma;box-shadow:0 3px 12px #0006';
            notifyButton.addEventListener('click',async()=>{{
              if(!cyrusNotifyEnabled){{
                const permission=Notification.permission==='default'?await Notification.requestPermission():Notification.permission;
                if(permission!=='granted'){{notifyButton.textContent='اعلان مجاز نشد';return;}}
                cyrusNotifyEnabled=true;
              }}else cyrusNotifyEnabled=false;
              localStorage.setItem('cyrus-chat-notifications',cyrusNotifyEnabled?'1':'0');
              notifyButton.textContent=cyrusNotifyEnabled?'🔔 اعلان‌ها روشن':'🔕 اعلان‌ها خاموش';
            }});
            document.body.appendChild(notifyButton);
          }}
        }}catch(e){{}}
        const loadedMessages=document.querySelectorAll('.message[data-message-id]');
        let newest=loadedMessages.length?loadedMessages[loadedMessages.length-1].dataset.messageId:'';
        let delay=7000,timer=null,stopped=false;
        function schedule(){{if(stopped||document.hidden)return;clearTimeout(timer);timer=setTimeout(poll,delay);}}
        async function poll(){{
          if(stopped||document.hidden)return schedule();
          try{{
            const response=await fetch(endpoint,{{headers:{{'Accept':'application/json'}},cache:'no-store',credentials:'same-origin'}});
            if(!response.ok)throw new Error('updates unavailable');
            const data=await response.json();
            delay=7000;
            if(data.latest_id&&data.latest_id!==newest){{
              const distance=Math.max(0,document.documentElement.scrollHeight-window.scrollY-window.innerHeight);
              try{{sessionStorage.setItem('cyrus-chat-scroll-distance',String(distance));}}catch(e){{}}
              try{{
                if(cyrusNotifyEnabled&&'Notification' in window&&Notification.permission==='granted'){{
                  const notice=new Notification('پیام تازه در CYRUS',{{body:'در این گفتگو پیام جدیدی دریافت شد.',icon:'/static/cyrus-app-icon.svg',tag:'cyrus-chat-{conversation_id}'}});
                  notice.onclick=()=>{{window.focus();notice.close();}};
                }}
                if(navigator.vibrate)navigator.vibrate([90,45,90]);
              }}catch(e){{}}
              setTimeout(()=>location.reload(),650);return;
            }}
            if(data.latest_id)newest=data.latest_id;
          }}catch(e){{delay=Math.min(30000,Math.round(delay*1.7));}}
          schedule();
        }}
        document.addEventListener('visibilitychange',()=>{{if(document.hidden)clearTimeout(timer);else{{delay=7000;schedule();}}}});
        window.addEventListener('pagehide',()=>{{stopped=true;clearTimeout(timer);}});
        const savedDistance=sessionStorage.getItem('cyrus-chat-scroll-distance');
        if(savedDistance!==null){{
          sessionStorage.removeItem('cyrus-chat-scroll-distance');
          window.addEventListener('load',()=>{{const d=Number(savedDistance);if(Number.isFinite(d))window.scrollTo(0,Math.max(0,document.documentElement.scrollHeight-window.innerHeight-d));}},{{once:true}});
        }}
        schedule();
      }})();
      </script>
      {send_box}
    </div>"""
    jump_id = request.args.get("message", "").strip()
    if jump_id:
        try:
            uuid.UUID(jump_id)
            content += f"""<script>window.addEventListener("load",function(){{var m=document.getElementById("message-{html.escape(jump_id, quote=True)}");if(m){{m.scrollIntoView({{behavior:"smooth",block:"center"}});m.classList.add("search-jump-highlight");setTimeout(function(){{m.classList.remove("search-jump-highlight")}},2600);}}}});</script><style>.search-jump-highlight{{outline:2px solid #e5bd69!important;box-shadow:0 0 0 6px #e5bd6922!important}}</style>"""
        except ValueError:
            pass
    return page(content)


@app.route("/chat/<conversation_id>/updates")
def chat_updates(conversation_id):
    if not session.get("access_token"):
        return app.response_class('{"error":"unauthorized"}', status=401, mimetype="application/json")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return app.response_class('{"error":"invalid_conversation"}', status=400, mimetype="application/json")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"]}
    try:
        member=requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"user_id","conversation_id":"eq."+conversation_id,
                    "user_id":"eq."+str(session.get("user_id") or ""),"limit":"1"},
            headers=headers,timeout=10)
        if not member.ok:
            return app.response_class('{"error":"forbidden"}',status=403,mimetype="application/json")
        if not member.json():
            room=requests.get(URL+"/rest/v1/cyrus_conversations",
                params={"select":"created_by","id":"eq."+conversation_id,"limit":"1"},
                headers=headers,timeout=10)
            if not room.ok or not room.json() or str(room.json()[0].get("created_by") or "")!=str(session.get("user_id") or ""):
                return app.response_class('{"error":"forbidden"}',status=403,mimetype="application/json")
        latest=requests.get(URL+"/rest/v1/cyrus_messages",
            params={"select":"id,created_at","conversation_id":"eq."+conversation_id,
                    "order":"created_at.desc","limit":"1"},
            headers=headers,timeout=10)
        if not latest.ok:
            return app.response_class('{"error":"updates_unavailable"}',status=502,mimetype="application/json")
        row=latest.json()[0] if latest.json() else {}
        payload=__import__("json").dumps({"latest_id":str(row.get("id") or ""),"latest_at":row.get("created_at")},ensure_ascii=False)
        return app.response_class(payload,mimetype="application/json",headers={"Cache-Control":"no-store"})
    except Exception:
        return app.response_class('{"error":"server_error"}',status=502,mimetype="application/json")


@app.route("/chat/<conversation_id>/remove", methods=["POST"])
def remove_chat_from_list(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Prefer": "return=minimal"
    }
    try:
        response = requests.delete(
            URL + "/rest/v1/cyrus_members",
            params={
                "conversation_id": "eq." + conversation_id,
                "user_id": "eq." + str(session.get("user_id") or "")
            },
            headers=headers,
            timeout=20
        )
        if not response.ok:
            return page('<div class="container card"><p>حذف گفتگو انجام نشد؛ دسترسی پایگاه داده را بررسی کنید.</p><a href="/">بازگشت</a></div>'), 400
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502
    return redirect(url_for("home"))


@app.route("/chat/media/<conversation_id>/<owner_id>/<object_name>")
def serve_chat_media(conversation_id, owner_id, object_name):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
        uuid.UUID(owner_id)
    except ValueError:
        return "شناسه فایل نامعتبر است",400
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,180}",object_name):
        return "نام فایل نامعتبر است",400
    current_user=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json"}
    try:
        room=requests.get(URL+"/rest/v1/cyrus_conversations",
            params={"select":"id,type,created_by,is_public","id":"eq."+conversation_id,"limit":"1"},
            headers=headers,timeout=20)
        if not room.ok or not room.json():
            return "گفتگو پیدا نشد",404
        room_data=room.json()[0]
        member=requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"user_id","conversation_id":"eq."+conversation_id,"user_id":"eq."+current_user,"limit":"1"},
            headers=headers,timeout=20)
        allowed=(str(room_data.get("created_by") or "")==current_user or
                 (member.ok and bool(member.json())) or
                 (room_data.get("type")=="channel" and room_data.get("is_public") is True))
        if not allowed:
            return "برای دریافت این فایل به عضویت گفتگو نیاز دارید",403
        object_path=conversation_id+"/"+owner_id+"/"+object_name
        signed=requests.post(URL+"/storage/v1/object/sign/cyrus-chat-files/"+object_path,
            json={"expiresIn":3600},headers=headers,timeout=20)
        if not signed.ok:
            return "لینک امن فایل ایجاد نشد",403
        payload=signed.json() if signed.content else {}
        signed_url=str(payload.get("signedURL") or payload.get("signedUrl") or "")
        if not signed_url:
            return "پاسخ ذخیره‌سازی نامعتبر بود",502
        if signed_url.startswith("/storage/v1/"):
            signed_url=URL+signed_url
        elif signed_url.startswith("/object/"):
            signed_url=URL+"/storage/v1"+signed_url
        elif not signed_url.startswith("http"):
            return "لینک فایل نامعتبر است",502
        return redirect(signed_url,code=302)
    except Exception:
        return "ارتباط با سرور ذخیره‌سازی برقرار نشد",502


def cyrus_media_signature_valid(mime, data):
    """Reject uploads whose bytes do not match their declared safe media type."""
    if not data:
        return False
    if mime == "image/jpeg":
        return data.startswith(b"\\xff\\xd8\\xff")
    if mime == "image/png":
        return data.startswith(b"\\x89PNG\\r\\n\\x1a\\n")
    if mime == "image/webp":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    if mime == "image/gif":
        return data.startswith((b"GIF87a", b"GIF89a"))
    if mime == "video/mp4" or mime == "audio/mp4":
        return len(data) >= 12 and data[4:8] == b"ftyp"
    if mime == "video/webm" or mime == "audio/webm":
        return data.startswith(b"\\x1a\\x45\\xdf\\xa3")
    if mime == "audio/ogg":
        return data.startswith(b"OggS")
    if mime == "audio/mpeg":
        return data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xff and (data[1] & 0xe0) == 0xe0)
    if mime == "application/pdf":
        return data.startswith(b"%PDF-")
    if mime == "text/plain":
        try:
            return b"\\x00" not in data and data.decode("utf-8") is not None
        except UnicodeDecodeError:
            return False
    if mime in ("application/zip",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
                if mime == "application/zip":
                    return bool(names)
                if mime.endswith("wordprocessingml.document"):
                    return "[Content_Types].xml" in names and "word/document.xml" in names
                return "[Content_Types].xml" in names and "xl/workbook.xml" in names
        except (zipfile.BadZipFile, OSError):
            return False
    return False


@app.route("/chat/<conversation_id>/upload", methods=["POST"])
def upload_chat_media(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400
    files = [item for item in request.files.getlist("media") if item and item.filename]
    if not files:
        return "فایلی انتخاب نشده است", 400
    if len(files) > 10:
        return "در هر نوبت حداکثر ۱۰ فایل می‌توانید ارسال کنید", 413
    kind_by_mime = {
        "image/jpeg":"photo","image/png":"photo","image/webp":"photo","image/gif":"photo",
        "video/mp4":"video","video/webm":"video",
        "audio/mpeg":"audio","audio/mp4":"audio","audio/ogg":"audio","audio/webm":"audio",
        "application/pdf":"document","text/plain":"document","application/zip":"document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document":"document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":"document"
    }
    current_user = str(session.get("user_id") or "")
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],
               "Content-Type":"application/json","Prefer":"return=minimal"}
    try:
        room_response=requests.get(URL+"/rest/v1/cyrus_conversations",
            params={"select":"id,type,created_by,member_permissions","id":"eq."+conversation_id,"limit":"1"},
            headers=headers,timeout=20)
        if not room_response.ok or not room_response.json():
            return "گفتگو پیدا نشد",404
        room=room_response.json()[0]
        member_response=requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"role","conversation_id":"eq."+conversation_id,"user_id":"eq."+current_user,"limit":"1"},
            headers=headers,timeout=20)
        if not member_response.ok:
            return "بررسی عضویت ناموفق بود",503
        member_rows=member_response.json()
        is_owner=str(room.get("created_by") or "")==current_user
        role=str(member_rows[0].get("role") or "") if member_rows else ""
        if not is_owner and not member_rows:
            return "عضو این گفتگو نیستید",403
        if room.get("type")=="channel" and not (is_owner or role in ("admin","owner")):
            return "در این کانال اجازه انتشار فایل ندارید",403
        if room.get("type")=="group" and role not in ("owner","admin"):
            permissions=room.get("member_permissions") if isinstance(room.get("member_permissions"),dict) else {}
            if not permissions.get("send_media",True):
                return "ارسال رسانه برای اعضای عادی غیرفعال است",403
        if room.get("type")=="private":
            others=requests.get(URL+"/rest/v1/cyrus_members",
                params={"select":"user_id","conversation_id":"eq."+conversation_id},
                headers=headers,timeout=20)
            if not others.ok:
                return "بررسی گفتگو ناموفق بود",503
            for row in others.json():
                other=str(row.get("user_id") or "")
                if other and other!=current_user:
                    blocked=cyrus_block_status(other,headers)
                    if blocked is None:
                        return "بررسی مسدودسازی ناموفق بود",503
                    if blocked:
                        return "این گفتگو مسدود است",403

        sent_count=0
        failures=[]
        for file in files:
            mime=(file.mimetype or "").lower().split(";")[0].strip()
            if mime not in kind_by_mime:
                failures.append((file.filename,"نوع فایل پشتیبانی نمی‌شود"))
                continue
            data=file.read(20*1024*1024+1)
            if not data or len(data)>20*1024*1024:
                failures.append((file.filename,"حجم فایل باید حداکثر ۲۰ مگابایت باشد"))
                continue
            if not cyrus_media_signature_valid(mime, data):
                failures.append((file.filename,"محتوای فایل با نوع اعلام‌شده سازگار نیست"))
                continue
            filename=Path(file.filename).name[:180]
            safe_name=re.sub(r"[^A-Za-z0-9._-]","_",filename) or "file"
            ext=safe_name.rsplit(".",1)[-1].lower() if "." in safe_name else ""
            ext_map={"jpeg":"jpg","png":"png","webp":"webp","gif":"gif","mp4":"mp4","webm":"webm","mpeg":"mp3","mp3":"mp3","ogg":"ogg","pdf":"pdf","txt":"txt","zip":"zip","docx":"docx","xlsx":"xlsx"}
            mime_ext={"image/jpeg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif","video/mp4":"mp4","video/webm":"webm","audio/mpeg":"mp3","audio/mp4":"m4a","audio/ogg":"ogg","audio/webm":"webm","application/pdf":"pdf","text/plain":"txt","application/zip":"zip","application/vnd.openxmlformats-officedocument.wordprocessingml.document":"docx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":"xlsx"}
            ext=ext_map.get(ext,mime_ext.get(mime,"bin"))
            object_path=conversation_id+"/"+current_user+"/"+str(uuid.uuid4())+"."+ext
            uploaded=requests.post(URL+"/storage/v1/object/cyrus-chat-files/"+object_path,data=data,
                headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":mime,"x-upsert":"false"},timeout=60)
            if not uploaded.ok:
                failures.append((filename,"بارگذاری در فضای ذخیره‌سازی ناموفق بود"))
                continue
            public_url=request.host_url.rstrip("/")+"/chat/media/"+object_path
            message_response=requests.post(URL+"/rest/v1/cyrus_messages",
                json={"conversation_id":conversation_id,"sender_id":current_user,"content":filename,
                      "message_type":kind_by_mime[mime],"attachment_url":public_url,
                      "metadata":{"file_name":filename,"mime_type":mime,"file_size":len(data)}},
                headers=headers,timeout=30)
            if not message_response.ok:
                requests.delete(URL+"/storage/v1/object/cyrus-chat-files/"+object_path,
                    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"]},timeout=20)
                failures.append((filename,"ثبت پیام ناموفق بود"))
                continue
            sent_count+=1
        if sent_count==0:
            detail="؛ ".join(html.escape(name)+": "+html.escape(reason) for name,reason in failures[:3])
            return page('<div class="container card"><h3>ارسال فایل انجام نشد</h3><p>'+detail+'</p><a href="/chat/'+conversation_id+'">بازگشت به گفتگو</a></div>'),400
        if failures:
            flash(str(sent_count)+" فایل ارسال شد؛ "+str(len(failures))+" فایل ارسال نشد.")
        return redirect(url_for("chat",conversation_id=conversation_id))
    except Exception:
        return "ارتباط با سرور برقرار نشد",502


@app.route("/chat/<conversation_id>/send", methods=["POST"])
def send_message(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")

    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400

    message = request.form.get("content", "").strip()
    if not message or len(message) > 4000:
        return redirect(url_for("chat", conversation_id=conversation_id))

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }

    current_user = str(session.get("user_id") or "")

    try:
        room_response = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={
                "select": "id,type,created_by,member_permissions,slow_mode_seconds",
                "id": "eq." + conversation_id,
                "limit": "1"
            },
            headers=headers,
            timeout=20
        )

        if not room_response.ok or not room_response.json():
            return "گفتگو پیدا نشد یا دسترسی ندارید", 403

        room = room_response.json()[0]

        message_metadata = {}
        reply_to_id = str(request.form.get("reply_to_id") or "").strip()
        if reply_to_id:
            try:
                uuid.UUID(reply_to_id)
            except ValueError:
                return "شناسه پیام پاسخ نامعتبر است", 400
            reply_response = requests.get(
                URL + "/rest/v1/cyrus_messages",
                params={"select":"id,conversation_id,content","id":"eq."+reply_to_id,"limit":"1"},
                headers=headers, timeout=15
            )
            if not reply_response.ok or not reply_response.json() or str(reply_response.json()[0].get("conversation_id")) != conversation_id:
                return "پیام پاسخ در این گفتگو پیدا نشد", 400
            replied = reply_response.json()[0]
            message_metadata = {"reply_to_id":reply_to_id,"reply_to_content":str(replied.get("content") or "")[:500]}

        client_nonce = str(request.form.get("client_nonce") or "").strip()
        if client_nonce:
            try:
                client_nonce = str(uuid.UUID(client_nonce))
            except ValueError:
                client_nonce = ""
        if client_nonce:
            message_metadata["client_nonce"] = client_nonce
            # Retry after a weak connection reuses the same nonce; never insert it twice.
            try:
                duplicate_check = requests.get(
                    URL + "/rest/v1/cyrus_messages",
                    params={"select":"id,metadata","conversation_id":"eq."+conversation_id,
                            "sender_id":"eq."+current_user,"order":"created_at.desc","limit":"100"},
                    headers=headers, timeout=15
                )
                if duplicate_check.ok:
                    for existing_message in duplicate_check.json():
                        existing_meta = existing_message.get("metadata") if isinstance(existing_message.get("metadata"),dict) else {}
                        if str(existing_meta.get("client_nonce") or "") == client_nonce:
                            return redirect(url_for("chat", conversation_id=conversation_id))
            except Exception:
                pass

        # Secure pair check sees blocks in either direction without exposing block rows.
        if room.get("type") == "private":
            members_check = requests.get(
                URL + "/rest/v1/cyrus_members",
                params={"select":"user_id", "conversation_id":"eq."+conversation_id},
                headers=headers, timeout=20
            )
            if not members_check.ok:
                return "بررسی وضعیت مسدودسازی ناموفق بود؛ دوباره تلاش کنید.", 503
            other_ids = [str(m.get("user_id") or "") for m in members_check.json()
                         if str(m.get("user_id") or "") != current_user]
            if not other_ids:
                return "عضو دیگر گفتگو پیدا نشد؛ ارسال پیام متوقف شد.", 403
            for other_id in other_ids:
                block_status = cyrus_block_status(other_id, headers)
                if block_status is None:
                    return "بررسی مسدودسازی با سرور انجام نشد؛ پیام ارسال نشد.", 503
                if block_status:
                    return "این گفتگو مسدود است؛ امکان ارسال پیام وجود ندارد.", 403

        # برای گفتگوهای غیرکانال، فرستنده باید عضو گفتگو باشد.
        if room.get("type") != "channel":
            membership = requests.get(
                URL + "/rest/v1/cyrus_members",
                params={
                    "select": "user_id,role,last_message_at",
                    "conversation_id": "eq." + conversation_id,
                    "user_id": "eq." + current_user,
                    "limit": "1"
                },
                headers=headers,
                timeout=20
            )
            if not membership.ok or not membership.json():
                return "شما عضو این گفتگو نیستید", 403
            member_row = membership.json()[0]
            if room.get("type") == "group" and member_row.get("role") not in ("owner", "admin"):
                permissions = room.get("member_permissions") or {}
                if not isinstance(permissions, dict) or not permissions.get("send_messages", True):
                    return "ارسال پیام برای اعضای عادی غیرفعال است", 403
                slow_seconds = int(room.get("slow_mode_seconds") or 0)
                last_message_at = member_row.get("last_message_at")
                if slow_seconds and last_message_at:
                    try:
                        last_dt = datetime.fromisoformat(str(last_message_at).replace("Z", "+00:00"))
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=timezone.utc)
                        remaining = slow_seconds - (datetime.now(timezone.utc) - last_dt.astimezone(timezone.utc)).total_seconds()
                        if remaining > 0:
                            return "حالت آهسته فعال است؛ " + str(int(remaining)) + " ثانیه دیگر پیام بفرستید", 429
                    except (TypeError, ValueError):
                        pass

        if room.get("type") == "channel":
            is_owner = str(room.get("created_by") or "") == current_user
            is_admin = False

            if not is_owner:
                member_response = requests.get(
                    URL + "/rest/v1/cyrus_members",
                    params={
                        "select": "role",
                        "conversation_id": "eq." + conversation_id,
                        "user_id": "eq." + current_user,
                        "limit": "1"
                    },
                    headers=headers,
                    timeout=20
                )

                if not member_response.ok:
                    return "بررسی مجوز ارسال ناموفق بود", 403

                member_rows = member_response.json()
                is_admin = bool(
                    member_rows and
                    member_rows[0].get("role") in ("admin", "owner")
                )

            if not is_owner and not is_admin:
                return "در این کانال فقط مالک یا مدیر اجازه انتشار دارد", 403

        response = requests.post(
            URL + "/rest/v1/cyrus_messages",
            json={
                "conversation_id": conversation_id,
                "sender_id": current_user,
                "content": message,
                "message_type": "text",
                "metadata": message_metadata
            },
            headers=headers,
            timeout=20
        )

        if not response.ok:
            if response.status_code == 409 and client_nonce:
                try:
                    duplicate_check = requests.get(
                        URL + "/rest/v1/cyrus_messages",
                        params={"select":"id,metadata","conversation_id":"eq."+conversation_id,
                                "sender_id":"eq."+current_user,"order":"created_at.desc","limit":"100"},
                        headers=headers, timeout=15
                    )
                    if duplicate_check.ok and any(
                        isinstance(x.get("metadata"),dict) and str(x["metadata"].get("client_nonce") or "") == client_nonce
                        for x in duplicate_check.json()
                    ):
                        return redirect(url_for("chat", conversation_id=conversation_id))
                except Exception:
                    pass
            return page(
                '<div class="container card"><h3>ارسال پیام ناموفق بود</h3><p>'
                + html.escape(response.text[:500])
                + '</p><a href="/chat/' + conversation_id
                + '">بازگشت به گفتگو</a></div>'
            ), 403
        if room.get("type") == "group":
            requests.patch(
                URL + "/rest/v1/cyrus_members",
                params={"conversation_id": "eq." + conversation_id, "user_id": "eq." + current_user},
                json={"last_message_at": datetime.now(timezone.utc).isoformat()},
                headers=headers,
                timeout=15
            )

    except Exception:
        return page(
            '<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'
        ), 502

    return redirect(url_for("chat", conversation_id=conversation_id))



@app.route("/chat/<conversation_id>/mark-unread", methods=["POST"])
def mark_conversation_unread(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400

    uid = str(session.get("user_id") or "")
    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session.get("access_token", ""),
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }
    try:
        membership = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={"select":"conversation_id", "conversation_id":"eq."+conversation_id,
                    "user_id":"eq."+uid, "limit":"1"},
            headers=headers, timeout=15
        )
        if not membership.ok or not membership.json():
            return "عضو این گفتگو نیستید", 403
        updated = requests.patch(
            URL + "/rest/v1/cyrus_members",
            params={"conversation_id":"eq."+conversation_id, "user_id":"eq."+uid},
            json={"last_read_at":"1970-01-01T00:00:00+00:00"},
            headers=headers, timeout=15
        )
        if not updated.ok:
            return "علامت‌گذاری گفتگو انجام نشد", 502
        return redirect(url_for("home"))
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502


@app.route("/chat/<conversation_id>/save-selected", methods=["POST"])
def save_selected_messages(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400
    ids = list(dict.fromkeys(str(x or "").strip() for x in request.form.getlist("message_ids")))
    if not ids or len(ids) > 100:
        return "تعداد پیام‌های انتخاب‌شده نامعتبر است", 400
    valid_ids = []
    for value in ids:
        try:
            valid_ids.append(str(uuid.UUID(value)))
        except ValueError:
            return "شناسه یکی از پیام‌ها نامعتبر است", 400
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],
               "Content-Type":"application/json","Prefer":"return=minimal"}
    try:
        own_id = str(session.get("user_id") or "")
        room = requests.get(URL+"/rest/v1/cyrus_conversations",
            params={"select":"id,title,created_by","id":"eq."+conversation_id,"limit":"1"},
            headers=headers,timeout=15)
        member = requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"user_id","conversation_id":"eq."+conversation_id,"user_id":"eq."+own_id,"limit":"1"},
            headers=headers,timeout=15)
        if not room.ok or not room.json() or (not member.ok or not member.json()) and str((room.json() or [{}])[0].get("created_by") or "") != own_id:
            return "به این گفتگو دسترسی ندارید",403
        found = requests.get(URL+"/rest/v1/cyrus_messages",
            params={"select":"id,content,created_at","conversation_id":"eq."+conversation_id,
                    "id":"in.("+",".join(valid_ids)+")","limit":"100"},
            headers=headers,timeout=20)
        if not found.ok:
            return "دریافت پیام‌های انتخاب‌شده ناموفق بود",502
        title = str(room.json()[0].get("title") or "گفتگو")[:100]
        records = []
        for item in found.json():
            mid = str(item.get("id") or "")
            source = request.host_url.rstrip("/") + url_for("chat",conversation_id=conversation_id) + "?message=" + quote(mid)
            records.append({"user_id":own_id,"content":str(item.get("content") or "")[:10000] + "\n\n— ذخیره‌شده از «" + title + "»\n" + source})
        if not records:
            return "پیامی برای ذخیره پیدا نشد",404
        saved = requests.post(URL+"/rest/v1/cyrus_saved_messages",json=records,
            headers={**headers,"Prefer":"return=minimal"},timeout=30)
        if not saved.ok:
            return "ذخیره پیام‌های انتخاب‌شده انجام نشد",502
        return redirect("/saved-messages")
    except Exception:
        return "ارتباط با سرور برقرار نشد",502


@app.route("/chat/<conversation_id>/delete-selected", methods=["POST"])
def delete_selected_messages(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه گفتگو نامعتبر است", 400
    posted_room = str(request.form.get("conversation_id") or "")
    if posted_room != conversation_id:
        return "گفتگوی انتخاب‌شده معتبر نیست", 400
    message_ids = list(dict.fromkeys(str(value or "").strip() for value in request.form.getlist("message_ids")))
    if not message_ids or len(message_ids) > 100:
        return "تعداد پیام‌های انتخاب‌شده معتبر نیست", 400
    valid_ids=[]
    for message_id in message_ids:
        try:
            uuid.UUID(message_id)
            valid_ids.append(message_id)
        except ValueError:
            continue
    if not valid_ids:
        return "شناسه پیام معتبر نیست", 400
    uid=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session.get("access_token",""),"Prefer":"return=representation"}
    try:
        membership=requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"user_id","conversation_id":"eq."+conversation_id,"user_id":"eq."+uid,"limit":"1"},
            headers=headers,timeout=15)
        if not membership.ok or not membership.json():
            return "عضو این گفتگو نیستید",403
        deleted=0
        for message_id in valid_ids:
            response=requests.delete(URL+"/rest/v1/cyrus_messages",
                params={"id":"eq."+message_id,"conversation_id":"eq."+conversation_id,"sender_id":"eq."+uid},
                headers=headers,timeout=15)
            if not response.ok:
                return page('<div class="container card"><p>حذف گروهی کامل نشد؛ دوباره گفتگو را بررسی کنید.</p><a href="/chat/'+html.escape(conversation_id,quote=True)+'">بازگشت</a></div>'),400
            try:
                deleted+=len(response.json())
            except Exception:
                pass
        return redirect(url_for("chat",conversation_id=conversation_id,deleted=deleted))
    except Exception:
        return "ارتباط با سرور برقرار نشد",502


@app.route("/chat/message/<message_id>/save", methods=["POST"])
def save_chat_message(message_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(message_id)
        conversation_id = str(request.form.get("conversation_id") or "")
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه پیام یا گفتگو نامعتبر است", 400
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],
               "Content-Type":"application/json","Prefer":"return=minimal"}
    try:
        own_id = str(session.get("user_id") or "")
        membership = requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"user_id","conversation_id":"eq."+conversation_id,"user_id":"eq."+own_id,"limit":"1"},
            headers=headers,timeout=15)
        room = requests.get(URL+"/rest/v1/cyrus_conversations",
            params={"select":"id,title,created_by","id":"eq."+conversation_id,"limit":"1"},
            headers=headers,timeout=15)
        if not room.ok or not room.json() or (not membership.ok or not membership.json()) and str((room.json() or [{}])[0].get("created_by") or "") != own_id:
            return "به این گفتگو دسترسی ندارید", 403
        found = requests.get(URL+"/rest/v1/cyrus_messages",
            params={"select":"id,content,created_at","id":"eq."+message_id,"conversation_id":"eq."+conversation_id,"limit":"1"},
            headers=headers,timeout=15)
        if not found.ok or not found.json():
            return "پیام پیدا نشد", 404
        item = found.json()[0]
        title = str(room.json()[0].get("title") or "گفتگو")[:100]
        saved_content = str(item.get("content") or "")[:10000]
        source = request.host_url.rstrip("/") + url_for("chat", conversation_id=conversation_id) + "?message=" + quote(message_id)
        payload = saved_content + "\n\n— ذخیره‌شده از «" + title + "»\n" + source
        saved = requests.post(URL+"/rest/v1/cyrus_saved_messages",
            json={"user_id":own_id,"content":payload},headers=headers,timeout=20)
        if not saved.ok:
            return "ذخیره پیام انجام نشد", 502
        return redirect(url_for("chat",conversation_id=conversation_id))
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502


@app.route("/chat/message/<message_id>/pin", methods=["POST"])
def toggle_message_pin(message_id):
    if not session.get("access_token"):
        return redirect("/login")
    conversation_id = str(request.form.get("conversation_id") or "")
    try:
        uuid.UUID(message_id)
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه پیام یا گفتگو نامعتبر است", 400
    headers = {"apikey": KEY, "Authorization": "Bearer " + session["access_token"],
               "Content-Type": "application/json"}
    try:
        uid = str(session.get("user_id") or "")
        room_response = requests.get(URL + "/rest/v1/cyrus_conversations",
            params={"select":"id,type,created_by,member_permissions","id":"eq."+conversation_id,"limit":"1"},
            headers=headers, timeout=15)
        if not room_response.ok or not room_response.json():
            return "گفتگو پیدا نشد", 404
        room = room_response.json()[0]
        member_response = requests.get(URL + "/rest/v1/cyrus_members",
            params={"select":"role","conversation_id":"eq."+conversation_id,"user_id":"eq."+uid,"limit":"1"},
            headers=headers, timeout=15)
        if not member_response.ok:
            return "بررسی عضویت ناموفق بود", 502
        member_rows = member_response.json()
        is_owner = str(room.get("created_by") or "") == uid
        role = str(member_rows[0].get("role") or "") if member_rows else ""
        if not is_owner and not member_rows:
            return "عضو این گفتگو نیستید", 403
        if room.get("type") == "channel" and not (is_owner or role in ("owner","admin")):
            return "در این کانال اجازه سنجاق پیام ندارید", 403
        if room.get("type") == "group" and not (is_owner or role in ("owner","admin")):
            permissions = room.get("member_permissions") if isinstance(room.get("member_permissions"), dict) else {}
            if not permissions.get("pin_messages", True):
                return "سنجاق پیام برای اعضای عادی غیرفعال است", 403
        found = requests.get(URL + "/rest/v1/cyrus_messages",
            params={"select":"id,conversation_id,metadata","id":"eq."+message_id,"limit":"1"},
            headers=headers, timeout=15)
        if not found.ok or not found.json() or str(found.json()[0].get("conversation_id")) != conversation_id:
            return "پیام پیدا نشد", 404
        meta = found.json()[0].get("metadata") if isinstance(found.json()[0].get("metadata"), dict) else {}
        pin = not bool(meta.get("pinned"))
        result = requests.post(URL + "/rest/v1/rpc/cyrus_pin_message",
            json={"p_conversation_id":conversation_id,"p_message_id":message_id,"p_pin":pin},
            headers=headers, timeout=20)
        if not result.ok:
            return page('<div class="container card"><h3>سنجاق پیام انجام نشد</h3><p>' +
                html.escape(result.text[:400]) + '</p><a href="/chat/' +
                html.escape(conversation_id, quote=True) + '">بازگشت</a></div>'), 403
        return redirect(url_for("chat", conversation_id=conversation_id))
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502


@app.route("/chat/message/<message_id>/forward", methods=["POST"])
def forward_message(message_id):
    if not session.get("access_token"):
        return redirect("/login")
    destination=str(request.form.get("conversation_id") or "")
    current_user=str(session.get("user_id") or "")
    try:
        uuid.UUID(message_id); uuid.UUID(destination)
    except ValueError:
        return "شناسه پیام یا مقصد نامعتبر است", 400
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],
             "Content-Type":"application/json","Prefer":"return=minimal"}
    try:
        source=requests.get(URL+"/rest/v1/cyrus_messages",
            params={"select":"id,conversation_id,content,message_type","id":"eq."+message_id,"limit":"1"},
            headers=headers,timeout=15)
        if not source.ok or not source.json():
            return "پیام مبدأ پیدا نشد",404
        original=source.json()[0]
        dest=requests.get(URL+"/rest/v1/cyrus_conversations",
            params={"select":"id,type,created_by,member_permissions,slow_mode_seconds","id":"eq."+destination,"limit":"1"},
            headers=headers,timeout=15)
        if not dest.ok or not dest.json():
            return "گفتگوی مقصد پیدا نشد",404
        room=dest.json()[0]
        member=requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"role,last_message_at","conversation_id":"eq."+destination,"user_id":"eq."+current_user,"limit":"1"},
            headers=headers,timeout=15)
        if not member.ok or not member.json():
            return "عضو گفتگوی مقصد نیستید",403
        member_row=member.json()[0]
        member_role=str(member_row.get("role") or "")
        is_owner=str(room.get("created_by") or "")==current_user
        if room.get("type")=="channel" and not is_owner and member_role not in ("admin","owner"):
            return "در این کانال اجازه انتشار ندارید",403
        if room.get("type")=="group" and not is_owner and member_role not in ("admin","owner"):
            permissions=room.get("member_permissions") if isinstance(room.get("member_permissions"),dict) else {}
            if not permissions.get("send_messages",True):
                return "ارسال پیام برای اعضای عادی غیرفعال است",403
            slow_seconds=int(room.get("slow_mode_seconds") or 0)
            last_message_at=member_row.get("last_message_at")
            if slow_seconds and last_message_at:
                try:
                    last_dt=datetime.fromisoformat(str(last_message_at).replace("Z","+00:00"))
                    if last_dt.tzinfo is None:
                        last_dt=last_dt.replace(tzinfo=timezone.utc)
                    remaining=slow_seconds-(datetime.now(timezone.utc)-last_dt.astimezone(timezone.utc)).total_seconds()
                    if remaining>0:
                        return "حالت آهسته فعال است؛ "+str(int(remaining))+" ثانیه دیگر می‌توانید پیام را انتقال دهید",429
                except (TypeError,ValueError):
                    pass
        if room.get("type")=="private":
            others=requests.get(URL+"/rest/v1/cyrus_members",
                params={"select":"user_id","conversation_id":"eq."+destination},
                headers=headers,timeout=15)
            if others.ok:
                for m in others.json():
                    other=str(m.get("user_id") or "")
                    if other and other!=current_user:
                        blocked=requests.get(URL+"/rest/v1/cyrus_user_blocks",
                            params={"select":"blocker_id","blocker_id":"eq."+current_user,"blocked_id":"eq."+other,"limit":"1"},
                            headers=headers,timeout=15)
                        if blocked.ok and blocked.json():
                            return "این کاربر را مسدود کرده‌اید؛ امکان ارسال پیام نیست.",403
                        reverse_blocked=requests.get(URL+"/rest/v1/cyrus_user_blocks",
                            params={"select":"blocker_id","blocker_id":"eq."+other,"blocked_id":"eq."+current_user,"limit":"1"},
                            headers=headers,timeout=15)
                        if reverse_blocked.ok and reverse_blocked.json():
                            return "این کاربر شما را مسدود کرده است؛ امکان ارسال پیام نیست.",403
        saved=requests.post(URL+"/rest/v1/cyrus_messages",
            json={"conversation_id":destination,"sender_id":current_user,
                  "content":str(original.get("content") or ""),
                  "message_type":str(original.get("message_type") or "text"),
                  "metadata":{"forwarded_from_message_id":message_id,"forwarded_from_conversation_id":str(original.get("conversation_id") or "")}},
            headers=headers,timeout=20)
        if not saved.ok:
            return "انتقال پیام ناموفق بود",403
        if room.get("type")=="group":
            requests.patch(URL+"/rest/v1/cyrus_members",
                params={"conversation_id":"eq."+destination,"user_id":"eq."+current_user},
                json={"last_message_at":datetime.now(timezone.utc).isoformat()},
                headers={**headers,"Prefer":"return=minimal"},timeout=15)
        return redirect(url_for("chat",conversation_id=destination))
    except Exception:
        return "ارتباط با سرور برقرار نشد",502


@app.route("/chat/message/<message_id>/react", methods=["POST"])
def react_message(message_id):
    if not session.get("access_token"):
        return Response('{"error":"unauthorized"}',status=401,mimetype="application/json")
    conversation_id=str(request.form.get("conversation_id") or "").strip()
    emoji=str(request.form.get("emoji") or "").strip()
    allowed={"❤️","👍","👎","🔥","🥰","👏","🇮🇷","😂","😮","😢"}
    try:
        uuid.UUID(message_id); uuid.UUID(conversation_id)
    except ValueError:
        return Response('{"error":"invalid id"}',status=400,mimetype="application/json")
    if emoji not in allowed:
        return Response('{"error":"invalid emoji"}',status=400,mimetype="application/json")
    uid=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json","Prefer":"return=representation"}
    try:
        member=requests.get(URL+"/rest/v1/cyrus_members",params={"select":"role","conversation_id":"eq."+conversation_id,"user_id":"eq."+uid,"limit":"1"},headers=headers,timeout=15)
        if not member.ok or not member.json():
            return Response('{"error":"not a member"}',status=403,mimetype="application/json")
        message=requests.get(URL+"/rest/v1/cyrus_messages",params={"select":"id","id":"eq."+message_id,"conversation_id":"eq."+conversation_id,"limit":"1"},headers=headers,timeout=15)
        if not message.ok or not message.json():
            return Response('{"error":"message not found"}',status=404,mimetype="application/json")
        existing=requests.get(URL+"/rest/v1/cyrus_message_reactions",params={"select":"emoji","message_id":"eq."+message_id,"user_id":"eq."+uid,"limit":"1"},headers=headers,timeout=15)
        if not existing.ok:
            return Response('{"error":"reaction lookup failed"}',status=502,mimetype="application/json")
        if existing.json() and str(existing.json()[0].get("emoji") or "")==emoji:
            deleted=requests.delete(URL+"/rest/v1/cyrus_message_reactions",params={"message_id":"eq."+message_id,"user_id":"eq."+uid},headers=headers,timeout=15)
            if not deleted.ok:
                return Response('{"error":"reaction delete failed"}',status=502,mimetype="application/json")
            return Response(__import__("json").dumps({"removed":True,"count":0}),mimetype="application/json")
        previous_emoji = str(existing.json()[0].get("emoji") or "") if existing.json() else ""
        if existing.json():
            requests.delete(URL+"/rest/v1/cyrus_message_reactions",params={"message_id":"eq."+message_id,"user_id":"eq."+uid},headers=headers,timeout=15)
        inserted=requests.post(URL+"/rest/v1/cyrus_message_reactions",json={"message_id":message_id,"conversation_id":conversation_id,"user_id":uid,"emoji":emoji},headers=headers,timeout=15)
        if not inserted.ok:
            return Response('{"error":"reaction save failed"}',status=502,mimetype="application/json")
        count=requests.get(URL+"/rest/v1/cyrus_message_reactions",params={"select":"user_id","message_id":"eq."+message_id,"emoji":"eq."+emoji},headers=headers,timeout=15)
        total=len(count.json()) if count.ok else 1
        previous_count=0
        if previous_emoji:
            old_count=requests.get(URL+"/rest/v1/cyrus_message_reactions",params={"select":"user_id","message_id":"eq."+message_id,"emoji":"eq."+previous_emoji},headers=headers,timeout=15)
            previous_count=len(old_count.json()) if old_count.ok else 0
        return Response(__import__("json").dumps({"removed":False,"count":total,"previous":previous_emoji,"previous_count":previous_count}),mimetype="application/json")
    except Exception:
        return Response('{"error":"server error"}',status=502,mimetype="application/json")


@app.route("/chat/message/<message_id>/edit", methods=["POST"])
def edit_message(message_id):
    if not session.get("access_token"):
        return redirect("/login")

    conversation_id = request.form.get("conversation_id", "")
    content = request.form.get("content", "").strip()

    try:
        uuid.UUID(message_id)
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه پیام یا گفتگو نامعتبر است", 400

    if not content or len(content) > 4000:
        return redirect(url_for("chat", conversation_id=conversation_id))

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    try:
        response = requests.patch(
            URL + "/rest/v1/cyrus_messages",
            params={
                "id": "eq." + message_id,
                "sender_id": "eq." + str(session.get("user_id") or "")
            },
            json={
                "content": content,
                "edited_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            },
            headers=headers,
            timeout=20
        )
        if not response.ok:
            return page(
                '<div class="container card"><p>ویرایش انجام نشد: '
                + html.escape(response.text[:400])
                + '</p><a href="/chat/' + conversation_id + '">بازگشت</a></div>'
            ), 400
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502

    return redirect(url_for("chat", conversation_id=conversation_id))


@app.route("/chat/message/<message_id>/delete", methods=["POST"])
def delete_message(message_id):
    if not session.get("access_token"):
        return redirect("/login")

    conversation_id = request.form.get("conversation_id", "")
    try:
        uuid.UUID(message_id)
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه پیام یا گفتگو نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Prefer": "return=minimal"
    }

    try:
        response = requests.delete(
            URL + "/rest/v1/cyrus_messages",
            params={
                "id": "eq." + message_id,
                "sender_id": "eq." + str(session.get("user_id") or "")
            },
            headers=headers,
            timeout=20
        )
        if not response.ok:
            return page(
                '<div class="container card"><p>حذف انجام نشد: '
                + html.escape(response.text[:400])
                + '</p><a href="/chat/' + conversation_id + '">بازگشت</a></div>'
            ), 400
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502

    return redirect(url_for("chat", conversation_id=conversation_id))


def cyrus_channel_member_picker(title, room_type="channel", error=""):
    uid = str(session.get("user_id") or "")
    headers = {"apikey":KEY,"Authorization":"Bearer "+session.get("access_token","")}
    contacts = []
    try:
        cr = requests.get(URL+"/rest/v1/cyrus_contacts",params={"select":"contact_user_id,contact_name","owner_id":"eq."+uid,"order":"created_at.desc","limit":"1000"},headers=headers,timeout=20)
        if cr.ok:
            contact_rows=cr.json()
            ids=list(dict.fromkeys(str(x.get("contact_user_id") or "") for x in contact_rows if x.get("contact_user_id")))
            profiles={}
            if ids:
                pr=requests.get(URL+"/rest/v1/cyrus_profiles",params={"select":"id,username,display_name","id":"in.("+",".join(ids)+")"},headers=headers,timeout=20)
                if pr.ok: profiles={str(x.get("id")):x for x in pr.json() if isinstance(x,dict)}
            for row in contact_rows:
                cid=str(row.get("contact_user_id") or "")
                p=profiles.get(cid)
                if p: contacts.append((cid,str(row.get("contact_name") or p.get("display_name") or p.get("username") or "کاربر"),str(p.get("username") or "")))
    except Exception: pass
    rows=""
    for cid,name,username in contacts:
        rows+='<label class="channel-contact"><input type="checkbox" name="member_ids" value="'+html.escape(cid,quote=True)+'"><span><b>'+html.escape(name)+'</b><small>@'+html.escape(username)+'</small></span></label>'
    if not rows: rows='<p class="muted">مخاطب ذخیره‌شده‌ای پیدا نشد؛ ابتدا افراد را به مخاطبان اضافه کن.</p>'
    safe_title=html.escape(title,quote=True)
    safe_type=room_type if room_type in ("group","channel") else "channel"
    kind="گروه" if safe_type=="group" else "کانال"
    create_action="create_group" if safe_type=="group" else "create_channel"
    content=f"""
    <main class="container card channel-member-picker"><style>
    .channel-member-picker{{margin:12px;padding:14px;background:#101b28;border:1px solid #263b50;border-radius:16px}}
    .channel-member-picker h2{{font-size:18px;margin:5px 0 8px}}
    .channel-member-picker .channel-contact{{display:flex;align-items:center;gap:12px;padding:12px 4px;border-bottom:1px solid #263442;color:#eaf0f5}}
    .channel-member-picker .channel-contact input{{width:20px;height:20px;margin:0;accent-color:#248bd0;flex:0 0 20px}}
    .channel-member-picker .channel-contact span{{display:flex;flex-direction:column;gap:4px}}
    .channel-member-picker .channel-contact small{{direction:ltr;text-align:right;color:#8ea5b9;font-size:11px}}
    .channel-member-picker .picker-list{{max-height:55vh;overflow:auto}}</style>
    <h2>انتخاب اعضای {kind}</h2><p class="muted">{safe_title} · در آغاز حداکثر ۱۰۰ مخاطب</p><p class="error">{html.escape(error)}</p>
    <form method="post" action="/rooms/create" id="channel-members-form">
    <input type="hidden" name="title" value="{safe_title}"><input type="hidden" name="type" value="{safe_type}"><input type="hidden" name="action" value="{create_action}">
    <div class="picker-list">{rows}</div><p class="muted" id="channel-member-count">۰ نفر انتخاب شده‌اند</p><button type="submit">ساخت {kind} و افزودن اعضا</button></form>
    <script>(function(){{const f=document.getElementById('channel-members-form'),b=[...f.querySelectorAll('input[name="member_ids"]')],l=document.getElementById('channel-member-count');function u(){{const n=b.filter(x=>x.checked).length;l.textContent=n+' نفر انتخاب شده‌اند';b.forEach(x=>x.disabled=!x.checked&&n>=100)}}b.forEach(x=>x.addEventListener('change',u));f.addEventListener('submit',e=>{{if(b.filter(x=>x.checked).length>100){{e.preventDefault();alert('حداکثر ۱۰۰ مخاطب را انتخاب کن')}}}});u()}})();</script></main>"""
    return page(content)


def create_room_page(error=""):
    selected=request.args.get("type","group")
    if selected not in ("group","channel"): selected="group"
    content=f"""
    <main class="container cyrus-create-room">
      <style>
        .cyrus-create-room{{min-height:calc(100dvh - 76px);padding:0;background:#0d1722}}
        .cyrus-create-top{{height:56px;display:flex;align-items:center;gap:14px;padding:0 16px;background:#172331;border-bottom:1px solid #263442;color:#eef4f8}}
        .cyrus-create-top a{{font-size:27px;color:#eef4f8}}
        .cyrus-create-top b{{font-size:16px;font-weight:600}}
        .cyrus-create-body{{padding:24px 18px}}
        .cyrus-create-body h2{{font-size:20px;margin:0 0 8px;color:#f1f5f8}}
        .cyrus-create-body p{{font-size:13px;line-height:1.8;color:#91a8ba;margin:0 0 22px}}
        .cyrus-create-body input[name=title]{{display:block;width:100%;box-sizing:border-box;padding:14px;margin:0 0 22px;background:#111e2b;border:1px solid #31475a;border-radius:10px;color:#f1f5f8;font:inherit}}
        .cyrus-create-choice{{display:flex;align-items:center;gap:13px;padding:15px 13px;margin:10px 0;background:#111e2b;border:1px solid #263442;border-radius:12px;color:#eaf1f6;cursor:pointer}}
        .cyrus-create-choice input{{width:20px;height:20px;accent-color:#248bd2}}
        .cyrus-create-choice span{{display:flex;flex-direction:column;gap:5px}}
        .cyrus-create-choice small{{color:#91a8ba;font-size:12px;line-height:1.6}}
        .cyrus-create-body button{{width:100%;margin:18px 0 0;padding:14px;border:0;border-radius:10px;background:#248bd2;color:#fff;font:inherit}}
      </style>
      <div class="cyrus-create-top"><a href="/contacts" aria-label="بازگشت">‹</a><b>ساخت گروه یا کانال</b></div>
      <form class="cyrus-create-body" method="post" action="/rooms/create">
        <h2>نام و نوع مجموعه</h2><p>ابتدا نام و نوع را انتخاب کن؛ در مرحله بعد می‌توانی مخاطبان را اضافه کنی.</p>
        <input name="title" minlength="2" maxlength="60" placeholder="نام گروه یا کانال" required>
        <label class="cyrus-create-choice"><input type="radio" name="type" value="group" {"checked" if selected=="group" else ""}><span><b>گروه جدید</b><small>گفتگوی چندنفره با امکان ارسال پیام اعضا طبق مجوزها</small></span></label>
        <label class="cyrus-create-choice"><input type="radio" name="type" value="channel" {"checked" if selected=="channel" else ""}><span><b>کانال جدید</b><small>انتشار پیام توسط مالک و مدیران؛ اعضا دنبال‌کننده هستند</small></span></label>
        <p class="error">{html.escape(error)}</p><button type="submit">ادامه</button>
      </form>
    </main>"""
    return page(content)


@app.route("/rooms/create", methods=["GET","POST"])
def create_room():
    if not session.get("access_token"): return redirect("/login")
    if request.method=="GET": return create_room_page()
    title=request.form.get("title","").strip()
    room_type=request.form.get("type","").strip()
    action=request.form.get("action","")
    if not 2<=len(title)<=60: return create_room_page("نام باید بین ۲ تا ۶۰ حرف باشد"),400
    if room_type not in ("group","channel"): return create_room_page("نوع مجموعه نامعتبر است"),400
    expected_action="create_channel" if room_type=="channel" else "create_group"
    if action!=expected_action:
        return cyrus_channel_member_picker(title,room_type)
    member_ids=request.form.getlist("member_ids")
    if len(member_ids)>100: return cyrus_channel_member_picker(title,room_type,"حداکثر ۱۰۰ مخاطب را انتخاب کن"),400
    uid=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json"}
    if member_ids:
        try:
            cr=requests.get(URL+"/rest/v1/cyrus_contacts",params={"select":"contact_user_id","owner_id":"eq."+uid,"contact_user_id":"in.("+",".join(member_ids)+")"},headers=headers,timeout=20)
            valid={str(x.get("contact_user_id")) for x in cr.json()} if cr.ok else set()
            if len(valid)!=len(set(member_ids)): return cyrus_channel_member_picker(title,room_type,"فقط مخاطبان ذخیره‌شده را می‌توان در شروع اضافه کرد"),400
        except Exception: return cyrus_channel_member_picker(title,room_type,"بررسی مخاطبان انجام نشد؛ دوباره تلاش کن"),502
    try:
        response=requests.post(URL+"/rest/v1/rpc/create_cyrus_room",json={"room_title":title,"room_type":room_type},headers=headers,timeout=20)
        if not response.ok: return cyrus_channel_member_picker(title,room_type,"ساخت انجام نشد؛ دسترسی پایگاه داده را بررسی کنید"),502
        result=response.json()
        if isinstance(result,list) and result: result=result[0]
        if isinstance(result,dict): result=result.get("create_cyrus_room") or result.get("id")
        room_id=str(uuid.UUID(str(result)))
        failed=[]
        for member_id in dict.fromkeys(member_ids):
            added=requests.post(URL+"/rest/v1/rpc/cyrus_manage_add_member",json={"p_conversation_id":room_id,"p_user_id":member_id},headers=headers,timeout=15)
            if not added.ok: failed.append(member_id)
        if failed: return page('<div class="container card"><p>'+("گروه" if room_type=="group" else "کانال")+' ساخته شد، اما افزودن بعضی مخاطبان ناموفق بود.</p><a href="/rooms/'+room_id+'/manage">مدیریت اعضا</a><a href="/chat/'+room_id+'">باز کردن مجموعه</a></div>'),502
        return redirect(url_for("chat",conversation_id=room_id))
    except Exception: return cyrus_channel_member_picker(title,room_type,"ارتباط با سرور برقرار نشد یا پاسخ نامعتبر بود"),502


@app.route("/rooms/<conversation_id>/add-member", methods=["POST"])
def add_room_member(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json"
    }
    username = request.form.get("username", "").strip().lstrip("@")
    if not username or len(username) > 40:
        return "نام کاربری نامعتبر است", 400
    try:
        room_response = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={"select":"id,type,created_by,member_permissions","id":"eq."+conversation_id,"limit":"1"},
            headers=headers, timeout=20
        )
        if not room_response.ok or not room_response.json():
            return "گروه یا کانال پیدا نشد", 404
        room = room_response.json()[0]
        if room.get("type") not in ("group", "channel"):
            return "این گفتگو گروه یا کانال نیست", 400
        current = str(session.get("user_id") or "")
        member_response = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={"select":"role","conversation_id":"eq."+conversation_id,"user_id":"eq."+current,"limit":"1"},
            headers=headers, timeout=20
        )
        member_rows = member_response.json() if member_response.ok else []
        role = str(member_rows[0].get("role") or "") if member_rows else ""
        owner = str(room.get("created_by") or "") == current
        permissions = room.get("member_permissions") if isinstance(room.get("member_permissions"),dict) else {}
        can_add = owner or role in ("owner","admin") or (room.get("type") == "group" and bool(permissions.get("add_members",False)))
        if not can_add:
            return "اجازه افزودن عضو ندارید", 403
        profile_response = requests.get(
            URL + "/rest/v1/cyrus_profiles",
            params={"select":"id","username":"eq."+username,"limit":"1"},
            headers=headers, timeout=20
        )
        if not profile_response.ok or not profile_response.json():
            return "نام کاربری پیدا نشد", 404
        target_id = str(profile_response.json()[0].get("id") or "")
        if not target_id or target_id == current:
            return "افزودن خودتان امکان‌پذیر نیست", 400
        result = requests.post(
            URL + "/rest/v1/rpc/cyrus_manage_add_member",
            json={"p_conversation_id":conversation_id,"p_user_id":target_id},
            headers=headers, timeout=20
        )
        if not result.ok:
            return page('<div class="container card"><h3>افزودن عضو انجام نشد</h3><p>'+html.escape(result.text[:350])+'</p><a href="/rooms/'+html.escape(conversation_id,quote=True)+'/manage">بازگشت</a></div>'), 400
        return redirect(url_for("manage_room",conversation_id=conversation_id))
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502


@app.route("/rooms/<conversation_id>/manage", methods=["GET", "POST"])
def manage_room(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")

    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json"
    }
    current = str(session.get("user_id") or "")

    try:
        rr = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={
                "select": "id,title,type,created_by,description,avatar_url,invite_code,reactions_enabled,is_public,join_approval,history_visible,slow_mode_seconds,topics_enabled,sign_messages,member_permissions",
                "id": "eq." + conversation_id,
                "limit": "1"
            },
            headers=headers, timeout=20
        )
        if not rr.ok or not rr.json():
            return "گروه یا کانال پیدا نشد", 404

        room = rr.json()[0]
        room_type = room.get("type")
        if room_type not in ("group", "channel"):
            return "این گفتگو گروه یا کانال نیست", 400

        owner = str(room.get("created_by") or "") == current

        mr = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={
                "select": "user_id,role",
                "conversation_id": "eq." + conversation_id
            },
            headers=headers, timeout=20
        )
        if not mr.ok:
            return "دریافت اعضا ناموفق بود", 502

        members = mr.json()
        member_profiles = {}
        member_ids_for_profiles = list(dict.fromkeys(str(m.get("user_id") or "") for m in members if m.get("user_id")))
        if member_ids_for_profiles:
            try:
                profiles_response = requests.get(
                    URL + "/rest/v1/cyrus_profiles",
                    params={"select":"id,username,display_name,avatar_url","id":"in.(" + ",".join(member_ids_for_profiles) + ")"},
                    headers=headers, timeout=20
                )
                if profiles_response.ok:
                    member_profiles = {str(p.get("id")):p for p in profiles_response.json() if isinstance(p,dict)}
            except Exception:
                member_profiles = {}
        my_role = next(
            (m.get("role") for m in members
             if str(m.get("user_id")) == current), None
        )
        if not owner and my_role not in ("owner", "admin"):
            return "فقط مالک یا مدیر اجازه مدیریت دارد", 403

        join_requests = []
        if room_type in ("group", "channel"):
            try:
                jr = requests.post(
                    URL + "/rest/v1/rpc/cyrus_manage_list_join_requests",
                    json={"p_conversation_id": conversation_id},
                    headers=headers, timeout=15
                )
                if jr.ok and isinstance(jr.json(), list):
                    join_requests = jr.json()
            except Exception:
                join_requests = []

        if request.method == "POST":
            action = request.form.get("action", "")
            data = {"p_conversation_id": conversation_id}
            rpc = None

            if action == "save_settings":
                title = request.form.get("title", "").strip()
                description = request.form.get("description", "").strip()
                avatar_url = request.form.get("avatar_url", "").strip()
                reactions = request.form.get("reactions_enabled") == "on"
                is_public = request.form.get("is_public") == "on"
                join_approval = request.form.get("join_approval") == "on"
                history_visible = request.form.get("history_visible") == "on"
                topics_enabled = request.form.get("topics_enabled") == "on"
                sign_messages = request.form.get("sign_messages") == "on"
                try:
                    slow_mode_seconds = int(request.form.get("slow_mode_seconds", "0"))
                except ValueError:
                    slow_mode_seconds = -1
                member_permissions = {
                    "send_messages": request.form.get("perm_send_messages") == "on",
                    "send_media": request.form.get("perm_send_media") == "on",
                    "add_members": request.form.get("perm_add_members") == "on",
                    "pin_messages": request.form.get("perm_pin_messages") == "on",
                    "change_info": request.form.get("perm_change_info") == "on"
                }

                if not 2 <= len(title) <= 60:
                    return "نام باید بین ۲ تا ۶۰ حرف باشد", 400
                if len(description) > 500:
                    return "توضیحات حداکثر ۵۰۰ حرف باشد", 400
                if len(avatar_url) > 500:
                    return "آدرس تصویر بیش از حد طولانی است", 400
                if slow_mode_seconds not in (0, 10, 30, 60, 300, 900, 3600):
                    return "مدت حالت آهسته نامعتبر است", 400

                rpc = "cyrus_manage_update_room_settings"
                data.update({
                    "p_title": title,
                    "p_description": description,
                    "p_avatar_url": avatar_url or None,
                    "p_reactions_enabled": reactions,
                    "p_is_public": is_public,
                    "p_join_approval": join_approval,
                    "p_history_visible": history_visible,
                    "p_slow_mode_seconds": slow_mode_seconds,
                    "p_topics_enabled": topics_enabled,
                    "p_sign_messages": sign_messages,
                    "p_member_permissions": member_permissions
                })

            elif action == "rotate_invite":
                rpc = "cyrus_manage_rotate_invite"

            elif action in ("approve_request", "decline_request"):
                uid = request.form.get("user_id", "")
                try:
                    uuid.UUID(uid)
                except ValueError:
                    return "شناسه درخواست نامعتبر است", 400
                rpc = "cyrus_manage_review_join_request"
                data["p_user_id"] = uid
                data["p_approve"] = action == "approve_request"

            elif action == "add":
                username = request.form.get("username", "").strip()
                pr = requests.get(
                    URL + "/rest/v1/cyrus_profiles",
                    params={
                        "select": "id,username",
                        "username": "eq." + username,
                        "limit": "1"
                    },
                    headers=headers, timeout=20
                )
                if not pr.ok or not pr.json():
                    return "نام کاربری پیدا نشد", 404
                rpc = "cyrus_manage_add_member"
                data["p_user_id"] = pr.json()[0]["id"]

            elif action in ("remove", "promote", "demote"):
                uid = request.form.get("user_id", "")
                try:
                    uuid.UUID(uid)
                except ValueError:
                    return "شناسه عضو نامعتبر است", 400
                if uid == current:
                    return "برای خروج از گفتگو از گزینه ترک گروه استفاده کنید", 400
                target_member = next((m for m in members if str(m.get("user_id") or "") == uid), None)
                if not target_member:
                    return "عضو موردنظر در این گفتگو نیست", 404
                target_role = str(target_member.get("role") or "member")
                if target_role == "owner" or uid == str(room.get("created_by") or ""):
                    return "امکان تغییر یا حذف مالک وجود ندارد؛ ابتدا مالکیت منتقل شود", 403

                data["p_user_id"] = uid
                if action == "remove":
                    # An administrator may remove ordinary members only.
                    if not owner and target_role != "member":
                        return "مدیر فقط اجازه حذف اعضای عادی را دارد", 403
                    rpc = "cyrus_manage_remove_member"
                else:
                    if not owner:
                        return "فقط مالک می‌تواند مدیر تعیین یا عزل کند", 403
                    if action == "promote" and target_role != "member":
                        return "فقط عضو عادی را می‌توان به مدیریت ارتقا داد", 400
                    if action == "demote" and target_role != "admin":
                        return "این کاربر مدیر نیست", 400
                    rpc = "cyrus_manage_set_role"
                    data["p_role"] = "admin" if action == "promote" else "member"

            elif action == "transfer_owner":
                if not owner:
                    return "فقط مالک فعلی می‌تواند مالکیت را منتقل کند", 403
                uid = request.form.get("user_id", "")
                try:
                    uuid.UUID(uid)
                except ValueError:
                    return "شناسه مالک جدید نامعتبر است", 400
                if uid == current:
                    return "انتخاب مالک فعلی امکان‌پذیر نیست", 400
                rpc = "cyrus_manage_transfer_ownership"
                data["p_user_id"] = uid

            elif action == "rename":
                title = request.form.get("title", "").strip()
                if not 2 <= len(title) <= 60:
                    return "نام باید بین ۲ تا ۶۰ حرف باشد", 400
                rpc = "cyrus_manage_rename_room"
                data["p_title"] = title

            elif action == "leave":
                if owner:
                    return "مالک فعلاً نمی‌تواند خارج شود؛ ابتدا مالکیت منتقل شود", 400
                rpc = "cyrus_manage_leave_room"

            elif action == "delete":
                if not owner:
                    return "فقط مالک اجازه حذف دارد", 403
                rpc = "cyrus_manage_delete_room"

            else:
                return "عملیات نامعتبر است", 400

            result = requests.post(
                URL + "/rest/v1/rpc/" + rpc,
                json=data, headers=headers, timeout=20
            )
            if not result.ok:
                return page(
                    '<div class="container card"><h3>عملیات انجام نشد</h3><p>'
                    + html.escape(result.text[:400])
                    + '</p><a href="' + request.url + '">بازگشت</a></div>'
                ), 400

            if action in ("delete", "leave"):
                return redirect("/")

            return redirect(request.url)

        title = html.escape(str(room.get("title") or ""))
        description = html.escape(str(room.get("description") or ""))
        avatar_url = html.escape(str(room.get("avatar_url") or ""), quote=True)
        invite_code = str(room.get("invite_code") or "")
        invite_url = request.host_url.rstrip("/") + "/invite/" + invite_code if invite_code else ""
        invite_safe = html.escape(invite_url, quote=True)
        reactions_checked = "checked" if room.get("reactions_enabled", True) else ""
        public_checked = "checked" if room.get("is_public", False) else ""
        approval_checked = "checked" if room.get("join_approval", False) else ""
        history_checked = "checked" if room.get("history_visible", True) else ""
        topics_checked = "checked" if room.get("topics_enabled", False) else ""
        sign_checked = "checked" if room.get("sign_messages", False) else ""
        permissions = room.get("member_permissions") or {}
        if not isinstance(permissions, dict):
            permissions = {}
        perm_checks = {
            key: ("checked" if permissions.get(key, default) else "")
            for key, default in (("send_messages", True),("send_media", True),("add_members", True),("pin_messages", True),("change_info", False))
        }
        slow_mode = int(room.get("slow_mode_seconds") or 0)
        slow_options = "".join(
            '<option value="' + str(value) + '"' + (" selected" if value == slow_mode else "") + ">" + label + "</option>"
            for value, label in ((0,"خاموش"),(10,"۱۰ ثانیه"),(30,"۳۰ ثانیه"),(60,"۱ دقیقه"),(300,"۵ دقیقه"),(900,"۱۵ دقیقه"),(3600,"۱ ساعت"))
        )
        kind = "گروه" if room_type == "group" else "کانال"
        subtitle = (
            "گفتگوی اعضا و مدیریت گروه"
            if room_type == "group"
            else "انتشار محتوا برای دنبال‌کنندگان کانال"
        )

        rows = ""
        for m in members:
            uid = str(m.get("user_id") or "")
            role = str(m.get("role") or "member")
            safe_uid = html.escape(uid, quote=True)
            safe_role = html.escape({"owner":"مالک","admin":"مدیر","member":"عضو"}.get(role,role))
            profile = member_profiles.get(uid,{})
            display_name = html.escape(str(profile.get("display_name") or profile.get("username") or "کاربر"))
            username_text = html.escape(str(profile.get("username") or ""))
            avatar_source = str(profile.get("avatar_url") or "")
            avatar_html = ('<img class="tg-member-avatar" src="' + html.escape(avatar_source,quote=True) + '" alt="">') if avatar_source else '<span class="tg-member-avatar tg-member-avatar-fallback">♙</span>'

            controls = ""
            if uid != str(room.get("created_by") or ""):
                if owner and role == "member":
                    controls += (
                        '<form method="post" onsubmit="return confirm(&quot;این عضو مدیر شود؟&quot;)"><input type="hidden" name="action" value="promote">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>تعیین مدیر</button></form>'
                    )
                if owner and role == "admin":
                    controls += (
                        '<form method="post" onsubmit="return confirm(&quot;دسترسی مدیریت این عضو برداشته شود؟&quot;)"><input type="hidden" name="action" value="demote">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>عزل مدیر</button></form>'
                    )
                if owner and role in ("member", "admin"):
                    controls += (
                        '<form method="post" onsubmit="return confirm(&quot;با انتقال مالکیت، شما مدیر می‌شوید و این عضو مالک مجموعه خواهد شد. ادامه می‌دهید؟&quot;)">'
                        '<input type="hidden" name="action" value="transfer_owner">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>انتقال مالکیت</button></form>'
                    )
                if owner or (my_role == "admin" and role == "member"):
                    controls += (
                        '<form method="post" onsubmit="return confirm(\'عضو حذف شود؟\')">'
                        '<input type="hidden" name="action" value="remove">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>حذف عضو</button></form>'
                    )

            rows += (
                '<div class="tg-member-row" data-member-search="{html.escape((str(profile.get("display_name") or profile.get("username") or "") + " " + str(profile.get("username") or "")).lower(), quote=True)}" data-member-role="{html.escape(role, quote=True)}"><div class="tg-member-person">' + avatar_html
                + '<span><b>' + display_name + '</b><small>' + ('@' + username_text if username_text else '') + '</small></span></div>'
                + '<div class="tg-member-role">' + safe_role + '</div><div class="tg-member-actions">' + controls + '</div></div>'
            )

        if not rows:
            rows = '<p class="muted">هنوز عضوی وجود ندارد</p>'

        join_request_rows = ""
        for jr in join_requests:
            req_uid = html.escape(str(jr.get("user_id") or ""), quote=True)
            req_name = html.escape(str(jr.get("display_name") or jr.get("username") or "کاربر"))
            req_username = html.escape(str(jr.get("username") or ""))
            join_request_rows += (
                '<div class="card"><p>' + req_name + ' (@' + req_username + ')</p>'
                '<form method="post"><input type="hidden" name="action" value="approve_request">'
                '<input type="hidden" name="user_id" value="' + req_uid + '"><button>تأیید عضویت</button></form>'
                '<form method="post"><input type="hidden" name="action" value="decline_request">'
                '<input type="hidden" name="user_id" value="' + req_uid + '"><button>رد درخواست</button></form></div>'
            )
        if not join_request_rows:
            join_request_rows = '<p class="muted">درخواست عضویت جدیدی نیست</p>'

        content = f"""
        <div class="container">
          <section class="welcome">
            <h2>تنظیمات {kind}</h2>
            <p>{title}</p>
            <p class="muted">{subtitle}</p>
          </section>

          <style>
            .tg-room-settings{{margin:0 0 14px;padding:0;background:#101a25;border:0;border-radius:0;color:#e8edf2;overflow:hidden}}
            .tg-member-row{{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 14px;background:#111e2b;border-bottom:1px solid #263442;color:#eaf1f6}}.cyrus-member-tools{{padding:12px;background:#0e1a26;border-radius:12px;margin:10px 0 14px}}.cyrus-member-tools input{{width:100%;box-sizing:border-box;padding:11px;border-radius:9px;border:1px solid #2b4256;background:#091521;color:#fff}}.cyrus-member-filters{{display:flex;gap:6px;flex-wrap:wrap;margin:9px 0}}.cyrus-member-filters button{{border:0;border-radius:16px;padding:7px 12px;background:#22384b;color:#b8c9d8;font-size:12px}}.cyrus-member-filters button.active{{background:#268bd0;color:#fff}}.cyrus-member-tools small{{color:#8ea5b8;font-size:11px}}.tg-member-row[hidden]{{display:none!important}}.cyrus-field-counter{{display:block;text-align:left;color:#8ea5b8;font-size:10px;margin-top:3px}}
            .tg-member-person{{display:flex;align-items:center;gap:11px;min-width:0;flex:1}}
            .tg-member-avatar{{width:42px;height:42px;flex:0 0 42px;border-radius:50%;object-fit:cover;background:#26394a;display:grid;place-items:center}}
            .tg-member-avatar-fallback{{color:#d8b46a;font-size:21px}}
            .tg-member-person span{{display:flex;flex-direction:column;gap:4px;min-width:0}}
            .tg-member-person b{{font-size:14px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
            .tg-member-person small{{font-size:11px;color:#8ea5b9;direction:ltr;text-align:right}}
            .tg-member-role{{font-size:12px;color:#7eb8e2;white-space:nowrap}}
            .tg-member-actions{{display:flex;flex-wrap:wrap;gap:4px;justify-content:flex-end}}
            .tg-member-actions form{{margin:0}}
            .tg-member-actions button{{padding:7px 9px;margin:0;background:#20384d;border:0;border-radius:7px;color:#8dc9f5;font-size:11px;white-space:nowrap}}

            .tg-room-settings .tg-section-title{{padding:17px 16px 9px;color:#6ab5ee;font-size:14px;font-weight:600}}
            .tg-room-settings .tg-section{{padding:0 16px;border-bottom:8px solid #09131e}}
            .tg-room-settings .tg-field{{display:block;padding:13px 0;border-bottom:1px solid #263442;font-size:14px;color:#e3eaf0}}
            .tg-room-settings .tg-field:last-child{{border-bottom:0}}
            .tg-room-settings .tg-field input[type=text],.tg-room-settings .tg-field input:not([type]),.tg-room-settings .tg-field textarea,.tg-room-settings .tg-field select{{display:block;width:100%;margin:8px 0 0;padding:12px;background:#0a141f;border:1px solid #263b4d;border-radius:9px;color:#f1f5f8;font:inherit}}
            .tg-room-settings .tg-field textarea{{resize:vertical}}
            .tg-room-settings .tg-switch-row{{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:54px;padding:10px 0;border-bottom:1px solid #263442;color:#e2eaf1;font-size:14px}}
            .tg-room-settings .tg-switch-row:last-child{{border-bottom:0}}
            .tg-room-settings .tg-switch{{position:relative;flex:0 0 43px;width:43px;height:26px;border-radius:15px;background:#43515e;transition:background .18s;direction:ltr}}
            .tg-room-settings .tg-switch input{{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;z-index:2}}
            .tg-room-settings .tg-switch i{{position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#f4f6f8;transition:transform .18s}}
            .tg-room-settings .tg-switch:has(input:checked){{background:#248bd2}}
            .tg-room-settings .tg-switch input:checked+i{{transform:translateX(17px)}}
            .tg-room-settings .tg-permissions{{margin:0;background:#101a25}}
            .tg-room-settings .tg-permissions summary{{display:flex;align-items:center;justify-content:space-between;padding:16px;cursor:pointer;list-style:none;color:#e8edf2;font-size:14px}}
            .tg-room-settings .tg-permissions summary::-webkit-details-marker{{display:none}}
            .tg-room-settings .tg-permissions summary .tg-chevron{{color:#7f94a7;transition:transform .18s}}
            .tg-room-settings .tg-permissions[open] summary .tg-chevron{{transform:rotate(180deg)}}
            .tg-room-settings .tg-permissions-body{{padding:0 16px 10px}}
            .tg-room-settings .tg-save{{position:fixed;left:14px;bottom:calc(12px + env(safe-area-inset-bottom));z-index:25;width:auto;min-width:150px;margin:0;padding:13px 20px;border:0;border-radius:24px;background:#248bd2;color:white;font-size:14px;font-weight:600;box-shadow:0 5px 18px #0006}}\n            .tg-room-settings .tg-save:disabled{{background:#253747;color:#8193a2;box-shadow:none;opacity:.75}}\n            .tg-manage-topbar{{height:58px;display:flex;align-items:center;gap:12px;padding:0 14px;background:#172331;border-bottom:1px solid #263442}}\n            .tg-manage-topbar a{{width:38px;height:38px;display:grid;place-items:center;border-radius:50%;color:#eaf2f8;font-size:25px;background:#203243}}\n            .tg-manage-topbar span{{flex:1;text-align:right;color:#eef4f8;font-size:16px;font-weight:600}}
            .tg-room-settings hr{{display:none}}
          </style>
          <header class="tg-manage-topbar"><a href="/conversation/{conversation_id}/profile" aria-label="بازگشت به اطلاعات مجموعه">➜</a><span>مدیریت {kind}</span></header>
          <form class="tg-room-settings" method="post">
            <input type="hidden" name="action" value="save_settings">
            <div class="tg-section">
              <div class="tg-section-title">اطلاعات {kind}</div>
              <label class="tg-field">نام
                <input name="title" minlength="2" maxlength="60" value="{title}" required>
              </label>
              <label class="tg-field">توضیحات
                <textarea name="description" maxlength="500" rows="3">{description}</textarea>
              </label>
              <label class="tg-field">آدرس تصویر
                <input name="avatar_url" maxlength="500" value="{avatar_url}" placeholder="https://..." dir="ltr">
              </label>
              <label class="tg-switch-row"><span>فعال بودن واکنش‌ها</span><span class="tg-switch"><input type="checkbox" name="reactions_enabled" {reactions_checked}><i></i></span></label>
            </div>
            <div class="tg-section">
              <div class="tg-section-title">نوع و دسترسی</div>
              <label class="tg-switch-row"><span>{("گروه عمومی (قابل جستجو)" if room_type == "group" else "کانال عمومی (قابل جستجو)")}</span><span class="tg-switch"><input type="checkbox" name="is_public" {public_checked}><i></i></span></label>
              <label class="tg-switch-row"><span>درخواست عضویت نیازمند تأیید مدیر</span><span class="tg-switch"><input type="checkbox" name="join_approval" {approval_checked}><i></i></span></label>
              <label class="tg-switch-row"><span>نمایش پیام‌های قبلی به اعضای جدید</span><span class="tg-switch"><input type="checkbox" name="history_visible" {history_checked}><i></i></span></label>
            </div>
            {('<div class="tg-section"><details class="tg-permissions"><summary><span>مجوزهای اعضا</span><span class="tg-chevron">⌄</span></summary><div class="tg-permissions-body">' + 
              '<label class="tg-switch-row"><span>ارسال پیام</span><span class="tg-switch"><input type="checkbox" name="perm_send_messages" ' + perm_checks["send_messages"] + '><i></i></span></label>' +
              '<label class="tg-switch-row"><span>ارسال رسانه</span><span class="tg-switch"><input type="checkbox" name="perm_send_media" ' + perm_checks["send_media"] + '><i></i></span></label>' +
              '<label class="tg-switch-row"><span>افزودن اعضا</span><span class="tg-switch"><input type="checkbox" name="perm_add_members" ' + perm_checks["add_members"] + '><i></i></span></label>' +
              '<label class="tg-switch-row"><span>سنجاق پیام</span><span class="tg-switch"><input type="checkbox" name="perm_pin_messages" ' + perm_checks["pin_messages"] + '><i></i></span></label>' +
              '<label class="tg-switch-row"><span>تغییر اطلاعات گروه</span><span class="tg-switch"><input type="checkbox" name="perm_change_info" ' + perm_checks["change_info"] + '><i></i></span></label>' +
              '</div></details></div><div class="tg-section">' +
              '<label class="tg-switch-row"><span>فعال‌سازی موضوعات گروه</span><span class="tg-switch"><input type="checkbox" name="topics_enabled" ' + topics_checked + '><i></i></span></label>' +
              '<label class="tg-field">حالت آهسته ارسال پیام<select name="slow_mode_seconds">' + slow_options + '</select></label></div>') if room_type == "group" else ('<div class="tg-section"><div class="tg-section-title">تنظیمات کانال</div><label class="tg-switch-row"><span>نمایش امضای مدیر در پست‌ها</span><span class="tg-switch"><input type="checkbox" name="sign_messages" ' + sign_checked + '><i></i></span></label><p class="muted">در کانال فقط مالک و مدیران مجاز به انتشار هستند.</p></div>')}
            <button class="tg-save" type="submit" disabled>تأیید تغییرات</button>
          </form>
          <script>
          (function(){{
            const form=document.querySelector('.tg-room-settings'),save=form&&form.querySelector('.tg-save');
            if(!form||!save)return;
            let changed=false;
            function mark(){{changed=true;save.disabled=false;save.textContent='تأیید تغییرات';}}
            form.querySelectorAll('input,textarea,select').forEach(el=>{{el.addEventListener('input',mark);el.addEventListener('change',mark);}});
            form.addEventListener('submit',function(){{if(!changed)return;save.disabled=true;save.textContent='در حال ذخیره…';}});
          }})();
          </script>


          <div class="card">
            <h3>لینک دعوت</h3>
            <input id="invite-link" readonly value="{invite_safe}">
            <button type="button" onclick="cyrusCopyInvite()">کپی لینک</button><script>function cyrusCopyInvite(){{const v=document.getElementById("invite-link").value;if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(v).then(()=>alert("لینک کپی شد")).catch(()=>prompt("لینک دعوت",v));else prompt("لینک دعوت",v);}}</script>
            <form method="post" onsubmit="return confirm('لینک قبلی از کار می‌افتد. ادامه می‌دهید؟')">
              <input type="hidden" name="action" value="rotate_invite">
              <button>ساخت لینک جدید</button>
            </form>
          </div>

          <div class="card">
            <h3>افزودن عضو</h3>
            <form method="post" action="/rooms/{conversation_id}/add-member">
              <input name="username" placeholder="نام کاربری عضو" required>
              <button>افزودن عضو</button>
            </form>
          </div>

          {('<section class="card"><h3>درخواست‌های عضویت (' + str(len(join_requests)) + ')</h3>' + join_request_rows + '</section>') if join_requests else ''}

          <h3>اعضا (<span id="cyrusMemberTotal">{len(members)}</span>)</h3>
          <div class="cyrus-member-tools"><input id="cyrusMemberSearch" type="search" placeholder="جستجوی نام یا نام کاربری عضو"><div class="cyrus-member-filters"><button type="button" data-role="all" class="active">همه</button><button type="button" data-role="admin">مدیران</button><button type="button" data-role="member">اعضا</button><button type="button" id="cyrusMemberReset">پاک‌کردن</button></div><small id="cyrusMemberCount"></small></div>
          <div id="cyrusMemberRows">{rows}</div>
          <script>
          (function(){{const s=document.getElementById('cyrusMemberSearch'),w=document.getElementById('cyrusMemberRows'),n=document.getElementById('cyrusMemberCount'),bs=[...document.querySelectorAll('.cyrus-member-filters [data-role]')],r=document.getElementById('cyrusMemberReset');if(!s||!w)return;let role='all';function apply(){{const q=s.value.trim().toLocaleLowerCase();let shown=0;w.querySelectorAll('.tg-member-row').forEach(x=>{{const ok=(!q||(x.dataset.memberSearch||'').includes(q))&&(role==='all'||x.dataset.memberRole===role);x.hidden=!ok;if(ok)shown++;}});if(n)n.textContent='نمایش '+shown+' از '+w.querySelectorAll('.tg-member-row').length+' عضو';}}s.addEventListener('input',apply);bs.forEach(b=>b.addEventListener('click',()=>{{role=b.dataset.role;bs.forEach(x=>x.classList.toggle('active',x===b));apply();}}));r.addEventListener('click',()=>{{s.value='';role='all';bs.forEach(x=>x.classList.toggle('active',x.dataset.role==='all'));apply();s.focus();}});apply();}})();
          (function(){{const f=document.querySelector('.tg-room-settings'),save=f&&f.querySelector('.tg-save');if(!f)return;let dirty=false;function mark(){{dirty=true;if(save){{save.disabled=false;save.textContent='تأیید تغییرات';}}}}f.querySelectorAll('input,textarea,select').forEach(x=>{{x.addEventListener('input',mark);x.addEventListener('change',mark);}});f.addEventListener('submit',()=>{{dirty=false;if(save){{save.disabled=true;save.textContent='در حال ذخیره…';}}}});window.addEventListener('beforeunload',e=>{{if(dirty){{e.preventDefault();e.returnValue='';}}}});[[f.querySelector('[name=title]'),60],[f.querySelector('[name=description]'),500]].forEach(([x,m])=>{{if(!x)return;const b=document.createElement('small');b.className='cyrus-field-counter';b.textContent=x.value.length+'/'+m;x.after(b);x.addEventListener('input',()=>b.textContent=x.value.length+'/'+m);}});}})();
          </script>
          <div class="card">
            <h3>خروج از مجموعه</h3>
            <form method="post" onsubmit="return confirm('خارج می‌شوید؟')">
              <input type="hidden" name="action" value="leave">
              <button>خروج از مجموعه</button>
            </form>
          </div>
        """

        if owner:
            content += """
            <div class="card">
              <h3>حذف کامل مجموعه</h3>
              <form method="post" onsubmit="return confirm('تمام پیام‌ها و اعضا حذف می‌شوند. مطمئن هستید؟')">
                <input type="hidden" name="action" value="delete">
                <button>حذف گروه یا کانال</button>
              </form>
            </div>
            """

        content += (
            '<p><a href="/chat/' + conversation_id + '">بازگشت به گفتگو</a></p></div>'
        )
        return page(content)

    except Exception:
        return page(
            '<div class="container card"><p>ارتباط با سرور برقرار نشد</p>'
            '<a href="/">بازگشت</a></div>'
        ), 502


@app.route("/channels")
def public_channels():
    if not session.get("access_token"):
        return redirect("/login")

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"]
    }

    try:
        response = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={
                "select": "id,title,created_by,created_at,is_public,invite_code",
                "type": "eq.channel",
                "is_public": "eq.true",
                "order": "created_at.desc",
                "limit": "200"
            },
            headers=headers,
            timeout=20
        )
        if not response.ok:
            raise Exception("channel list failed")

        channels = response.json()

        membership = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={
                "select": "conversation_id",
                "user_id": "eq." + str(session["user_id"])
            },
            headers=headers,
            timeout=20
        )
        if not membership.ok:
            raise Exception("membership list failed")

        joined = {
            str(x.get("conversation_id"))
            for x in membership.json()
        }

        rows = ""
        for channel in channels:
            cid = str(channel.get("id") or "")
            try:
                uuid.UUID(cid)
            except ValueError:
                continue

            title = html.escape(str(channel.get("title") or "کانال عمومی"))
            if cid in joined:
                action = (
                    f'<a class="action" href="/chat/{cid}">مشاهده کانال</a>'
                )
            else:
                invite_code = str(channel.get("invite_code") or "")
                if invite_code:
                    action = '<a class="action" href="/invite/' + quote(invite_code) + '">مشاهده و پیوستن</a>'
                else:
                    action = '<span class="muted">لینک عضویت در دسترس نیست</span>'

            rows += (
                '<div class="card"><h3>' + title + '</h3>'
                '<p class="muted">کانال عمومی CYRUS</p>'
                + action + '</div>'
            )

        if not rows:
            rows = '<div class="empty"><h3>هنوز کانال عمومی ساخته نشده است</h3></div>'

        request_notice = (
            '<div class="card"><p class="muted">درخواست عضویت ارسال شد؛ پس از تأیید مدیر به کانال دسترسی پیدا می‌کنید.</p></div>'
            if request.args.get("request_sent") == "1" else ""
        )
        content = (
            '<div class="container"><section class="welcome">'
            '<h2>کانال‌های عمومی</h2>'
            '<p>کانال‌های قابل دسترس در CYRUS</p></section>'
            + request_notice + rows +
            '<p class="muted"><a href="/contacts">بازگشت</a></p></div>'
        )
        return page(content)

    except Exception:
        return page(
            '<div class="container card"><p>دریافت کانال‌ها ناموفق بود</p>'
            '<a href="/">بازگشت</a></div>'
        ), 502


@app.route("/rooms/<conversation_id>/leave", methods=["POST"])
def leave_room_from_chat(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه مجموعه نامعتبر است", 400
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json"}
    try:
        result = requests.post(URL+"/rest/v1/rpc/cyrus_manage_leave_room",
            json={"p_conversation_id":conversation_id},headers=headers,timeout=20)
        if not result.ok:
            return page('<div class="container card"><p>خروج از مجموعه انجام نشد.</p><a href="/chat/'+html.escape(conversation_id,quote=True)+'">بازگشت</a></div>'),400
        return redirect("/home")
    except Exception:
        return "ارتباط با سرور برقرار نشد",502


@app.route("/channels/join/<conversation_id>", methods=["POST"])
def join_public_channel(conversation_id):
    if not session.get("access_token"):
        return redirect("/login")

    try:
        uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه کانال نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"]
    }
    try:
        channel_response = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={"select":"invite_code,type,is_public","id":"eq."+conversation_id,"limit":"1"},
            headers=headers, timeout=20
        )
        if not channel_response.ok or not channel_response.json():
            return "کانال پیدا نشد", 404
        channel = channel_response.json()[0]
        if channel.get("type") != "channel" or not channel.get("is_public"):
            return "این کانال عمومی نیست", 403
        code = str(channel.get("invite_code") or "")
        if not code:
            return "لینک پیوستن این کانال در دسترس نیست", 404
        return redirect("/invite/" + quote(code))
    except Exception:
        return "ارتباط با سرور برقرار نشد", 502


@app.route("/invite/<invite_code>", methods=["GET", "POST"])
def join_by_invite(invite_code):
    if not session.get("access_token"):
        return redirect("/login")
    if not invite_code or len(invite_code) > 100:
        return "لینک دعوت نامعتبر است", 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json"
    }

    if request.method == "GET":
        try:
            preview_response = requests.post(
                URL + "/rest/v1/rpc/cyrus_invite_preview",
                json={"p_invite_code": invite_code},
                headers=headers,
                timeout=20
            )
            if not preview_response.ok:
                return page('<div class="container card"><p>لینک دعوت نامعتبر یا لغو شده است.</p><a href="/home">بازگشت</a></div>'), 404
            preview = preview_response.json()
            if isinstance(preview, list) and preview:
                preview = preview[0]
            if not isinstance(preview, dict):
                return page('<div class="container card"><p>پیش‌نمایش دعوت دریافت نشد.</p></div>'), 502
            room_id = str(uuid.UUID(str(preview.get("id") or "")))
            if preview.get("already_member"):
                return redirect(url_for("chat", conversation_id=room_id))

            kind = "گروه" if preview.get("type") == "group" else "کانال"
            title = html.escape(str(preview.get("title") or kind))
            description = html.escape(str(preview.get("description") or ""))
            avatar_url = str(preview.get("avatar_url") or "")
            avatar_html = ('<img src="' + html.escape(avatar_url, quote=True) + '" alt="">') if avatar_url else '<div class="invite-avatar-symbol">𓊹</div>'
            try:
                member_count = int(preview.get("member_count") or 0)
            except (TypeError, ValueError):
                member_count = 0
            pending = bool(preview.get("request_pending")) or request.args.get("request_sent") == "1"
            join_approval = bool(preview.get("join_approval"))
            notice = ""
            button = "درخواست عضویت" if join_approval else "پیوستن"
            button_html = ('<div class="invite-pending">درخواست عضویت شما در انتظار تأیید است.</div><form method="post"><input type="hidden" name="action" value="cancel_request"><button type="submit" class="invite-cancel">لغو درخواست عضویت</button></form>') if pending else '<form method="post"><button type="submit">' + button + '</button></form>'
            content = f"""
            <main class="container cyrus-invite-preview">
              <style>
                .cyrus-invite-preview{{min-height:calc(100dvh - 76px);padding:0;background:#0d1722}}
                .invite-topbar{{height:56px;display:flex;align-items:center;gap:15px;padding:0 16px;background:#172331;border-bottom:1px solid #263442;color:#edf4f8}}
                .invite-topbar a{{font-size:27px;color:#eaf2f8}}
                .invite-topbar span{{font-size:16px;font-weight:600}}
                .invite-summary{{text-align:center;padding:32px 20px 24px}}
                .invite-summary img,.invite-avatar-symbol{{width:104px;height:104px;border-radius:50%;object-fit:cover;margin:0 auto 14px;border:2px solid #2d8ecb;display:grid;place-items:center;font-size:42px;color:#d8b46a}}
                .invite-summary h2{{margin:6px 0;color:#eef4f8;font-size:22px}}
                .invite-summary .invite-count{{color:#7eb8e2;font-size:13px;margin:8px 0 15px}}
                .invite-summary .invite-description{{color:#c3cfda;font-size:14px;line-height:1.9;white-space:pre-wrap}}
                .invite-join{{position:sticky;bottom:calc(12px + env(safe-area-inset-bottom));margin:12px;padding:12px;background:#111e2b;border:1px solid #263442;border-radius:14px}}
                .invite-join form{{margin:0}}
                .invite-join button{{width:100%;margin:0;padding:13px;background:#248bd2;color:white;border:0;border-radius:10px;font-size:15px}}
                .invite-join .invite-cancel{{background:#263747;color:#d4e0e9;margin-top:8px}}
                .invite-pending{{margin:12px;padding:13px;background:#111e2b;border:1px solid #263442;border-radius:12px;color:#9fc7e5;text-align:center;font-size:13px;line-height:1.8}}
              </style>
              <div class="invite-topbar"><a href="/home" aria-label="بازگشت">‹</a><span>پیش‌نمایش {kind}</span></div>
              <section class="invite-summary">
                {avatar_html}
                <h2>{title}</h2>
                <div class="invite-count">{kind} · {member_count} عضو</div>
                <div class="invite-description">{description or "توضیحی اضافه نشده است"}</div>
              </section>
              {notice}
              <div class="invite-join">{button_html}</div>
            </main>
            """
            return page(content)
        except Exception:
            return page('<div class="container card"><p>دریافت پیش‌نمایش دعوت ناموفق بود.</p><a href="/home">بازگشت</a></div>'), 502

    try:
        if request.form.get("action") == "cancel_request":
            cancelled = requests.post(
                URL + "/rest/v1/rpc/cyrus_invite_cancel_request",
                json={"p_invite_code": invite_code},
                headers=headers,
                timeout=20
            )
            if not cancelled.ok:
                return page('<div class="container card"><p>لغو درخواست انجام نشد.</p><a href="/invite/' + html.escape(invite_code, quote=True) + '">بازگشت</a></div>'), 400
            return redirect("/invite/" + quote(invite_code))

        result = requests.post(
            URL + "/rest/v1/rpc/cyrus_invite_join",
            json={"p_invite_code": invite_code},
            headers=headers,
            timeout=20
        )
        if not result.ok:
            return page('<div class="container card"><p>پیوستن به مجموعه ناموفق بود.</p><a href="/invite/' + html.escape(invite_code, quote=True) + '">بازگشت</a></div>'), 400
        outcome = result.json()
        if isinstance(outcome, list) and outcome:
            outcome = outcome[0]
        if not isinstance(outcome, dict):
            return page('<div class="container card"><p>پاسخ عضویت نامعتبر بود.</p></div>'), 502
        room_id = str(uuid.UUID(str(outcome.get("conversation_id") or "")))
        if outcome.get("status") == "requested":
            return redirect("/invite/" + quote(invite_code) + "?request_sent=1")
        return redirect(url_for("chat", conversation_id=room_id))
    except Exception:
        return page('<div class="container card"><p>پیوستن به مجموعه ناموفق بود.</p><a href="/home">بازگشت</a></div>'), 502


def cyrus_profile_headers():
    return {
        "apikey": KEY,
        "Authorization": "Bearer " + session.get("access_token", ""),
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def cyrus_get_profile():
    uid = str(session.get("user_id") or "")
    if not uid:
        return None
    try:
        r = requests.get(
            URL + "/rest/v1/cyrus_profiles",
            params={
                "select": "id,username,display_name,bio,avatar_url",
                "id": "eq." + uid,
                "limit": "1"
            },
            headers=cyrus_profile_headers(),
            timeout=20
        )
        if r.ok and r.json():
            return r.json()[0]
    except Exception:
        pass
    return None


def cyrus_ensure_profile(email=""):
    existing = cyrus_get_profile()
    if existing:
        return existing

    uid = str(session.get("user_id") or "")
    if not uid:
        return None

    base = str(email or "").split("@")[0]
    username = "".join(
        ch for ch in base if ch.isalnum() or ch in "_-"
    )[:24]
    if len(username) < 3:
        username = "cyrus_" + uid.replace("-", "")[:10]

    payload = {
        "id": uid,
        "username": username,
        "display_name": username,
        "bio": ""
    }

    try:
        r = requests.post(
            URL + "/rest/v1/cyrus_profiles",
            json=payload,
            headers={
                **cyrus_profile_headers(),
                "Prefer": "resolution=merge-duplicates,return=representation"
            },
            timeout=20
        )
        if r.ok:
            return cyrus_get_profile()

        payload["username"] = "cyrus_" + uid.replace("-", "")[:12]
        payload["display_name"] = payload["username"]
        r = requests.post(
            URL + "/rest/v1/cyrus_profiles",
            json=payload,
            headers={
                **cyrus_profile_headers(),
                "Prefer": "resolution=merge-duplicates,return=representation"
            },
            timeout=20
        )
        if r.ok:
            return cyrus_get_profile()
    except Exception:
        pass

    return None


@app.route("/profile/avatar", methods=["POST"])
def upload_profile_avatar():
    if not session.get("access_token"):
        return redirect("/login")
    file = request.files.get("avatar")
    if not file or not file.filename:
        return redirect("/settings?avatar_error=فایلی%20انتخاب%20نشده")
    mime = (file.mimetype or "").lower()
    extensions = {"image/jpeg":"jpg", "image/png":"png", "image/webp":"webp"}
    if mime not in extensions:
        return redirect("/settings?avatar_error=فقط%20JPG%20،%20PNG%20یا%20WebP")
    data = file.read(5 * 1024 * 1024 + 1)
    if not data or len(data) > 5 * 1024 * 1024:
        return redirect("/settings?avatar_error=حجم%20عکس%20باید%20حداکثر%205%20مگابایت%20باشد")

    # پسوند و MIME ارسالی به‌تنهایی قابل اعتماد نیست؛ امضای واقعی فایل را بررسی کن.
    valid_image = (
        (mime == "image/jpeg" and data.startswith(b"\xff\xd8\xff")) or
        (mime == "image/png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or
        (mime == "image/webp" and len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP")
    )
    if not valid_image:
        return redirect("/settings?avatar_error=محتوای%20فایل%20با%20نوع%20تصویر%20هماهنگ%20نیست")

    uid = str(session.get("user_id") or "")
    key_path = uid + "/profile." + extensions[mime]
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":mime,"x-upsert":"true"}
    try:
        uploaded = requests.put(URL + "/storage/v1/object/cyrus-avatars/" + key_path, data=data, headers=headers, timeout=45)
        if not uploaded.ok:
            detail = ""
            try:
                detail = str(uploaded.json().get("message") or uploaded.json().get("error") or uploaded.json().get("statusCode") or "")
            except Exception:
                detail = (uploaded.text or "")[:180]
            message = "بارگذاری عکس ناموفق بود"
            if detail:
                message += " (" + detail[:180] + ")"
            from urllib.parse import quote
            return redirect("/settings?avatar_error=" + quote(message))
        public_url = URL + "/storage/v1/object/public/cyrus-avatars/" + key_path + "?v=" + str(int(time.time()))
        saved = requests.patch(URL + "/rest/v1/cyrus_profiles", params={"id":"eq."+uid}, json={"avatar_url":public_url}, headers={**cyrus_profile_headers(),"Prefer":"return=minimal"}, timeout=20)
        if not saved.ok:
            return redirect("/settings?avatar_error=عکس%20بارگذاری%20شد%20اما%20ذخیره%20پروفایل%20ناموفق%20بود")
        return redirect("/settings?avatar_success=1")
    except Exception:
        return redirect("/settings?avatar_error=ارتباط%20با%20سرور%20برقرار%20نشد")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("access_token"):
        return redirect("/login")
    return redirect("/settings")

    error = ""
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        bio = request.form.get("bio", "").strip()

        if not 2 <= len(display_name) <= 40:
            error = "نام نمایشی باید بین ۲ تا ۴۰ حرف باشد"
        elif len(bio) > 250:
            error = "بیوگرافی حداکثر ۲۵۰ حرف باشد"
        else:
            try:
                r = requests.patch(
                    URL + "/rest/v1/cyrus_profiles",
                    params={"id": "eq." + str(session.get("user_id"))},
                    json={"display_name": display_name, "bio": bio},
                    headers=cyrus_profile_headers(),
                    timeout=20
                )
                if r.ok:
                    return redirect("/profile")
                error = "ذخیره پروفایل انجام نشد؛ دوباره تلاش کنید"
            except Exception:
                error = "ارتباط با سرور برقرار نشد"

    data = cyrus_ensure_profile(session.get("cyrus_login_email", ""))
    if not data:
        data = {"username": "", "display_name": "", "bio": ""}

    username = html.escape(str(data.get("username") or ""))
    display_name = html.escape(str(data.get("display_name") or ""), quote=True)
    bio = html.escape(str(data.get("bio") or ""))
    avatar_url = str(data.get("avatar_url") or "")
    avatar_html = ('<img src="' + html.escape(avatar_url, quote=True) + '" alt="عکس پروفایل" style="width:110px;height:110px;border-radius:50%;object-fit:cover;display:block;margin:0 auto 14px;border:2px solid #3297df">') if avatar_url else '<div class="avatar" style="width:110px;height:110px;margin:0 auto 14px;font-size:42px">𓅃</div>'
    avatar_error = html.escape(request.args.get("avatar_error", ""))
    avatar_success = request.args.get("avatar_success") == "1"

    content = f"""
    <main class="container cyrus-profile-page">
      <style>
        .cyrus-profile-page{{padding:12px 12px 90px;max-width:560px}}
        .profile-hero{{text-align:center;padding:25px 16px 22px;background:#111e2b;border:1px solid #263b50;border-radius:18px;margin-bottom:12px}}
        .avatar-upload-form{{margin:12px auto 16px;max-width:330px;padding:10px;background:#0a1521;border:1px solid #2a4054;border-radius:12px}}
        .avatar-upload-form input[type=file]{{font-size:12px;padding:9px;background:#07121e;border:1px solid #30485e;border-radius:9px;color:#cbd7e2;width:100%;box-sizing:border-box}}
        .avatar-upload-form button{{margin-top:8px;padding:11px;font-size:13px;background:linear-gradient(100deg,#98702e,#e3bf69);color:#181208}}
        .avatar-upload-success{{color:#8ee0b0;font-size:12px;margin:8px 0}}
        .profile-hero img,.profile-hero .avatar{{width:104px;height:104px;border-radius:50%;object-fit:cover;margin:0 auto 13px;border:2px solid #2d8ecb;display:grid;place-items:center}}
        .profile-hero h2{{margin:5px 0;color:#eef4f8;font-size:21px;font-weight:500}}
        .profile-hero .username{{color:#78b8e6;font-size:13px;direction:ltr;margin-top:5px}}
        .profile-hero .bio{{color:#c3cfda;font-size:14px;line-height:1.9;white-space:pre-wrap;margin:14px 0 0}}
        .profile-row{{display:flex;align-items:center;gap:14px;padding:15px 16px;margin:0;background:#111e2b;border-bottom:1px solid #24374a;color:#e5edf5;font-size:14px}}
        .profile-row:first-of-type{{border-radius:14px 14px 0 0}}
        .profile-row:last-of-type{{border-radius:0 0 14px 14px;border-bottom:0}}
        .profile-row .row-icon{{width:28px;text-align:center;color:#7ebbe8;font-size:20px}}
        .profile-row .row-sub{{display:block;color:#8fa5b8;font-size:11px;margin-top:5px}}
        .profile-edit-details{{margin-top:12px;background:#111e2b;border:1px solid #263b50;border-radius:14px;overflow:hidden}}
        .profile-edit-details summary{{list-style:none;cursor:pointer;padding:16px;color:#80c1f0;text-align:center;font-size:14px}}
        .profile-edit-details summary::-webkit-details-marker{{display:none}}
        .profile-edit{{padding:14px;border-top:1px solid #263b50}}
        .profile-edit h3{{margin:0 0 12px;color:#d7b56c;font-size:15px;font-weight:normal}}
        .profile-edit label{{display:block;color:#9fb1c1;font-size:12px;margin-top:10px}}
        .profile-edit input,.profile-edit textarea{{background:#0a1521;border:1px solid #2a4054;border-radius:10px;padding:11px 12px;margin:5px 0;font-size:14px;color:white;width:100%;box-sizing:border-box}}
        .profile-edit button{{background:#258bd0;color:white;margin-top:12px}}
        .profile-link{{display:block;text-align:center;color:#87bfe8;padding:13px}}
      </style>
      <section class="profile-hero">
        {avatar_html}
        <form method="post" action="/profile/avatar" enctype="multipart/form-data" class="avatar-upload-form">
          <input type="file" name="avatar" accept="image/jpeg,image/png,image/webp" required>
          <button type="submit">بارگذاری تصویر پروفایل</button>
          <p class="error">{avatar_error}</p>
          <p class="avatar-upload-success">{"تصویر پروفایل با موفقیت ذخیره شد" if avatar_success else ""}</p>
        </form>
        <h2>{html.escape(str(data.get("display_name") or data.get("username") or "کاربر"))}</h2>
        <div class="username">@{username}</div>
        <p class="bio">{bio or "بیوگرافی اضافه نشده است"}</p>
      </section>
      <div class="profile-menu">
        <a class="profile-row" href="/settings">
          <span class="row-icon">♙</span><span>نام کاربری<span class="row-sub">@{username}</span></span>
        </a>
        <a class="profile-row" href="/settings">
          <span class="row-icon">⚙</span><span>تنظیمات حساب و حریم خصوصی</span>
        </a>
      </div>
      <details class="profile-edit-details">
        <summary>ویرایش پروفایل</summary>
        <section class="profile-edit">
          <h3>ویرایش اطلاعات</h3>
          <p class="error">{html.escape(error)}</p>
          <form method="post">
            <label>نام نمایشی</label>
            <input name="display_name" maxlength="40" minlength="2" value="{display_name}" required>
            <label>بیوگرافی</label>
            <textarea name="bio" maxlength="120" rows="3">{bio}</textarea>
            <button type="submit">ذخیره تغییرات</button>
          </form>
        </section>
      </details>
      <a class="profile-link" href="/home">بازگشت به بارگاه</a>
    </main>
    """
    return page(content)


@app.route("/saved-messages", methods=["GET"])
def saved_messages():
    if not session.get("access_token"):
        return redirect("/login")
    own_id = str(session.get("user_id") or "")
    headers = {"apikey":KEY, "Authorization":"Bearer "+session["access_token"]}
    error = ""
    rows = ""
    try:
        result = requests.get(
            URL + "/rest/v1/cyrus_saved_messages",
            params={"select":"id,content,created_at","user_id":"eq."+own_id,"order":"created_at.desc","limit":"300"},
            headers=headers, timeout=20
        )
        if not result.ok:
            error = "پیام‌های ذخیره‌شده بارگذاری نشد"
        else:
            for item in result.json():
                sid = html.escape(str(item.get("id") or ""), quote=True)
                text_value = html.escape(str(item.get("content") or ""))
                created = str(item.get("created_at") or "")
                try:
                    stamp = datetime.fromisoformat(created.replace("Z","+00:00")).astimezone().strftime("%Y/%m/%d · %H:%M")
                except Exception:
                    stamp = ""
                rows += f'<article class="saved-message-item" data-saved-text="{html.escape(str(item.get("content") or "").lower(),quote=True)}"><div class="saved-message-text">{text_value}</div><small>{html.escape(stamp)}</small><div class="saved-message-actions"><button type="button" class="saved-copy" data-copy="{html.escape(str(item.get("content") or ""),quote=True)}">کپی متن</button><form method="post" action="/saved-messages/{sid}/delete" onsubmit="return confirm(\'این پیام حذف شود؟\')"><button type="submit">حذف</button></form></div></article>'
    except Exception:
        error = "ارتباط با سرور برقرار نشد"
    content = f"""
    <main class="container card cyrus-saved-messages">
      <style>
        .cyrus-saved-messages{{max-width:620px;margin:12px auto;padding:16px 14px 90px;background:#0d1a28;border:1px solid #263b50;border-radius:16px;color:#edf2f7}}
        .saved-messages-header{{display:flex;align-items:center;gap:12px;margin-bottom:16px}}
        .saved-messages-back{{width:38px;height:38px;display:grid;place-items:center;border-radius:50%;background:#172b3d;color:#e8eef5;text-decoration:none;font-size:22px}}
        .saved-messages-header h2{{font-size:18px;font-weight:500;margin:0}}
        .saved-messages-form{{display:grid;gap:10px;margin-bottom:16px}}
        .saved-messages-form textarea{{width:100%;box-sizing:border-box;min-height:110px;padding:13px;border-radius:12px;background:#07121e;color:#fff;border:1px solid #30485e;font:inherit;resize:vertical}}
        .saved-messages-form button{{padding:12px;border:0;border-radius:12px;background:#248bd0;color:#fff;font:inherit}}
        .saved-message-item{{position:relative;background:#142536;border:1px solid #263b50;border-radius:12px;padding:13px;margin:9px 0;overflow-wrap:anywhere}}
        .saved-message-text{{white-space:pre-wrap;line-height:1.8;font-size:14px}}
        .saved-message-item small{{display:block;color:#8ea5b9;font-size:10px;margin-top:9px}}
        .saved-message-actions{{display:flex;justify-content:space-between;align-items:center;margin-top:10px;gap:8px}}.saved-message-actions form{{margin:0}}.saved-message-actions button{{background:transparent;color:#9acdf2;border:1px solid #38556d;border-radius:8px;padding:6px 12px;font:inherit;font-size:12px}}.saved-message-actions form button{{color:#e6a5a5;border-color:#5a3c45}}
        .saved-message-item form{{text-align:left;margin-top:8px}}
        .saved-message-item button{{background:transparent;color:#e6a5a5;border:1px solid #5a3c45;border-radius:8px;padding:5px 12px}}
        .saved-messages-error{{color:#f1aeb4;text-align:center}}
      </style>
      <header class="saved-messages-header"><a class="saved-messages-back" href="/settings" aria-label="بازگشت">➜</a><h2>پیام‌های ذخیره‌شده</h2></header>
      <input id="saved-message-search" type="search" placeholder="جستجو در پیام‌های ذخیره‌شده…" aria-label="جستجو در پیام‌های ذخیره‌شده" style="width:100%;box-sizing:border-box;padding:11px 13px;margin:0 0 12px;border-radius:10px;background:#07121e;color:#fff;border:1px solid #30485e;font:inherit">
      <p id="saved-message-empty-search" hidden style="text-align:center;color:#8ea5b9">موردی پیدا نشد.</p>
      <form class="saved-messages-form" method="post" action="/saved-messages/add">
        <textarea name="content" maxlength="10000" placeholder="یادداشت، متن یا لینک مهم را برای خودت ذخیره کن..." required></textarea>
        <button type="submit">ذخیره پیام</button>
      </form>
      <p class="saved-messages-error">{html.escape(error)}</p>
      {rows or '<p style="text-align:center;color:#8ea5b9">هنوز پیامی ذخیره نکرده‌ای.</p>'}
      <script>
      (function(){{
        const search=document.getElementById('saved-message-search'),items=Array.from(document.querySelectorAll('.saved-message-item')),empty=document.getElementById('saved-message-empty-search');
        if(search)search.addEventListener('input',()=>{{const q=search.value.trim().toLocaleLowerCase();let shown=0;items.forEach(x=>{{const ok=(x.dataset.savedText||'').includes(q);x.hidden=!ok;if(ok)shown++;}}if(empty)empty.hidden=shown>0||!q;}});
        document.querySelectorAll('.saved-copy').forEach(b=>b.addEventListener('click',async()=>{{const value=b.dataset.copy||'';try{{await navigator.clipboard.writeText(value);b.textContent='کپی شد';}}catch(_e){{window.prompt('متن را کپی کنید:',value);}}}}));
      }})();
      </script>
    </main>
    """
    return page(content)


@app.route("/saved-messages/add", methods=["POST"])
def add_saved_message():
    if not session.get("access_token"):
        return redirect("/login")
    content = str(request.form.get("content") or "").strip()
    if not content or len(content) > 10000:
        return redirect("/saved-messages")
    response = requests.post(
        URL + "/rest/v1/cyrus_saved_messages",
        json={"user_id":str(session.get("user_id") or ""),"content":content},
        headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],
                 "Content-Type":"application/json","Prefer":"return=minimal"},
        timeout=20
    )
    if not response.ok:
        return page('<div class="container card"><p>ذخیره پیام انجام نشد؛ دوباره تلاش کنید.</p><a href="/saved-messages">بازگشت</a></div>'),400
    return redirect("/saved-messages")


@app.route("/saved-messages/<message_id>/delete", methods=["POST"])
def delete_saved_message(message_id):
    if not session.get("access_token"):
        return redirect("/login")
    try:
        uuid.UUID(message_id)
    except ValueError:
        return "شناسه پیام نامعتبر است",400
    response = requests.delete(
        URL + "/rest/v1/cyrus_saved_messages",
        params={"id":"eq."+message_id,"user_id":"eq."+str(session.get("user_id") or "")},
        headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],
                "Prefer":"return=minimal"},
        timeout=20
    )
    if not response.ok:
        return page('<div class="container card"><p>حذف پیام انجام نشد</p><a href="/saved-messages">بازگشت</a></div>'),400
    return redirect("/saved-messages")


def cyrus_block_status(other_user_id, headers):
    """Return True/False for a blocked pair, or None if the server check failed."""
    try:
        response = requests.post(
            URL + "/rest/v1/rpc/cyrus_is_blocked_pair",
            json={"other_user_id":str(other_user_id)},
            headers={**headers, "Content-Type":"application/json"},
            timeout=12
        )
        if response.ok:
            value = response.json()
            if isinstance(value, bool):
                return value
            if isinstance(value, list) and value and isinstance(value[0], bool):
                return value[0]
    except Exception:
        pass
    return None


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not session.get("access_token"):
        return redirect("/login")

    error = ""
    edit_field = ""
    field_value = ""
    if request.method == "POST":
        edit_field = request.form.get("edit_field", "").strip()
        field_value = request.form.get("field_value", "").strip()
        if edit_field == "username":
            valid = (
                3 <= len(field_value) <= 24
                and all(ch.isalnum() or ch in "_-" for ch in field_value)
            )
            if not valid:
                error = "نام کاربری باید ۳ تا ۲۴ حرف و فقط شامل حروف، عدد، خط تیره یا زیرخط باشد"
            else:
                patch_data = {"username": field_value}
        elif edit_field == "display_name":
            if not 2 <= len(field_value) <= 40:
                error = "نام نمایشی باید بین ۲ تا ۴۰ حرف باشد"
            else:
                patch_data = {"display_name": field_value}
        elif edit_field == "bio":
            if len(field_value) > 250:
                error = "بیوگرافی حداکثر ۲۵۰ حرف باشد"
            else:
                patch_data = {"bio": field_value}
        else:
            error = "بخش ویرایش نامعتبر است"

        if not error:
            try:
                r = requests.patch(
                    URL + "/rest/v1/cyrus_profiles",
                    params={"id": "eq." + str(session.get("user_id"))},
                    json=patch_data,
                    headers=cyrus_profile_headers(),
                    timeout=20
                )
                if r.ok:
                    return redirect("/settings")
                error = "ذخیره انجام نشد؛ دوباره تلاش کنید"
            except Exception:
                error = "ارتباط با سرور برقرار نشد"

    data = cyrus_ensure_profile(session.get("cyrus_login_email", "")) or {
        "username": "", "display_name": "", "bio": "", "avatar_url": ""
    }
    username_raw = str(data.get("username") or "")
    display_raw = str(data.get("display_name") or username_raw or "کاربر")
    bio_raw = str(data.get("bio") or "")
    username = html.escape(username_raw, quote=True)
    display_name = html.escape(display_raw, quote=True)
    bio = html.escape(bio_raw, quote=True)
    share_text = html.escape("@" + username_raw, quote=True)
    avatar_url = str(data.get("avatar_url") or "")
    if avatar_url:
        avatar_html = '<img class="setting-profile-image" src="' + html.escape(avatar_url, quote=True) + '" alt="تصویر پروفایل">'
    else:
        avatar_html = '<div class="setting-profile-image setting-profile-fallback">♙</div>'
    avatar_error = html.escape(request.args.get("avatar_error", ""))
    avatar_notice = ('<p class="setting-error">' + avatar_error + '</p>') if avatar_error else ('<p class="setting-avatar-success">تصویر پروفایل با موفقیت تغییر کرد</p>' if request.args.get("avatar_success") == "1" else "")
    edit_value_html = html.escape(field_value, quote=True)

    content = f"""
    <main class="container cyrus-settings-page">
      <style>
        .cyrus-settings-page{{width:100%;max-width:430px;margin:0 auto;padding:0 0 82px;color:#f1e7d2}}
        .setting-container{{position:relative;display:grid;grid-template-rows:240px 7px auto auto 1fr;width:100%;min-height:calc(100dvh - 76px);text-align:center;background:rgba(7,15,25,.97);color:#f1e7d2;z-index:1;overflow:visible;border-inline:1px solid #27394a}}
        .setting-img-container{{grid-row:1/2;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:11px;background:linear-gradient(rgba(5,12,22,.18),rgba(5,12,22,.82)),url('/static/cyrus-tomb.jpg') center/cover no-repeat;padding:18px;position:relative}}
        .setting-profile-image{{width:100px;height:100px;border-radius:50%;object-fit:cover;border:2px solid #d5ad5b;box-shadow:0 0 0 5px #151e29aa}}
        .setting-profile-fallback{{display:grid;place-items:center;background:#14283b;color:#d9b45f;font-size:40px}}
        .setting-profile-name{{font-size:20px;color:#f3d48a;text-shadow:0 2px 7px #000;cursor:pointer}}
        .setting-profile-user{{font-size:13px;color:#e4e9ee;direction:ltr;cursor:pointer;max-width:100%;overflow-wrap:anywhere;text-shadow:0 2px 7px #000}}
        .setting-profile-bio{{font-size:13px;color:#e1e8ee;max-width:92%;line-height:1.7;cursor:pointer;text-shadow:0 2px 7px #000}}
        .setting-divider{{grid-row:2/3;background:#a37a3d55}}
        .setting-information-container{{grid-row:3/4;display:grid;grid-gap:5px;grid-template-rows:repeat(3,minmax(67px,auto));padding:8px 5px}}
        .setting-info{{width:100%;border:1px solid #1d3042;border-radius:13px;display:grid;grid-template-columns:minmax(0,1fr) 94px;align-items:center;transition:.2s;background:#0e1b29;text-align:right;color:#edf2f7;padding:12px 16px;cursor:pointer;font:inherit}}
        .setting-info:hover,.s-button:hover{{background:#1a2c3e;border-color:#3c5871}}
        .setting-info:active{{transform:scale(.99)}}
        .setting-info .info{{grid-column:1/2;font-size:15px;text-align:right;align-self:center;min-width:0;overflow-wrap:anywhere;color:#edf2f7}}
        .smal-title{{grid-column:2/3;grid-row:1/2;align-self:center;font-size:12px;padding:0 8px;color:#8fa4b7;white-space:nowrap}}
        .setting-buttons{{grid-row:5/6;display:grid;grid-gap:7px;grid-template-rows:repeat(5,minmax(56px,auto));padding:8px 9px 18px}}.setting-avatar-success{{color:#8ee0b0;text-align:center;font-size:12px;margin:4px 0}}
        .setting-avatar-picker{{position:absolute;inset-inline-start:calc(50% - 64px);top:calc(50% - 64px);width:34px;height:34px;border:2px solid #0b1724;border-radius:50%;background:#2b9be8;color:#fff;display:grid;place-items:center;box-shadow:0 3px 12px #0008;cursor:pointer;z-index:3;padding:0;margin:0}}
        .setting-avatar-picker svg{{width:19px;height:19px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}}
        .setting-avatar-hidden{{display:none!important}}
        .setting-avatar-editor{{position:fixed;inset:0;z-index:60;background:#020711d9;backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:18px 14px calc(88px + env(safe-area-inset-bottom))}}
        .setting-avatar-editor.open{{display:flex}}
        .setting-avatar-sheet{{width:100%;max-width:390px;background:#0d1a28;border:1px solid #344b60;border-radius:22px;padding:20px;text-align:center;box-shadow:0 20px 70px #0009}}
        .setting-avatar-sheet h3{{margin:0 0 7px;color:#e5bd69;font-size:18px;font-weight:500}}
        .setting-avatar-sheet p{{font-size:12px;color:#91a6b9;line-height:1.8;margin:0 0 15px}}
        .setting-avatar-crop{{width:220px;height:220px;max-width:70vw;max-height:70vw;border-radius:50%;overflow:hidden;border:2px solid #d8b45f;background:#14283b;margin:0 auto 18px;display:grid;place-items:center}}
        .setting-avatar-crop img{{width:100%;height:100%;object-fit:cover;transform-origin:center;pointer-events:none}}
        .setting-avatar-sheet input[type=range]{{width:100%;accent-color:#d8b45f;margin:7px 0 14px}}
        .setting-avatar-actions{{display:flex;gap:9px}}
        .setting-avatar-actions button{{flex:1;margin:0;padding:12px;font:inherit;border-radius:12px}}
        .setting-avatar-confirm{{background:#d8b45f;color:#17120a}}
        .setting-avatar-cancel{{background:#1a2a3a;color:#d8e3ec;border:1px solid #344b60}}
        .s-button{{display:grid;align-items:center;border-radius:12px;grid-template-columns:42px minmax(0,1fr) 20px;transition:.2s;cursor:pointer;background:#0e1b29;border:1px solid #1d3042;color:#edf2f7;text-align:right;text-decoration:none;padding:6px 12px;font:inherit}}
        .button-title{{font-size:14px;text-align:right;align-self:center;padding:0 12px;grid-column:2/3;grid-row:1/2}}
        .buttons-icons{{height:34px;width:34px;border-radius:10px;align-self:center;grid-column:1/2;background:#152b3e;color:#d6ad5b;display:grid;place-items:center}}
        .buttons-icons svg{{width:21px;height:21px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}}
        .setting-error{{color:#ff9b8f;font-size:12px;line-height:1.8;margin:5px 0}}
        .setting-edit-overlay{{position:fixed;inset:0;background:#020711b8;backdrop-filter:blur(5px);z-index:30;display:none;align-items:flex-end;justify-content:center;padding:14px 12px calc(90px + env(safe-area-inset-bottom))}}
        .setting-edit-overlay.open{{display:flex}}
        .setting-edit-sheet{{width:100%;max-width:430px;background:#0d1a28;border:1px solid #52627a;border-radius:22px;padding:18px;box-shadow:0 20px 60px #0008;text-align:right}}
        .setting-edit-sheet h3{{margin:0 0 14px;color:#e5bd69;font-size:17px;font-weight:500}}
        .setting-edit-sheet input,.setting-edit-sheet textarea{{width:100%;background:#07121e;border:1px solid #30485e;border-radius:12px;padding:13px;color:#fff;font:inherit;box-sizing:border-box;resize:vertical}}
        .setting-edit-sheet button{{margin-top:12px}}
        .setting-edit-cancel{{background:#1a2a3a;color:#d8e3ec;border:1px solid #344b60}}
        @media(max-width:430px){{.cyrus-settings-page{{max-width:100%}}.setting-container{{border-inline:0}}}}
      </style>
      <section class="setting-container">
        <section class="setting-img-container">
          <div class="setting-avatar-wrap" style="position:relative;display:inline-flex;align-items:center;justify-content:center">
            {avatar_html}
            <button class="setting-avatar-picker" type="button" id="setting-avatar-open" aria-label="انتخاب عکس از گالری" title="انتخاب عکس از گالری"><svg viewBox="0 0 24 24"><path d="M4 7h3l1.5-2h7L17 7h3v12H4z"/><circle cx="12" cy="13" r="4"/></svg></button>
          </div>
          <div class="setting-profile-name" data-edit="display_name" data-current="{display_name}">{display_name}</div>
          <div class="setting-profile-user" data-edit="username" data-current="{username}">@{username}</div>
          <div class="setting-profile-bio" data-edit="bio" data-current="{bio}">{bio or "بیوگرافی اضافه نشده · برای ویرایش لمس کنید"}</div>
        </section>
        <div class="setting-divider"></div>
        <section class="setting-information-container">
          <button class="setting-info" type="button" data-edit="display_name" data-current="{display_name}">
            <span class="info">{display_name}</span><span class="smal-title">نام نمایشی</span>
          </button>
          <button class="setting-info" type="button" data-edit="username" data-current="{username}">
            <span class="info" dir="ltr">@{username}</span><span class="smal-title">نام کاربری</span>
          </button>
          <button class="setting-info" type="button" data-edit="bio" data-current="{bio}">
            <span class="info">{bio or "بیوگرافی ثبت نشده · برای ویرایش لمس کنید"}</span><span class="smal-title">درباره</span>
          </button>
        </section>
        <section class="setting-buttons">
          <form id="setting-avatar-upload" class="setting-avatar-hidden" method="post" action="/profile/avatar" enctype="multipart/form-data"><input id="setting-avatar-file" type="file" name="avatar" accept="image/jpeg,image/png,image/webp" required></form>
          {avatar_notice}
          <a class="s-button" href="/account/export"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M12 3v12m-5-5 5 5 5-5M4 17v3h16v-3"/></svg></span><span class="button-title">دریافت نسخهٔ پشتیبان اطلاعات حساب</span><span>‹</span></a>
          <a class="s-button" href="/blocked-users"><span class="buttons-icons"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0M4 4l16 16"/></svg></span><span class="button-title">کاربران مسدودشده و حریم خصوصی</span><span>‹</span></a>
          <a class="s-button" href="/saved-messages"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M5 3h14v18l-7-4-7 4z"/><path d="M8 7h8M8 10h8"/></svg></span><span class="button-title">پیام‌های ذخیره‌شده</span><span>‹</span></a>
          <a class="s-button" href="https://t.me/CyrusSupport_Aria" target="_blank" rel="noopener noreferrer"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M21.5 3.5 18 20.2a1.5 1.5 0 0 1-2.4.8l-4.7-3.5-2.3 2.2a1 1 0 0 1-1.7-.6l-.8-5.2L2.4 11a1.4 1.4 0 0 1 .1-2.6L20 2.8a1.2 1.2 0 0 1 1.5.7Z"/><path d="m6.2 13.7 11.2-8.1-6.5 11.9"/></svg></span><span class="button-title">پشتیبانی رسمی سرزمین‌های پارس</span><span>‹</span></a>
          <a class="s-button" href="/contacts"><span class="buttons-icons"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="4"/><path d="M2 21v-2a7 7 0 0 1 14 0v2M17 4a4 4 0 0 1 0 8M18 16a5 5 0 0 1 4 5"/></svg></span><span class="button-title">خویشان و مخاطبان</span><span>‹</span></a>
          <button class="s-button" type="button" onclick="navigator.clipboard.writeText(document.getElementById('cyrus-settings-share').value).then(()=>alert('شناسه کپی شد'))"><span class="buttons-icons"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg></span><span class="button-title">کپی شناسه برای دوستان</span><span>‹</span></button>
          <form method="post" action="/logout"><button class="s-button" type="submit"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M10 17l5-5-5-5M15 12H3"/><path d="M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7"/></svg></span><span class="button-title">خروج از حساب</span><span>‹</span></button></form>
          <a class="s-button" href="/home"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M3 10.5 12 3l9 7.5M5.5 9.5V21h13V9.5M9.5 21v-6h5v6"/></svg></span><span class="button-title">بازگشت به بارگاه</span><span>‹</span></a>
        </section>
        <input id="cyrus-settings-share" type="hidden" value="{share_text}">
      </section>
      <div class="setting-avatar-editor" id="setting-avatar-editor" role="dialog" aria-modal="true" aria-label="ویرایش عکس پروفایل">
        <section class="setting-avatar-sheet">
          <h3>ویرایش تصویر پروفایل</h3>
          <p>عکس را از گالری انتخاب کن، اندازه‌اش را تنظیم کن و بعد تأیید کن.</p>
          <div class="setting-avatar-crop"><img id="setting-avatar-preview" alt="پیش‌نمایش عکس پروفایل"></div>
          <label for="setting-avatar-zoom" style="display:block;color:#b7c8d8;font-size:12px">بزرگ‌نمایی</label>
          <input id="setting-avatar-zoom" type="range" min="1" max="3" step="0.05" value="1">
          <div class="setting-avatar-actions"><button type="button" class="setting-avatar-cancel" id="setting-avatar-cancel">انصراف</button><button type="button" class="setting-avatar-confirm" id="setting-avatar-confirm">تأیید و ثبت پروفایل</button></div>
        </section>
      </div>
      <script>
      (function(){{
        const picker=document.getElementById('setting-avatar-open'), file=document.getElementById('setting-avatar-file'), form=document.getElementById('setting-avatar-upload');
        const modal=document.getElementById('setting-avatar-editor'), preview=document.getElementById('setting-avatar-preview'), zoom=document.getElementById('setting-avatar-zoom');
        const cancel=document.getElementById('setting-avatar-cancel'), confirm=document.getElementById('setting-avatar-confirm');
        let source=null, image=null;
        picker.addEventListener('click',()=>file.click());
        file.addEventListener('change',()=>{{
          const chosen=file.files&&file.files[0]; if(!chosen)return;
          if(!/^image\/(jpeg|png|webp)$/.test(chosen.type)){{alert('فقط عکس JPG، PNG یا WebP انتخاب کن');file.value='';return;}}
          if(chosen.size>5*1024*1024){{alert('حجم عکس باید حداکثر ۵ مگابایت باشد');file.value='';return;}}
          source=URL.createObjectURL(chosen); image=new Image();
          image.onload=()=>{{preview.src=source;zoom.value='1';preview.style.transform='scale(1)';modal.classList.add('open');}};
          image.onerror=()=>{{alert('باز کردن عکس ناموفق بود');file.value='';}}; image.src=source;
        }});
        zoom.addEventListener('input',()=>preview.style.transform='scale('+zoom.value+')');
        function closeEditor(){{modal.classList.remove('open');if(source)URL.revokeObjectURL(source);source=null;image=null;file.value='';}}
        cancel.addEventListener('click',closeEditor);
        modal.addEventListener('click',e=>{{if(e.target===modal)closeEditor();}});
        confirm.addEventListener('click',()=>{{
          if(!image)return;
          const side=512, scale=Math.max(side/image.naturalWidth,side/image.naturalHeight)*Number(zoom.value);
          const canvas=document.createElement('canvas');canvas.width=side;canvas.height=side;
          const ctx=canvas.getContext('2d');const w=image.naturalWidth*scale,h=image.naturalHeight*scale;
          ctx.drawImage(image,(side-w)/2,(side-h)/2,w,h);
          confirm.disabled=true;confirm.textContent='در حال آماده‌سازی…';
          canvas.toBlob(blob=>{{
            if(!blob){{confirm.disabled=false;confirm.textContent='تأیید و ثبت پروفایل';alert('آماده‌سازی عکس ناموفق بود');return;}}
            const cropped=new File([blob],'profile.jpg',{{type:'image/jpeg'}});const transfer=new DataTransfer();transfer.items.add(cropped);file.files=transfer.files;
            confirm.textContent='در حال ثبت عکس…';form.submit();
          }},'image/jpeg',.92);
        }});
        document.addEventListener('keydown',e=>{{if(e.key==='Escape'&&modal.classList.contains('open'))closeEditor();}});
      }})();
      </script>
      <div class="setting-edit-overlay" id="cyrus-edit-overlay" role="dialog" aria-modal="true" aria-labelledby="cyrus-edit-title">
        <form class="setting-edit-sheet" method="post" id="cyrus-inline-edit">
          <h3 id="cyrus-edit-title">ویرایش اطلاعات</h3>
          <input type="hidden" name="edit_field" id="cyrus-edit-field">
          <input name="field_value" id="cyrus-edit-input" autocomplete="off" value="{edit_value_html}">
          <textarea name="field_value" id="cyrus-edit-textarea" maxlength="250" rows="4" style="display:none">{edit_value_html}</textarea>
          <p class="setting-error">{html.escape(error)}</p>
          <button type="submit">ذخیره</button>
          <button type="button" class="setting-edit-cancel" onclick="document.getElementById('cyrus-edit-overlay').classList.remove('open')">انصراف</button>
        </form>
      </div>
      <script>
        (function(){{
          const overlay=document.getElementById('cyrus-edit-overlay');
          const field=document.getElementById('cyrus-edit-field');
          const input=document.getElementById('cyrus-edit-input');
          const textarea=document.getElementById('cyrus-edit-textarea');
          const title=document.getElementById('cyrus-edit-title');
          function openEditor(key,value){{
            field.value=key;
            title.textContent=key==='display_name'?'ویرایش نام نمایشی':key==='username'?'ویرایش نام کاربری':'ویرایش بیوگرافی';
            const useBio=key==='bio';
            input.style.display=useBio?'none':'block';
            input.disabled=useBio;
            textarea.style.display=useBio?'block':'none';
            textarea.disabled=!useBio;
            input.value=value;
            textarea.value=value;
            if(key==='username'){{input.minLength=3;input.maxLength=24;input.removeAttribute('pattern');input.required=true;input.dir='ltr';}}
            else if(key==='display_name'){{input.minLength=2;input.maxLength=40;input.removeAttribute('pattern');input.required=true;input.dir='auto';}}
            else{{textarea.maxLength=120;}}
            overlay.classList.add('open');
            setTimeout(()=>{{(useBio?textarea:input).focus();}},40);
          }}
          document.querySelectorAll('[data-edit]').forEach(el=>{{
            el.addEventListener('click',()=>openEditor(el.dataset.edit,el.dataset.current||''));
          }});
          overlay.addEventListener('click',e=>{{if(e.target===overlay)overlay.classList.remove('open');}});
          document.addEventListener('keydown',e=>{{if(e.key==='Escape')overlay.classList.remove('open');}});
          if({str(bool(error)).lower()}) openEditor('{html.escape(edit_field, quote=True)}',document.getElementById('{ 'cyrus-edit-textarea' if edit_field == 'bio' else 'cyrus-edit-input' }').value);
        }})();
      </script>
    </main>
    """
    return page(content)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
