import os, secrets, requests, html, uuid, time
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask, request, session, redirect, url_for, render_template, render_template_string

load_dotenv()
app = Flask(__name__)
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
app.permanent_session_lifetime = timedelta(days=365)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

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
            session["refresh_token"] = data.get("refresh_token", "")
            session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
            session.permanent = True
            session["refresh_token"] = data.get("refresh_token", refresh_token)
            session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
            session.permanent = True
        else:
            session["token_expires_at"] = time.time() + 60
    except Exception:
        session["token_expires_at"] = time.time() + 60

URL = os.getenv("SUPABASE_URL", "").rstrip("/")
KEY = os.getenv("SUPABASE_KEY", "")

BASE = """
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
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
<header class="top">
 <div class="brand">
  <div class="emblem"><img src="/static/cyrus-cylinder.jpg" alt="منشور کوروش بزرگ"></div>
  <div><div class="logo">CYRUS</div><div class="sub">پیوند پارسیان · شکوه هخامنشی</div></div>
 </div>
 <div class="top-actions">
  <a href="/search" aria-label="جستجو">⌕</a>
  <a href="/settings" aria-label="فرمان">⚙</a>
 </div>
</header>
{{ content|safe }}
{{ nav|safe }}
</body>
</html>
"""

def page(content):
    nav = ""
    if session.get("access_token"):
        current = request.path
        items = [
            ("/home", "▣", "پیام‌ها"),
            ("/contacts", "♧", "مخاطبین"),
            ("/search", "⌕", "جستجو"),
            ("/profile", "◉", "پروفایل"),
            ("/settings", "⚙", "تنظیمات")
        ]
        links = ""
        for href, icon, label in items:
            active = "current" if current == href or (href == "/home" and current == "/") else ""
            links += f'<a class="{active}" href="{href}"><span>{icon}</span>{label}</a>'
        nav = f'<nav class="bottom">{links}</nav>'
    return render_template_string(BASE, content=content, nav=nav)

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
    error = ""

    try:
        memberships = requests.get(
            URL + "/rest/v1/cyrus_members",
            params={
                "select": "conversation_id",
                "user_id": "eq." + session["user_id"]
            },
            headers=headers,
            timeout=20
        )

        if not memberships.ok:
            raise Exception("دریافت عضویت‌ها ناموفق بود")

        room_ids = list(dict.fromkeys(
            str(x["conversation_id"])
            for x in memberships.json()
            if x.get("conversation_id")
        ))

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

    tabs = "".join(
        f'<a class="tab {"active" if key == selected else ""}" href="/home?type={key}">{item[0]}</a>'
        for key, item in categories.items()
    )

    rows = ""

    for room in conversations:
        room_type = str(room.get("type") or "private")

        if selected != "all" and room_type != selected:
            continue

        room_id = str(room.get("id") or "")
        try:
            uuid.UUID(room_id)
        except ValueError:
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

        rows += f"""
        <a class="chat-row" href="/chat/{room_id}">
          <div class="avatar">{icon}</div>
          <div class="chat-info">
            <div class="chat-name">{html.escape(str(room_title))}</div>
            <div class="chat-preview">{html.escape(preview)}</div>
          </div>
        </a>"""

    if not rows and not error:
        rows = '<div class="empty"><h3>هیچ گفتگویی موجود نیست</h3></div>'

    content = f"""
    <div class="container">

      <div class="tabs">{tabs}</div>

      <div class="chat-list">{rows}</div>
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
        email = request.form.get("email","").strip()
        password = request.form.get("password","")
        password_confirm = request.form.get("password_confirm","")
        username = request.form.get("username","").strip()
        if not email or not password or not password_confirm or not username:
            error = "همه بخش‌ها را تکمیل کنید"
        elif password != password_confirm:
            error = "رمزهای عبور با یکدیگر مطابقت ندارند"
        else:
            code, data = auth_request("/auth/v1/signup", {"email":email,"password":password})
            if code in (200,201) and data.get("access_token"):
                session["access_token"] = data["access_token"]
                session["refresh_token"] = data.get("refresh_token", "")
                session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
                session.permanent = True
                session["user_id"] = data["user"]["id"]
                requests.post(URL + "/rest/v1/cyrus_profiles",
                    json={"id":data["user"]["id"],"username":username,"display_name":username},
                    headers={"apikey":KEY,"Authorization":"Bearer "+data["access_token"],
                    "Content-Type":"application/json","Prefer":"resolution=merge-duplicates"},
                    timeout=20)
                return redirect(url_for("home"))
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


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            error = "ایمیل را وارد کنید"
        else:
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
            session["access_token"] = data["access_token"]
            session["refresh_token"] = data.get("refresh_token", "")
            session["token_expires_at"] = time.time() + int(data.get("expires_in", 3600))
            session.permanent = True
            session["user_id"] = data["user"]["id"]
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
    </div></main>
    """
    return page(content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/search", methods=["GET"])
def search():
    if not session.get("access_token"):
        return redirect(url_for("login"))

    raw_query = request.args.get("q", "").strip()
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
            # جستجوی افراد
            people_response = requests.get(
                URL + "/rest/v1/cyrus_profiles",
                params={
                    "select": "id,username,display_name,bio",
                    "id": "neq." + str(session.get("user_id", "")),
                    "or": "(username.ilike.*" + query + "*,display_name.ilike.*" + query + "*)",
                    "limit": "50"
                },
                headers=headers,
                timeout=20
            )

            if people_response.ok:
                people = people_response.json()

            # جستجوی گروه‌ها و کانال‌ها
            room_response = requests.get(
                URL + "/rest/v1/cyrus_conversations",
                params={
                    "select": "id,title,type,created_by",
                    "type": "in.(group,channel)",
                    "title": "ilike.*" + query + "*",
                    "order": "created_at.desc",
                    "limit": "100"
                },
                headers=headers,
                timeout=20
            )

            if room_response.ok:
                rooms = room_response.json()

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
                joined_ids = {
                    str(item.get("conversation_id"))
                    for item in membership_response.json()
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
        <div class="chat-row">
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
        title = str(room.get("title") or "بدون نام")
        room_type = str(room.get("type") or "")
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
        <div class="chat-row">
          <div class="avatar">{icon}</div>
          <div class="chat-info">
            <div class="chat-name">{html.escape(title)}</div>
            <div class="chat-preview">{label}</div>
          </div>
          {action}
        </div>
        """

    if query and not people_rows and not room_rows and not error:
        empty = '<div class="empty"><h3>نتیجه‌ای پیدا نشد</h3></div>'
    else:
        empty = ""

    content = f"""
    <div class="container">
      <form class="searchbar" method="get" action="/search"
            style="display:flex;align-items:center;gap:8px;margin:12px 16px;padding:4px 12px;border-radius:14px;background:rgba(12,22,38,.92);border:1px solid rgba(190,151,82,.45)">
        <input name="q" value="{html.escape(query, quote=True)}"
               placeholder="جستجوی افراد، گروه‌ها و کانال‌ها"
               autocomplete="off" autofocus
               style="flex:1;min-width:0;background:transparent;border:0;outline:0;box-shadow:none;padding:12px 4px;color:#fff">
        <button type="submit" aria-label="جستجو"
                style="margin:0;padding:8px 10px;background:transparent;border:0;box-shadow:none;font-size:25px;color:#d6b36a">⌕</button>
      </form>

      <p class="error">{html.escape(error)}</p>

      <div class="section-title">𓅃 · افراد و مخاطبین</div>
      <div class="chat-list">{people_rows}</div>

      <div class="section-title">𓆃 · گروه‌ها و کانال‌ها</div>
      <div class="chat-list">{room_rows}</div>

      {empty}
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
        response = requests.get(
            URL + "/rest/v1/cyrus_profiles",
            params={
                "select": "id,username,display_name,bio,avatar_url",
                "id": "neq." + session.get("user_id", ""),
                "order": "username.asc"
            },
            headers=headers,
            timeout=20
        )
        if response.ok:
            users = response.json()
        else:
            error = "دریافت مخاطبان انجام نشد"
    except Exception:
        error = "ارتباط با سرور برقرار نشد"

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

        rows += f"""
        <div class="chat-row">
          <div class="avatar">𓅃</div>
          <div class="chat-info">
            <div class="chat-name">{html.escape(name)}</div>
            <div class="chat-preview">@{html.escape(username)} · {html.escape(bio)}</div>
          </div>
          <form method="post" action="/start-chat/{safe_id}">
            <button type="submit">شروع گفتگو</button>
          </form>
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


@app.route("/start-chat/<user_id>", methods=["POST"])
def start_chat(user_id):
    if not session.get("access_token"):
        return redirect("/login")

    try:
        uuid.UUID(user_id)
    except ValueError:
        return redirect("/contacts?error=شناسه%20کاربر%20نامعتبر%20است")

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            URL + "/rest/v1/rpc/create_direct_conversation",
            json={"other_user": user_id},
            headers=headers,
            timeout=20
        )

        if response.ok:
            room_id = response.json()
            if isinstance(room_id, str):
                room_id = str(uuid.UUID(room_id))
                return redirect(url_for("chat", conversation_id=room_id))

        return redirect("/contacts?error=ساخت%20گفتگو%20انجام%20نشد")
    except Exception:
        return redirect("/contacts?error=ارتباط%20با%20سرور%20برقرار%20نشد")


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
                "select": "id,title,type,created_by,description,avatar_url",
                "id": "eq." + conversation_id
            },
            headers=headers,
            timeout=20
        )

        if not room.ok or not room.json():
            return page('<div class="container card"><h3>گفتگو پیدا نشد یا دسترسی ندارید</h3><a href="/contacts">بازگشت به خویشان</a></div>'), 404

        response = requests.get(
            URL + "/rest/v1/cyrus_messages",
            params={
                "select": "id,sender_id,content,message_type,created_at",
                "conversation_id": "eq." + conversation_id,
                "order": "created_at.asc",
                "limit": "200"
            },
            headers=headers,
            timeout=20
        )

        if not response.ok:
            return page('<div class="container card"><p>دریافت پیام‌ها ناموفق بود</p></div>'), 502

        messages = response.json()
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'), 502

    current_user = session.get("user_id", "")
    message_rows = ""

    for msg in messages:
        mine = str(msg.get("sender_id") or "") == current_user
        css_class = "mine" if mine else "theirs"
        body = html.escape(str(msg.get("content") or "")).replace("\n", "<br>")
        stamp = html.escape(str(msg.get("created_at") or ""))

        message_rows += f"""
        <div class="message {css_class}">
          <div>{body}</div>
          <small>{stamp}</small>
        </div>"""

    if not message_rows:
        message_rows = '<div class="empty">هنوز پیامی ارسال نشده؛ اولین پیام را بفرستید</div>'

    room_data = room.json()[0]
    room_title = html.escape(str(room_data.get("title") or "گفتگو"))
    room_description = html.escape(str(room_data.get("description") or ""))
    room_avatar_url = html.escape(str(room_data.get("avatar_url") or ""), quote=True)
    room_type_label = {"group": "گروه", "channel": "کانال", "private": "گفتگوی خصوصی"}.get(str(room_data.get("type") or ""), "گفتگو")
    room_avatar = (
        f'<img src="{room_avatar_url}" alt="">'
        if room_avatar_url else '<div class="room-avatar-symbol">𓊹</div>'
    )
    room_header = f"""
    <section class="room-header">
      <div class="room-avatar">{room_avatar}</div>
      <div class="room-info">
        <h2>{room_title}</h2>
        <span class="room-type">{room_type_label} · CYRUS</span>
        <p>{room_description}</p>
      </div>
    </section>"""

    room_type = str(room_data.get("type") or "")
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
        f'<form class="send-box" method="post" action="/chat/{conversation_id}/send">'
        '<input name="content" maxlength="4000" placeholder="پیام خود را بنویسید..." required>'
        '<button type="submit">ارسال</button></form>'
        if room_type != "channel" or channel_can_post else
        '<div class="card"><p>این کانال عمومی است؛ اعضا فقط می‌توانند پست‌ها را مشاهده کنند.</p></div>'
    )

    room_manage_link = (
        f'<p><a href="/rooms/{conversation_id}/manage">مدیریت گروه یا کانال</a></p>'
        if room_type in ("group", "channel") else ""
    )

    content = f"""
    <div class="container">
      {room_header}
      <style>
        .room-header{{display:flex;align-items:center;gap:14px;padding:16px;margin-bottom:14px;border:1px solid #987039;border-radius:16px;background:rgba(9,15,25,.94)}}
        .room-avatar{{width:58px;height:58px;flex:0 0 58px;border-radius:50%;overflow:hidden;border:1px solid #987039;background:#111b2b;display:flex;align-items:center;justify-content:center}}
        .room-avatar img{{width:100%;height:100%;object-fit:cover}}
        .room-avatar-symbol{{font-size:27px;color:#d8b46a}}
        .room-info{{min-width:0}}
        .room-info h2{{margin:0 0 5px;font-size:19px;overflow-wrap:anywhere}}
        .room-type{{font-size:11px;color:#d8b46a}}
        .room-info p{{margin:6px 0 0;color:#c4c6cc;font-size:13px;overflow-wrap:anywhere}}

        .messages-area{{display:flex;flex-direction:column;gap:12px;padding:12px 0}}
        .message{{max-width:85%;padding:12px 15px;border:1px solid #987039;border-radius:14px;background:rgba(9,15,25,.92);overflow-wrap:anywhere}}
        .message small{{display:block;color:#b0b2b7;font-size:10px;margin-top:7px}}
        .message.mine{{align-self:flex-start;border-color:#278bdc}}
        .message.theirs{{align-self:flex-end}}
        .send-box{{position:sticky;bottom:75px;background:rgba(9,15,25,.95);padding:12px;border:1px solid #987039;border-radius:12px}}
      </style>
      <div class="card messages-area">{message_rows}</div>
      {send_box}
      {room_manage_link}
      <p><a href="/contacts">بازگشت به خویشان</a></p>
    </div>"""
    return page(content)


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
                "select": "id,type,created_by",
                "id": "eq." + conversation_id,
                "limit": "1"
            },
            headers=headers,
            timeout=20
        )

        if not room_response.ok or not room_response.json():
            return "گفتگو پیدا نشد یا دسترسی ندارید", 403

        room = room_response.json()[0]

        # برای گفتگوهای غیرکانال، فرستنده باید عضو گفتگو باشد.
        if room.get("type") != "channel":
            membership = requests.get(
                URL + "/rest/v1/cyrus_members",
                params={
                    "select": "user_id",
                    "conversation_id": "eq." + conversation_id,
                    "user_id": "eq." + current_user,
                    "limit": "1"
                },
                headers=headers,
                timeout=20
            )
            if not membership.ok or not membership.json():
                return "شما عضو این گفتگو نیستید", 403

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
                "message_type": "text"
            },
            headers=headers,
            timeout=20
        )

        if not response.ok:
            return page(
                '<div class="container card"><p>ارسال پیام انجام نشد؛ '
                'ممکن است عضو این گفتگو نباشید</p>'
                '<a href="/contacts">بازگشت</a></div>'
            ), 403

    except Exception:
        return page(
            '<div class="container card"><p>ارتباط با سرور برقرار نشد</p></div>'
        ), 502

    return redirect(url_for("chat", conversation_id=conversation_id))



def create_room_page(error=""):
    selected = request.args.get("type", "group")
    if selected not in ("group", "channel"):
        selected = "group"

    group_selected = "selected" if selected == "group" else ""
    channel_selected = "selected" if selected == "channel" else ""

    content = f"""
    <div class="container">
      <section class="welcome">
        <h2>ساخت قلمرو تازه</h2>
        <p>یک گروه یا کانال جدید در CYRUS ایجاد کن</p>
      </section>
      <form class="card" method="post" action="/rooms/create">
        <h2>اطلاعات مجموعه</h2>
        <input name="title" minlength="2" maxlength="60" placeholder="نام گروه یا کانال" required>
        <select name="type" style="width:100%;padding:14px;margin:8px 0;background:#090f1b;border:1px solid #80643b;border-radius:9px;color:white">
          <option value="group" {group_selected}>گروه</option>
          <option value="channel" {channel_selected}>کانال</option>
        </select>
        <p class="error">{html.escape(error)}</p>
        <button type="submit">ساخت و ثبت</button>
      </form>
      <p class="muted"><a class="form-link" href="/">بازگشت به بارگاه</a></p>
    </div>
    """
    return page(content)


@app.route("/rooms/create", methods=["GET", "POST"])
def create_room():
    if not session.get("access_token"):
        return redirect("/login")

    if request.method == "GET":
        return create_room_page()

    title = request.form.get("title", "").strip()
    room_type = request.form.get("type", "").strip()

    if len(title) < 2 or len(title) > 60:
        return create_room_page("نام باید بین ۲ تا ۶۰ حرف باشد"), 400

    if room_type not in ("group", "channel"):
        return create_room_page("نوع مجموعه نامعتبر است"), 400

    headers = {
        "apikey": KEY,
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            URL + "/rest/v1/rpc/create_cyrus_room",
            json={"room_title": title, "room_type": room_type},
            headers=headers,
            timeout=20
        )

        if not response.ok:
            return create_room_page("ساخت انجام نشد؛ دسترسی پایگاه داده را بررسی کنید"), 502

        result = response.json()
        if isinstance(result, list) and result:
            result = result[0]
        if isinstance(result, dict):
            result = result.get("create_cyrus_room") or result.get("id")

        room_id = str(uuid.UUID(str(result)))
        return redirect(url_for("chat", conversation_id=room_id))

    except Exception:
        return create_room_page("ارتباط با سرور برقرار نشد یا پاسخ نامعتبر بود"), 502



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
                "select": "id,title,type,created_by,description,avatar_url,invite_code,reactions_enabled",
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
        my_role = next(
            (m.get("role") for m in members
             if str(m.get("user_id")) == current), None
        )
        if not owner and my_role not in ("owner", "admin"):
            return "فقط مالک یا مدیر اجازه مدیریت دارد", 403

        if request.method == "POST":
            action = request.form.get("action", "")
            data = {"p_conversation_id": conversation_id}
            rpc = None

            if action == "save_settings":
                title = request.form.get("title", "").strip()
                description = request.form.get("description", "").strip()
                avatar_url = request.form.get("avatar_url", "").strip()
                reactions = request.form.get("reactions_enabled") == "on"

                if not 2 <= len(title) <= 60:
                    return "نام باید بین ۲ تا ۶۰ حرف باشد", 400
                if len(description) > 500:
                    return "توضیحات حداکثر ۵۰۰ حرف باشد", 400
                if len(avatar_url) > 500:
                    return "آدرس تصویر بیش از حد طولانی است", 400

                rpc = "cyrus_manage_update_room_settings"
                data.update({
                    "p_title": title,
                    "p_description": description,
                    "p_avatar_url": avatar_url or None,
                    "p_reactions_enabled": reactions
                })

            elif action == "rotate_invite":
                rpc = "cyrus_manage_rotate_invite"

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

                data["p_user_id"] = uid
                if action == "remove":
                    rpc = "cyrus_manage_remove_member"
                else:
                    if not owner:
                        return "فقط مالک می‌تواند مدیر تعیین یا عزل کند", 403
                    rpc = "cyrus_manage_set_role"
                    data["p_role"] = "admin" if action == "promote" else "member"

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
            safe_role = html.escape(role)

            controls = ""
            if uid != str(room.get("created_by") or ""):
                if owner and role == "member":
                    controls += (
                        '<form method="post"><input type="hidden" name="action" value="promote">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>تعیین مدیر</button></form>'
                    )
                if owner and role == "admin":
                    controls += (
                        '<form method="post"><input type="hidden" name="action" value="demote">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>عزل مدیر</button></form>'
                    )
                if owner or (my_role == "admin" and role == "member"):
                    controls += (
                        '<form method="post" onsubmit="return confirm(\'عضو حذف شود؟\')">'
                        '<input type="hidden" name="action" value="remove">'
                        '<input type="hidden" name="user_id" value="' + safe_uid + '">'
                        '<button>حذف عضو</button></form>'
                    )

            rows += (
                '<div class="card"><p>شناسه عضو: ' + safe_uid
                + '</p><p>نقش: ' + safe_role + '</p>' + controls + '</div>'
            )

        if not rows:
            rows = '<p class="muted">هنوز عضوی وجود ندارد</p>'

        content = f"""
        <div class="container">
          <section class="welcome">
            <h2>تنظیمات {kind}</h2>
            <p>{title}</p>
            <p class="muted">{subtitle}</p>
          </section>

          <form class="card" method="post">
            <h3>اطلاعات {kind}</h3>
            <input type="hidden" name="action" value="save_settings">
            <label>نام</label>
            <input name="title" minlength="2" maxlength="60" value="{title}" required>
            <label>توضیحات</label>
            <textarea name="description" maxlength="500" rows="4">{description}</textarea>
            <label>آدرس تصویر (اختیاری)</label>
            <input name="avatar_url" maxlength="500" value="{avatar_url}" placeholder="https://...">
            <label><input type="checkbox" name="reactions_enabled" {reactions_checked}> فعال بودن واکنش‌ها</label>
            <button type="submit">ذخیره تنظیمات</button>
          </form>

          <div class="card">
            <h3>لینک دعوت</h3>
            <input id="invite-link" readonly value="{invite_safe}">
            <button type="button" onclick="navigator.clipboard.writeText(document.getElementById('invite-link').value).then(()=>alert('لینک کپی شد'))">کپی لینک</button>
            <form method="post" onsubmit="return confirm('لینک قبلی از کار می‌افتد. ادامه می‌دهید؟')">
              <input type="hidden" name="action" value="rotate_invite">
              <button>ساخت لینک جدید</button>
            </form>
          </div>

          <div class="card">
            <h3>افزودن عضو</h3>
            <form method="post">
              <input type="hidden" name="action" value="add">
              <input name="username" placeholder="نام کاربری عضو" required>
              <button>افزودن عضو</button>
            </form>
          </div>

          <h3>اعضا ({len(members)})</h3>
          {rows}

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
                "select": "id,title,created_by,created_at",
                "type": "eq.channel",
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
                action = (
                    f'<form method="post" action="/channels/join/{cid}">'
                    '<button type="submit">عضویت در کانال</button></form>'
                )

            rows += (
                '<div class="card"><h3>' + title + '</h3>'
                '<p class="muted">کانال عمومی CYRUS</p>'
                + action + '</div>'
            )

        if not rows:
            rows = '<div class="empty"><h3>هنوز کانال عمومی ساخته نشده است</h3></div>'

        content = (
            '<div class="container"><section class="welcome">'
            '<h2>کانال‌های عمومی</h2>'
            '<p>کانال‌های قابل دسترس در CYRUS</p></section>'
            + rows +
            '<p class="muted"><a href="/contacts">بازگشت</a></p></div>'
        )
        return page(content)

    except Exception:
        return page(
            '<div class="container card"><p>دریافت کانال‌ها ناموفق بود</p>'
            '<a href="/">بازگشت</a></div>'
        ), 502


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
        "Authorization": "Bearer " + session["access_token"],
        "Content-Type": "application/json"
    }

    try:
        result = requests.post(
            URL + "/rest/v1/rpc/cyrus_channel_join",
            json={"p_conversation_id": conversation_id},
            headers=headers,
            timeout=20
        )
        if not result.ok:
            return page(
                '<div class="container card"><p>عضویت انجام نشد</p>'
                '<a href="/channels">بازگشت به کانال‌ها</a></div>'
            ), 400

        return redirect(url_for("chat", conversation_id=conversation_id))

    except Exception:
        return "ارتباط با سرور برقرار نشد", 502


@app.route("/invite/<invite_code>", methods=["GET"])
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

    try:
        result = requests.post(
            URL + "/rest/v1/rpc/cyrus_join_by_invite",
            json={"p_invite_code": invite_code},
            headers=headers,
            timeout=20
        )
        if not result.ok:
            return page(
                '<div class="container card"><p>عضویت با این لینک انجام نشد؛ '
                'ممکن است لینک منقضی یا نامعتبر باشد.</p>'
                '<a href="/">بازگشت به بارگاه</a></div>'
            ), 400

        value = result.json()
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, dict):
            value = value.get("cyrus_join_by_invite") or value.get("id")

        room_id = str(uuid.UUID(str(value)))
        return redirect(url_for("chat", conversation_id=room_id))

    except Exception:
        return page(
            '<div class="container card"><p>پیوستن به مجموعه ناموفق بود</p>'
            '<a href="/">بازگشت</a></div>'
        ), 502


@app.route("/profile")
def profile():
    if not session.get("access_token"):
        return redirect("/login")
    return page('<main class="container"><div class="card"><h2>نگاره</h2><p class="muted">پروفایل کاربری CYRUS</p><a class="form-link" href="/">بازگشت به بارگاه</a></div></main>')

@app.route("/settings")
def settings():
    if not session.get("access_token"):
        return redirect("/login")
    return page('<main class="container"><div class="card"><h2>فرمان</h2><p class="muted">تنظیمات CYRUS</p><p class="muted"><a class="form-link" href="/logout">خروج از حساب</a></p></div></main>')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
