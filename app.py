import os, secrets, requests, html, uuid, time, hashlib, re
from urllib.parse import quote
from pathlib import Path
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
from flask import Flask, request, session, redirect, url_for, render_template, render_template_string

load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
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
<script>
window.addEventListener('pageshow', function(event) {
  const navEntry = performance.getEntriesByType('navigation')[0];
  if ((event.persisted || (navEntry && navEntry.type === 'back_forward')) && (location.pathname === '/' || location.pathname === '/home')) {
    location.reload();
  }
});
</script>
</body>
</html>
"""

def page(content):
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
        <div class="chat-row cyrus-chat-row" data-search="{html.escape(str(room_title) + " " + preview + " " + search_extra, quote=True).lower()}"
             role="link" tabindex="0" aria-label="بازکردن گفتگوی {html.escape(str(room_title), quote=True)}"
             onclick="if(!event.target.closest('.cyrus-remove-chat'))window.location.href='/chat/{room_id}'"
             onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();window.location.href='/chat/{room_id}'}}"
             style="cursor:pointer">
          {avatar_html}
          <div class="chat-info">
            <div class="chat-name">{html.escape(str(room_title))}</div>
            <div class="chat-preview">{html.escape(preview)}</div>
          </div>
          {unread_badge}
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
      <div class="tabs">{tabs}</div>

      <div class="chat-list">{rows}</div>
      <style>
        .cyrus-chat-row{{position:relative;touch-action:pan-y;min-height:64px;padding:8px 12px;background:transparent;border:0;border-bottom:1px solid #24313d;border-radius:0;box-shadow:none;gap:10px}} .cyrus-chat-row .avatar{{width:42px;height:42px;min-width:42px;flex:0 0 42px;font-size:18px}} .cyrus-chat-row .chat-info{{min-width:0;flex:1;padding:0 2px}} .cyrus-chat-row .chat-name{{font-size:14px;font-weight:600;color:#e8edf3;line-height:1.5}} .cyrus-chat-row .chat-preview{{font-size:12px;color:#94a5b4;line-height:1.45;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}} .cyrus-chat-row .unread-badge{{min-width:18px;height:18px;padding:0 5px;font-size:10px;display:flex;align-items:center;justify-content:center;border-radius:10px}} .cyrus-chat-row .cyrus-remove-chat button{{font-size:11px;padding:5px 8px}}
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
          <a class="action" style="margin:0;padding:10px 14px;text-align:center" href="/user/{safe_id}">نمایش پروفایل</a>
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
    send_link = "" if blocked_by_me else f'<a class="profile-primary-action" href="/start-chat/{safe_id}">ارسال پیام</a>'

    content = f"""<main class="container cyrus-user-profile">
      <style>
        .cyrus-user-profile{{padding:12px 12px 88px;max-width:560px}}
        .user-profile-card{{position:relative;background:#111e2b;border:1px solid #263b50;border-radius:16px;padding:15px 16px 17px;overflow:visible}}
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
        .profile-primary-action{{display:block;text-align:center;margin:12px 0 0;padding:13px;border-radius:12px;background:#248bd0;color:#fff;text-decoration:none;font-size:15px}}
        .profile-blocked-note{{margin:12px 0 0;color:#f1aeb4;font-size:12px;text-align:center}}
        .profile-contact-edit{{margin-top:12px;background:#111e2b;border:1px solid #263b50;border-radius:12px;overflow:hidden}}
        .profile-contact-edit summary{{padding:14px;text-align:center;color:#82bfe8;cursor:pointer;list-style:none}}
        .profile-contact-edit summary::-webkit-details-marker{{display:none}}
        .profile-contact-edit form{{padding:12px 14px;border-top:1px solid #263b50}}
        .profile-contact-edit input{{width:100%;box-sizing:border-box;padding:12px;background:#0a1521;color:#fff;border:1px solid #2a4054;border-radius:9px}}
        .profile-contact-edit button{{margin-top:10px;width:100%;padding:12px;background:#248bd0;color:white;border:0;border-radius:9px}}
      </style>
      <section class="user-profile-card">
        <a class="profile-back" href="/home" aria-label="بازگشت به بارگاه" title="بازگشت">➜</a>
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
        <div class="user-profile-username">@{html.escape(username)}</div>
        <p class="user-profile-bio">{html.escape(bio) if bio else "بیوگرافی اضافه نشده است"}</p>
      </section>
      {send_link}
      {blocked_notice}
      {('<details class="profile-contact-edit" id="cyrusEditContact"><summary>ویرایش مخاطب</summary><form method="post" action="/user/'+safe_id+'/contact/edit"><label>نام مخاطب</label><input name="contact_name" maxlength="60" value="'+html.escape(contact_name,quote=True)+'" placeholder="'+html.escape(name,quote=True)+'"><button type="submit">ذخیره نام مخاطب</button></form></details>') if is_contact else ""}
    </main>
    <script>
    document.addEventListener('click',function(e){{if(!e.target.closest('.profile-more'))document.querySelectorAll('.profile-more[open]').forEach(x=>x.open=false);}});
    </script>"""
    return page(content)


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
        return redirect("/user/" + user_id)
    except Exception:
        return page('<div class="container card"><p>ارتباط با سرور برقرار نشد.</p><a href="/user/'+user_id+'">بازگشت</a></div>'), 502


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
    headers = {"apikey":KEY,"Authorization":"Bearer "+session["access_token"]}
    try:
        response = requests.get(
            URL + "/rest/v1/cyrus_conversations",
            params={"select":"id,title,type,created_by,description,avatar_url","id":"eq."+conversation_id,"limit":"1"},
            headers=headers,timeout=20
        )
        if not response.ok or not response.json():
            return page('<main class="container"><div class="empty">پروفایل مجموعه پیدا نشد</div></main>'),404
        room=response.json()[0]
        members_response=requests.get(
            URL + "/rest/v1/cyrus_members",
            params={"select":"user_id,role","conversation_id":"eq."+conversation_id},
            headers=headers,timeout=20
        )
        members=members_response.json() if members_response.ok else []
    except Exception:
        return page('<main class="container"><div class="empty">ارتباط با سرور برقرار نشد</div></main>'),502
    title=html.escape(str(room.get("title") or "گفتگو"))
    desc=html.escape(str(room.get("description") or ""))
    avatar=str(room.get("avatar_url") or "")
    avatar_html=('<img src="'+html.escape(avatar,quote=True)+'" alt="">') if avatar else '<div class="profile-room-symbol">𓊹</div>'
    kind={"group":"گروه","channel":"کانال"}.get(str(room.get("type") or ""),"گفتگوی خصوصی")
    uid=str(session.get("user_id") or "")
    owner=str(room.get("created_by") or "")==uid
    role=next((str(m.get("role") or "") for m in members if str(m.get("user_id") or "")==uid),"")
    manage_link=f'<a class="profile-room-action" href="/rooms/{conversation_id}/manage">مدیریت {kind}</a>' if owner or role in ("admin","owner") else ""
    content=f"""
    <main class="container cyrus-room-profile">
      <style>
        .cyrus-room-profile{{padding:14px}}
        .room-profile-hero{{text-align:center;padding:24px 16px;background:#111e2b;border:1px solid #263b50;border-radius:18px}}
        .room-profile-hero img,.profile-room-symbol{{width:104px;height:104px;border-radius:50%;object-fit:cover;margin:0 auto 13px;border:2px solid #2d8ecb;display:grid;place-items:center;font-size:42px;color:#d8b46a}}
        .room-profile-hero h2{{margin:5px 0;color:#eef4f8;font-size:21px}}
        .room-profile-kind{{color:#7eb8e2;font-size:13px}}
        .room-profile-bio{{color:#c3cfda;font-size:14px;line-height:1.9;margin:14px 0;white-space:pre-wrap}}
        .room-profile-action{{display:block;margin:10px 0;padding:13px;border-radius:24px;text-align:center;background:#20384d;color:#eaf3fa}}
        .room-profile-actions{{margin-top:12px}}
      </style>
      <section class="room-profile-hero">
        {avatar_html}
        <h2>{title}</h2>
        <div class="room-profile-kind">{kind} · {len(members)} عضو</div>
        <p class="room-profile-bio">{desc or "توضیحی اضافه نشده است"}</p>
      </section>
      <div class="room-profile-actions">
        <a class="profile-room-action" href="/chat/{conversation_id}">بازگشت به گفتگو</a>
        {manage_link}
      </div>
    </main>"""
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
                "select": "id,title,type,created_by,description,avatar_url,history_visible",
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
        response = requests.get(
            URL + "/rest/v1/cyrus_messages",
            params={
                "select": "id,sender_id,content,message_type,created_at,edited_at,metadata",
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
    message_rows = ""
    previous_message_date = None

    for msg in messages:
        mine = str(msg.get("sender_id") or "") == current_user
        css_class = "mine" if mine else "theirs"
        body = cyrus_format_message_text(msg.get("content") or "")
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
        msg_id = html.escape(str(msg.get("id") or ""), quote=True)
        raw_content = html.escape(str(msg.get("content") or ""), quote=True)
        edited_label = " · ویرایش‌شده" if msg.get("edited_at") else ""

        meta = msg.get("metadata") if isinstance(msg.get("metadata"), dict) else {}
        reply_source = html.escape(str(meta.get("reply_to_content") or ""))
        reply_preview = f'<div class="reply-preview">↪ پاسخ به: {reply_source}</div>' if reply_source else ""
        forwarded_label = '<small class="forwarded-label">↗ پیام انتقال‌یافته</small>' if meta.get("forwarded_from_message_id") else ""
        pinned_label = '<small class="pinned-label">📌 سنجاق‌شده</small>' if meta.get("pinned") else ""
        controls = (
            f'<div class="message-context" aria-hidden="true">'
            '<div class="reaction-strip">'
            + ''.join(f'<button type="button" class="reaction-choice" onclick="cyrusReact(event,this)" aria-label="واکنش {emoji}">{emoji}</button>' for emoji in ["❤️","👍","👎","🔥","🥰","👏","🇮🇷"])
            + '</div><div class="context-actions">'
            + f'<button type="button" onclick="cyrusReply(this)" data-id="{msg_id}" data-content="{raw_content}"><span>↶</span> پاسخ</button>'
            + f'<button type="button" onclick="cyrusCopy(this)" data-content="{raw_content}"><span>▢</span> کپی</button>'
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
        <div id="message-{msg_id}" class="message {css_class}" data-content="{raw_content}" data-message-id="{msg_id}" onclick="cyrusOpenMessageMenu(event,this)" role="button" tabindex="0" onkeydown="if(event.key==='Enter'||event.key===' '){{event.preventDefault();cyrusOpenMessageMenu(event,this)}}">
          {reply_preview}{forwarded_label}{pinned_label}
          <div class="message-body">{body}</div>
          <small>{stamp}{edited_label}</small>
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
                    room_profile_href = "/user/" + other_id + "?from_chat=1"
        except Exception:
            pass
    room_title = html.escape(room_title_text)
    room_description = html.escape(str(room_data.get("description") or ""))
    room_avatar_url = html.escape(room_avatar_source, quote=True)
    room_avatar = (
        f'<img src="{room_avatar_url}" alt="">'
        if room_avatar_url else '<div class="room-avatar-symbol">𓊹</div>'
    )
    room_header = f"""
    <section class="room-header cyrus-chat-header">
      <a class="chat-back" href="/home" aria-label="بازگشت">➜</a>
      <a class="room-avatar" href="{html.escape(room_profile_href, quote=True)}">{room_avatar}</a>
      <a class="room-info" href="{html.escape(room_profile_href, quote=True)}">
        <h2>{room_title}</h2>
        <span class="room-type">{room_last_seen if room_type == 'private' else room_subtitle}</span>
      </a>
      <a class="chat-header-more" href="{html.escape(room_profile_href, quote=True)}" aria-label="پروفایل">⋮</a>
    </section>"""

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
        '<div id="cyrusReplyBar" class="cyrus-reply-composer" style="display:none">'
        '<span id="cyrusReplyText"></span><button type="button" onclick="cyrusCancelReply()">×</button></div>'
        '<input type="hidden" name="reply_to_id" id="cyrusReplyId" value="">'
        '<button class="composer-emoji" type="button" aria-label="ایموجی" onclick="cyrusToggleEmoji(event)">☺</button>'
        '<div class="composer-emoji-panel" id="cyrusEmojiPanel" style="display:none"><emoji-picker id="cyrusFullEmojiPicker" locale="en"></emoji-picker></div>'
        '<script type="module" src="https://cdn.jsdelivr.net/npm/emoji-picker-element@1.29.1/index.js"></script>'
        '<input type="hidden" name="client_nonce" value="">'
        '<input name="content" maxlength="4000" placeholder="پیام بنویسید..." autocomplete="off" required>'
        '<button class="composer-send" type="submit" aria-label="ارسال پیام">➤</button></form>'
        if (room_type != "channel" or channel_can_post) and not room_blocked else
        (
            ('<div class="cyrus-blocked-composer"><p>این کاربر را مسدود کرده‌اید.</p><form method="post" action="/user/' + html.escape(room_other_user_id, quote=True) + '/block"><button type="submit">رفع مسدودیت</button></form></div>' if room_blocked_by_me else
             '<div class="cyrus-blocked-composer"><p>امکان ارسال پیام وجود ندارد.</p></div>')
            if room_blocked else
            '<div class="cyrus-blocked-composer"><p>این کانال فقط برای مالک و مدیران امکان انتشار پیام دارد.</p></div>'
        )
    )

    room_manage_link = (
        f'<p><a href="/rooms/{conversation_id}/manage">مدیریت گروه یا کانال</a></p>'
        if room_type in ("group", "channel") else ""
    )

    content = f"""
    <div class="container">
      {room_header}
      {pinned_banner}
      <style>
        .container:has(.cyrus-chat-header){{max-width:650px;min-height:calc(100dvh - 76px);padding:0 12px 12px;display:flex;flex-direction:column;background:linear-gradient(180deg,rgba(7,16,27,.76),rgba(5,12,21,.9));}}
        .cyrus-chat-header{{position:sticky;top:0;z-index:8;flex:0 0 auto;box-shadow:0 4px 16px #0003}}
        .messages-area{{flex:1 1 auto;min-height:45vh;}}
        .chat-date-divider{{display:flex;justify-content:center;margin:8px 0 12px;pointer-events:none}}
        .chat-date-divider span{{padding:5px 12px;border-radius:14px;background:#253646dd;color:#c4d3df;font-size:11px;}}
        .message{{max-width:min(84%,480px);padding:9px 12px 7px;backdrop-filter:blur(5px);transition:background .15s,border-color .15s}}
        .message .message-body{{white-space:normal;word-break:break-word;}}
        .message .message-body a.chat-inline-link{{color:#8acbff;text-decoration:underline;text-underline-offset:2px;}}
        .message small{{display:flex;align-items:center;justify-content:flex-end;gap:5px;direction:ltr}}
        .message.context-open{{z-index:12;border-color:#e2bd6b;box-shadow:0 4px 20px #0006}}
        .send-box{{position:sticky;bottom:calc(8px + env(safe-area-inset-bottom));flex:0 0 auto;margin:8px 0 0;min-height:54px;border-radius:27px;background:#172432;border:1px solid #2b4053;box-shadow:0 4px 18px #0006;}}
        .send-box input[name="content"]{{color:#edf4fa;line-height:1.5;}}
        .composer-emoji,.composer-send{{width:38px;height:38px;flex:0 0 38px;display:grid;place-items:center;margin:0;padding:0;border-radius:50%;font-size:22px}}
        .composer-emoji{{background:transparent;color:#a9bdce;border:0}}
        .composer-send{{background:#268bd0;color:#fff;font-size:20px;transform:scaleX(-1)}}
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
        .reaction-choice{{width:auto;min-width:0;margin:0;padding:3px 2px;background:transparent;border:0;border-radius:50%;font-size:25px;line-height:1.25}}
        .context-actions{{display:flex;flex-direction:column;padding:6px 0;border-radius:12px;background:#253747;border:1px solid #344b5e;overflow:hidden}}
        .context-actions>button,.context-actions form>button{{display:flex;align-items:center;gap:16px;width:100%;margin:0;padding:12px 18px;border:0;border-radius:0;background:transparent;color:#edf4f8;text-align:right;font-size:15px;font-weight:normal}}
        .context-actions button span{{width:24px;text-align:center;color:#9db2c2;font-size:20px}}
        .context-actions button:active{{background:#344b5e}}
        .context-actions form{{display:flex;flex-direction:column;gap:5px;margin:0}}
        .context-actions select{{width:calc(100% - 24px);margin:6px 12px;max-width:none;background:#0b1422;color:#fff;border:1px solid #526a7d;border-radius:7px;padding:9px}}
        .context-actions form>button{{justify-content:flex-start}}
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
      function cyrusOpenMessageMenu(event,message) {{
        if(event.target.closest('.message-context')) return;
        if(event.target.closest('button,form,select,input,a')) return;
        document.querySelectorAll('.message.context-open').forEach(el=>el.classList.remove('context-open'));
        message.classList.add('context-open');
        const menu=message.querySelector('.message-context');
        if(menu)menu.setAttribute('aria-hidden','false');
        event.stopPropagation();
      }}
      document.addEventListener('click',function(event){{
        if(!event.target.closest('.message.context-open')) {{
          document.querySelectorAll('.message.context-open').forEach(el=>{{
            el.classList.remove('context-open');
            const menu=el.querySelector('.message-context');
            if(menu)menu.setAttribute('aria-hidden','true');
          }});
        }}
      }});
      function cyrusReact(event,button) {{
        event.preventDefault();event.stopPropagation();
        const message=button.closest('.message');
        if(!message)return;
        message.dataset.reaction=button.textContent;
        message.classList.add('reacted');
        message.classList.remove('context-open');
      }}
      function cyrusReply(button) {{
        document.getElementById("cyrusReplyId").value=button.dataset.id||"";
        document.getElementById("cyrusReplyText").textContent="پاسخ به: "+(button.dataset.content||"").slice(0,120);
        document.getElementById("cyrusReplyBar").style.display="block";
        document.querySelector('.send-box input[name="content"]').focus();
      }}
      function cyrusCancelReply() {{
        document.getElementById("cyrusReplyId").value="";
        document.getElementById("cyrusReplyBar").style.display="none";
      }}
      async function cyrusCopy(button) {{
        const value=button.dataset.content||"";
        try {{ await navigator.clipboard.writeText(value); button.textContent="کپی شد"; }}
        catch(e) {{ window.prompt("متن پیام را کپی کنید:",value); }}
      }}
      function cyrusShowForward(button) {{
        const form=button.parentElement.querySelector(".forward-form");
        if(form)form.style.display=form.style.display==="none"?"flex":"none";
      }}
      function cyrusEdit(button) {{
        const message = button.closest('.message');
        const value = prompt('متن پیام را ویرایش کنید:', message.dataset.content);
        if (value === null || !value.trim()) return;
        const form = message.querySelector('.edit-form');
        form.querySelector('[name="content"]').value = value.trim();
        form.submit();
      }}
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



@app.route("/chat/message/<message_id>/pin", methods=["POST"])
def toggle_message_pin(message_id):
    if not session.get("access_token"):
        return redirect("/login")
    conversation_id = str(request.form.get("conversation_id") or "")
    current_user = str(session.get("user_id") or "")
    try:
        uuid.UUID(message_id); uuid.UUID(conversation_id)
    except ValueError:
        return "شناسه پیام یا گفتگو نامعتبر است", 400
    headers = {"apikey":KEY, "Authorization":"Bearer "+session["access_token"],
               "Content-Type":"application/json", "Prefer":"return=minimal"}
    try:
        found = requests.get(URL + "/rest/v1/cyrus_messages",
            params={"select":"id,conversation_id,sender_id,metadata","id":"eq."+message_id,"limit":"1"},
            headers=headers, timeout=15)
        if not found.ok or not found.json() or str(found.json()[0].get("conversation_id")) != conversation_id:
            return "پیام پیدا نشد", 404
        msg=found.json()[0]
        if str(msg.get("sender_id") or "") != current_user:
            return "فعلاً فقط پیام خودتان را می‌توانید سنجاق کنید.", 403
        meta=msg.get("metadata") if isinstance(msg.get("metadata"),dict) else {}
        meta=dict(meta); meta["pinned"]=not bool(meta.get("pinned"))
        saved=requests.patch(URL+"/rest/v1/cyrus_messages",
            params={"id":"eq."+message_id},json={"metadata":meta},headers=headers,timeout=15)
        if not saved.ok:
            return "سنجاق پیام انجام نشد؛ مجوز ویرایش پیام را بررسی کنید.", 403
        return redirect(url_for("chat",conversation_id=conversation_id))
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
            params={"select":"id,type,created_by","id":"eq."+destination,"limit":"1"},
            headers=headers,timeout=15)
        if not dest.ok or not dest.json():
            return "گفتگوی مقصد پیدا نشد",404
        room=dest.json()[0]
        member=requests.get(URL+"/rest/v1/cyrus_members",
            params={"select":"role","conversation_id":"eq."+destination,"user_id":"eq."+current_user,"limit":"1"},
            headers=headers,timeout=15)
        if not member.ok or not member.json():
            return "عضو گفتگوی مقصد نیستید",403
        if room.get("type")=="channel" and str(room.get("created_by") or "")!=current_user and member.json()[0].get("role") not in ("admin","owner"):
            return "در این کانال اجازه انتشار ندارید",403
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
        return redirect(url_for("chat",conversation_id=destination))
    except Exception:
        return "ارتباط با سرور برقرار نشد",502


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


def cyrus_channel_member_picker(title, error=""):
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
    content=f"""
    <main class="container card channel-member-picker"><style>
    .channel-member-picker{{margin:12px;padding:14px;background:#101b28;border:1px solid #263b50;border-radius:16px}}
    .channel-member-picker h2{{font-size:18px;margin:5px 0 8px}}
    .channel-member-picker .channel-contact{{display:flex;align-items:center;gap:12px;padding:12px 4px;border-bottom:1px solid #263442;color:#eaf0f5}}
    .channel-member-picker .channel-contact input{{width:20px;height:20px;margin:0;accent-color:#248bd0;flex:0 0 20px}}
    .channel-member-picker .channel-contact span{{display:flex;flex-direction:column;gap:4px}}
    .channel-member-picker .channel-contact small{{direction:ltr;text-align:right;color:#8ea5b9;font-size:11px}}
    .channel-member-picker .picker-list{{max-height:55vh;overflow:auto}}</style>
    <h2>انتخاب اعضای کانال</h2><p class="muted">{safe_title} · در آغاز حداکثر ۱۰۰ مخاطب</p><p class="error">{html.escape(error)}</p>
    <form method="post" action="/rooms/create" id="channel-members-form">
    <input type="hidden" name="title" value="{safe_title}"><input type="hidden" name="type" value="channel"><input type="hidden" name="action" value="create_channel">
    <div class="picker-list">{rows}</div><p class="muted" id="channel-member-count">۰ نفر انتخاب شده‌اند</p><button type="submit">ساخت کانال و افزودن اعضا</button></form>
    <script>(function(){{const f=document.getElementById('channel-members-form'),b=[...f.querySelectorAll('input[name="member_ids"]')],l=document.getElementById('channel-member-count');function u(){{const n=b.filter(x=>x.checked).length;l.textContent=n+' نفر انتخاب شده‌اند';b.forEach(x=>x.disabled=!x.checked&&n>=100)}}b.forEach(x=>x.addEventListener('change',u));f.addEventListener('submit',e=>{{if(b.filter(x=>x.checked).length>100){{e.preventDefault();alert('حداکثر ۱۰۰ مخاطب را انتخاب کن')}}}});u()}})();</script></main>"""
    return page(content)


def create_room_page(error=""):
    selected=request.args.get("type","group")
    if selected not in ("group","channel"): selected="group"
    group_selected="selected" if selected=="group" else ""
    channel_selected="selected" if selected=="channel" else ""
    content=f"""
    <div class="container"><section class="welcome"><h2>ساخت قلمرو تازه</h2><p>یک گروه یا کانال جدید در CYRUS ایجاد کن</p></section>
    <form class="card" method="post" action="/rooms/create"><h2>اطلاعات مجموعه</h2>
    <input name="title" minlength="2" maxlength="60" placeholder="نام گروه یا کانال" required>
    <select name="type" style="width:100%;padding:14px;margin:8px 0;background:#090f1b;border:1px solid #80643b;border-radius:9px;color:white"><option value="group" {group_selected}>گروه</option><option value="channel" {channel_selected}>کانال</option></select>
    <p class="error">{html.escape(error)}</p><button type="submit">ادامه</button></form><p class="muted"><a class="form-link" href="/contacts">بازگشت به خویشان</a></p></div>"""
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
    if room_type=="channel" and action!="create_channel": return cyrus_channel_member_picker(title)
    member_ids=request.form.getlist("member_ids") if room_type=="channel" else []
    if len(member_ids)>100: return cyrus_channel_member_picker(title,"حداکثر ۱۰۰ مخاطب را انتخاب کن"),400
    uid=str(session.get("user_id") or "")
    headers={"apikey":KEY,"Authorization":"Bearer "+session["access_token"],"Content-Type":"application/json"}
    if room_type=="channel" and member_ids:
        try:
            cr=requests.get(URL+"/rest/v1/cyrus_contacts",params={"select":"contact_user_id","owner_id":"eq."+uid,"contact_user_id":"in.("+",".join(member_ids)+")"},headers=headers,timeout=20)
            valid={str(x.get("contact_user_id")) for x in cr.json()} if cr.ok else set()
            if len(valid)!=len(set(member_ids)): return cyrus_channel_member_picker(title,"فقط مخاطبان ذخیره‌شده را می‌توان در شروع اضافه کرد"),400
        except Exception: return cyrus_channel_member_picker(title,"بررسی مخاطبان انجام نشد؛ دوباره تلاش کن"),502
    try:
        response=requests.post(URL+"/rest/v1/rpc/create_cyrus_room",json={"room_title":title,"room_type":room_type},headers=headers,timeout=20)
        if not response.ok: return create_room_page("ساخت انجام نشد؛ دسترسی پایگاه داده را بررسی کنید"),502
        result=response.json()
        if isinstance(result,list) and result: result=result[0]
        if isinstance(result,dict): result=result.get("create_cyrus_room") or result.get("id")
        room_id=str(uuid.UUID(str(result)))
        failed=[]
        for member_id in dict.fromkeys(member_ids):
            added=requests.post(URL+"/rest/v1/rpc/cyrus_manage_add_member",json={"p_conversation_id":room_id,"p_user_id":member_id},headers=headers,timeout=15)
            if not added.ok: failed.append(member_id)
        if failed: return page('<div class="container card"><p>کانال ساخته شد، اما افزودن بعضی مخاطبان ناموفق بود.</p><a href="/rooms/'+room_id+'/manage">مدیریت اعضا</a><a href="/chat/'+room_id+'">باز کردن کانال</a></div>'),502
        return redirect(url_for("chat",conversation_id=room_id))
    except Exception: return create_room_page("ارتباط با سرور برقرار نشد یا پاسخ نامعتبر بود"),502


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
        my_role = next(
            (m.get("role") for m in members
             if str(m.get("user_id")) == current), None
        )
        if not owner and my_role not in ("owner", "admin"):
            return "فقط مالک یا مدیر اجازه مدیریت دارد", 403

        join_requests = []
        if room_type == "channel":
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
            .tg-room-settings .tg-save{{display:block;width:calc(100% - 32px);margin:16px auto;padding:13px;border:0;border-radius:10px;background:#248bd2;color:white;font-size:15px;font-weight:500}}
            .tg-room-settings hr{{display:none}}
          </style>
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
            <button class="tg-save" type="submit">ذخیره تغییرات</button>
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

          {('<section class="card"><h3>درخواست‌های عضویت (' + str(len(join_requests)) + ')</h3>' + join_request_rows + '</section>') if room_type == "channel" and join_requests else ''}

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
                "select": "id,title,created_by,created_at,is_public",
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

        outcome = result.json()
        if outcome == "requested":
            return redirect("/channels?request_sent=1")
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
            <textarea name="bio" maxlength="250" rows="3">{bio}</textarea>
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
                rows += f'<article class="saved-message-item"><div class="saved-message-text">{text_value}</div><small>{html.escape(stamp)}</small><form method="post" action="/saved-messages/{sid}/delete" onsubmit="return confirm(\'این پیام حذف شود؟\')"><button type="submit">حذف</button></form></article>'
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
        .saved-message-item form{{text-align:left;margin-top:8px}}
        .saved-message-item button{{background:transparent;color:#e6a5a5;border:1px solid #5a3c45;border-radius:8px;padding:5px 12px}}
        .saved-messages-error{{color:#f1aeb4;text-align:center}}
      </style>
      <header class="saved-messages-header"><a class="saved-messages-back" href="/settings" aria-label="بازگشت">➜</a><h2>پیام‌های ذخیره‌شده</h2></header>
      <form class="saved-messages-form" method="post" action="/saved-messages/add">
        <textarea name="content" maxlength="10000" placeholder="یادداشت، متن یا لینک مهم را برای خودت ذخیره کن..." required></textarea>
        <button type="submit">ذخیره پیام</button>
      </form>
      <p class="saved-messages-error">{html.escape(error)}</p>
      {rows or '<p style="text-align:center;color:#8ea5b9">هنوز پیامی ذخیره نکرده‌ای.</p>'}
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
          <a class="s-button" href="/saved-messages"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M5 3h14v18l-7-4-7 4z"/><path d="M8 7h8M8 10h8"/></svg></span><span class="button-title">پیام‌های ذخیره‌شده</span><span>‹</span></a>
          <a class="s-button" href="https://t.me/CyrusSupport_Aria" target="_blank" rel="noopener noreferrer"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M21.5 3.5 18 20.2a1.5 1.5 0 0 1-2.4.8l-4.7-3.5-2.3 2.2a1 1 0 0 1-1.7-.6l-.8-5.2L2.4 11a1.4 1.4 0 0 1 .1-2.6L20 2.8a1.2 1.2 0 0 1 1.5.7Z"/><path d="m6.2 13.7 11.2-8.1-6.5 11.9"/></svg></span><span class="button-title">پشتیبانی رسمی سرزمین‌های پارس</span><span>‹</span></a>
          <a class="s-button" href="/contacts"><span class="buttons-icons"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="4"/><path d="M2 21v-2a7 7 0 0 1 14 0v2M17 4a4 4 0 0 1 0 8M18 16a5 5 0 0 1 4 5"/></svg></span><span class="button-title">خویشان و مخاطبان</span><span>‹</span></a>
          <button class="s-button" type="button" onclick="navigator.clipboard.writeText(document.getElementById('cyrus-settings-share').value).then(()=>alert('شناسه کپی شد'))"><span class="buttons-icons"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg></span><span class="button-title">کپی شناسه برای دوستان</span><span>‹</span></button>
          <a class="s-button" href="/logout"><span class="buttons-icons"><svg viewBox="0 0 24 24"><path d="M10 17l5-5-5-5M15 12H3"/><path d="M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7"/></svg></span><span class="button-title">خروج از حساب</span><span>‹</span></a>
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
            else{{textarea.maxLength=250;}}
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
