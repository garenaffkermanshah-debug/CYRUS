import os, uuid, html, mimetypes
from datetime import datetime, timezone
from urllib.parse import quote
import requests
from flask import request, session, redirect

STORY_BUCKET = "cyrus-stories"
MAX_STORY_BYTES = 20 * 1024 * 1024

def register_story_routes(app, URL, KEY, ADMIN_KEY, page):
    def admin_headers(extra=None):
        h={"apikey":ADMIN_KEY,"Content-Type":"application/json"}
        if not ADMIN_KEY.startswith("sb_secret_"): h["Authorization"]="Bearer "+ADMIN_KEY
        if extra: h.update(extra)
        return h
    def user_headers(extra=None):
        h={"apikey":KEY,"Authorization":"Bearer "+str(session.get("access_token") or ""),"Content-Type":"application/json"}
        if extra: h.update(extra)
        return h
    def signed_media(path):
        if not path:return ""
        try:
            r=requests.post(URL+"/storage/v1/object/sign/"+STORY_BUCKET+"/"+quote(path,safe="/"),json={"expiresIn":3600},headers=admin_headers(),timeout=20)
            if r.ok:
                u=r.json().get("signedURL") or r.json().get("signedUrl") or ""
                if u.startswith("/"): return URL+("/storage/v1"+u if u.startswith("/object") else u)
                return u
        except Exception:pass
        return ""
    def profiles_for(ids):
        ids=list(dict.fromkeys(str(x) for x in ids if x))
        if not ids:return {}
        try:
            r=requests.get(URL+"/rest/v1/cyrus_profiles",params={"select":"id,username,display_name,avatar_url","id":"in.("+",".join(ids)+")"},headers=admin_headers(),timeout=15)
            if r.ok:return {str(p.get("id")):p for p in r.json() if isinstance(p,dict)}
        except Exception:pass
        return {}
    def audience_ids(user_id):
        allowed={str(user_id)}
        try:
            r=requests.get(URL+"/rest/v1/cyrus_contacts",params={"select":"contact_user_id","owner_id":"eq."+str(user_id),"limit":"1000"},headers=admin_headers(),timeout=15)
            if r.ok:allowed.update(str(x.get("contact_user_id")) for x in r.json() if x.get("contact_user_id"))
            # Also include users who saved this account as a contact.
            inbound=requests.get(URL+"/rest/v1/cyrus_contacts",params={"select":"owner_id","contact_user_id":"eq."+str(user_id),"limit":"1000"},headers=admin_headers(),timeout=15)
            if inbound.ok:allowed.update(str(x.get("owner_id")) for x in inbound.json() if x.get("owner_id"))
        except Exception:pass
        try:
            m=requests.get(URL+"/rest/v1/cyrus_members",params={"select":"conversation_id","user_id":"eq."+str(user_id),"limit":"1000"},headers=admin_headers(),timeout=15)
            rooms=[str(x.get("conversation_id")) for x in m.json() if x.get("conversation_id")] if m.ok else []
            if rooms:
                c=requests.get(URL+"/rest/v1/cyrus_conversations",params={"select":"id","id":"in.("+",".join(rooms)+")","type":"eq.private","limit":"1000"},headers=admin_headers(),timeout=15)
                private=[str(x.get("id")) for x in c.json() if x.get("id")] if c.ok else []
                if private:
                    o=requests.get(URL+"/rest/v1/cyrus_members",params={"select":"user_id","conversation_id":"in.("+",".join(private)+")","user_id":"neq."+str(user_id),"limit":"2000"},headers=admin_headers(),timeout=15)
                    if o.ok:allowed.update(str(x.get("user_id")) for x in o.json() if x.get("user_id"))
        except Exception:pass
        return allowed
    def get_story(sid):
        r=requests.get(URL+"/rest/v1/cyrus_stories",params={"select":"id,user_id,media_url,media_type,caption,created_at,expires_at","id":"eq."+sid,"expires_at":"gt."+datetime.now(timezone.utc).isoformat(),"limit":"1"},headers=admin_headers(),timeout=15)
        return r.json()[0] if r.ok and r.json() else None
    def can_view(me,owner):return str(me) in audience_ids(str(owner))
    @app.route("/stories",methods=["GET","POST"])
    def cyrus_stories():
        if not session.get("access_token"):return redirect("/login")
        me=str(session.get("user_id") or "")
        if not ADMIN_KEY:return page('<main class="container"><div class="card">کلید امن سرور برای داستان‌ها تنظیم نشده است.</div></main>'),503
        err=""
        if request.method=="POST":
            caption=str(request.form.get("caption") or "").strip()[:500];f=request.files.get("media");kind="text";path=""
            if f and f.filename:
                raw=f.read(MAX_STORY_BYTES+1);mime=(f.mimetype or "").lower()
                if len(raw)>MAX_STORY_BYTES:err="حجم رسانه حداکثر ۲۰ مگابایت است."
                elif mime.startswith("image/"):kind="image"
                elif mime.startswith("video/"):kind="video"
                else:err="فقط تصویر یا ویدئو قابل انتشار است."
                if not err:
                    ext=mimetypes.guess_extension(mime) or ".bin"
                    if ext==".jpe":ext=".jpg"
                    path=me+"/"+str(uuid.uuid4())+ext
                    try:
                        up=requests.post(URL+"/storage/v1/object/"+STORY_BUCKET+"/"+quote(path,safe="/"),data=raw,headers=admin_headers({"Content-Type":mime,"x-upsert":"false"}),timeout=45)
                        if not up.ok:err="بارگذاری رسانه ناموفق بود؛ تنظیمات Storage را بررسی کنید."
                    except Exception:err="ارتباط با فضای رسانه برقرار نشد."
            if not err and not caption and not path:err="متن یا رسانه‌ای برای داستان وارد کنید."
            if not err:
                ins=requests.post(URL+"/rest/v1/cyrus_stories",json={"user_id":me,"media_url":path,"media_type":kind,"caption":caption,"expires_at":datetime.now(timezone.utc).isoformat()},headers=admin_headers({"Prefer":"return=minimal"}),timeout=20)
                if ins.ok:return redirect("/stories?posted=1")
                err="ثبت داستان انجام نشد؛ فایل SQL داستان‌ها را در Supabase اجرا کنید."
        allowed=audience_ids(me)
        try:
            r=requests.get(URL+"/rest/v1/cyrus_stories",params={"select":"id,user_id,media_url,media_type,caption,created_at,expires_at","user_id":"in.("+",".join(allowed)+")","expires_at":"gt."+datetime.now(timezone.utc).isoformat(),"order":"created_at.desc","limit":"300"},headers=admin_headers(),timeout=20)
            stories=r.json() if r.ok else []
        except Exception:stories=[]
        prof=profiles_for([x.get("user_id") for x in stories])
        cards=""
        for st in stories:
            owner=str(st.get("user_id") or "");p=prof.get(owner,{});name=html.escape(str(p.get("display_name") or p.get("username") or "همراه پارسی"))
            avatar=str(p.get("avatar_url") or "");av='<img src="'+html.escape(avatar,quote=True)+'">' if avatar else '<span>𓅃</span>'
            media="";signed=signed_media(st.get("media_url")) if st.get("media_url") else ""
            if signed:
                media=('<video controls playsinline src="'+html.escape(signed,quote=True)+'"></video>' if st.get("media_type")=="video" else '<img class="story-media" src="'+html.escape(signed,quote=True)+'">')
            sid=html.escape(str(st.get("id") or ""),quote=True);caption=html.escape(str(st.get("caption") or ""))
            try:
                lr=requests.get(URL+"/rest/v1/cyrus_story_likes",params={"select":"user_id","story_id":"eq."+sid},headers=admin_headers(),timeout=12);likes=lr.json() if lr.ok else []
                viewsr=requests.get(URL+"/rest/v1/cyrus_story_views",params={"select":"viewer_id","story_id":"eq."+sid},headers=admin_headers(),timeout=12);views=viewsr.json() if viewsr.ok else []
            except Exception:likes=[];views=[]
            liked=any(str(x.get("user_id"))==me for x in likes)
            likeform='<form method="post" action="/stories/'+sid+'/like"><button>'+( "♥ پسندیده" if liked else "♡ پسندیدن")+' · '+str(len(likes))+'</button></form>'
            own=owner==me
            ownerlink='<a href="/stories/'+sid+'/viewers">بازدید '+str(len(views))+' · بینندگان</a>' if own else ""
            reply="" if own else '<form class="story-reply" method="post" action="/stories/'+sid+'/reply"><input name="message" maxlength="1500" placeholder="پاسخ به داستان…" required><button>ارسال</button></form>'
            cards+='<article class="story-card"><header><a class="story-user" href="/user/'+html.escape(owner,quote=True)+'">'+av+'<b>'+name+'</b></a><time>'+html.escape(str(st.get("created_at") or "")[:16].replace("T"," "))+'</time></header>'+media+'<p>'+caption+'</p><footer>'+likeform+ownerlink+'</footer>'+reply+'</article>'
            if not own:
                requests.post(URL+"/rest/v1/cyrus_story_views",params={"on_conflict":"story_id,viewer_id"},json={"story_id":st["id"],"viewer_id":me},headers=admin_headers({"Prefer":"resolution=merge-duplicates,return=minimal"}),timeout=12)
        if not cards:cards='<div class="story-empty">هنوز داستانی از مخاطبانت منتشر نشده است.</div>'
        notice='<p class="story-success">داستان منتشر شد؛ تا ۲۴ ساعت نمایش داده می‌شود.</p>' if request.args.get("posted")=="1" else ""
        content='''<main class="container story-page"><style>
.story-page{padding:10px 12px 90px;color:#eaf1f6}.story-page h2{color:#e5bd69;font-size:20px;margin:12px 0}.story-form,.story-card{background:#101f2e;border:1px solid #293e52;border-radius:16px;padding:13px;margin:10px 0}.story-form textarea,.story-reply input{box-sizing:border-box;width:100%;background:#081522;border:1px solid #30485d;border-radius:10px;padding:11px;color:#fff;font:14px Tahoma}.story-form input[type=file]{width:100%;margin:10px 0;color:#9eb4c7;font:12px Tahoma}.story-page button{background:#17334a;color:#cce8ff;border:1px solid #365a75;border-radius:10px;padding:10px 14px;font:13px Tahoma}.story-form button{width:100%;background:#d6b15e;color:#17120a}.story-card header,.story-card footer{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.story-user{display:flex;align-items:center;gap:8px;color:#e9f1f8;text-decoration:none}.story-user img,.story-user span{width:36px;height:36px;border-radius:50%;object-fit:cover;background:#24394d;display:grid;place-items:center}.story-card time{font-size:10px;color:#8298ac;direction:ltr}.story-media,.story-card video{width:100%;max-height:62vh;object-fit:contain;background:#050b12;border-radius:12px;margin-top:12px}.story-card p{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.7}.story-card footer a{color:#7dc5f7;font-size:12px;text-decoration:none}.story-reply{display:flex;gap:7px;margin-top:12px}.story-reply input{min-width:0;flex:1}.story-empty{text-align:center;color:#90a6b8;padding:35px 10px}.story-error{color:#ffaaa6;font-size:12px}.story-success{color:#a7e8bb;font-size:12px}
</style><a href="/home" style="color:#9bcdf0;text-decoration:none">‹ بازگشت به بارگاه</a><h2>داستان‌های ۲۴ ساعته</h2>'''+notice+('<p class="story-error">'+html.escape(err)+'</p>' if err else '')+'''<form class="story-form" method="post" enctype="multipart/form-data"><textarea name="caption" rows="3" maxlength="500" placeholder="چه خبر؟ داستان متنی یا توضیح عکس/ویدئو…"></textarea><input type="file" name="media" accept="image/*,video/*"><p style="font-size:11px;color:#8da5b9">تصویر یا ویدئو تا ۲۰ مگابایت · پس از ۲۴ ساعت از نمایش خارج می‌شود</p><button>انتشار داستان</button></form>'''+cards+"</main>"
        return page(content)
    @app.route("/stories/<story_id>/like",methods=["POST"])
    def cyrus_story_like(story_id):
        if not session.get("access_token"):return redirect("/login")
        try:story_id=str(uuid.UUID(story_id))
        except ValueError:return "شناسه داستان نامعتبر است",400
        me=str(session.get("user_id") or "");st=get_story(story_id)
        if not st:return "داستان منقضی یا پیدا نشد",404
        if not can_view(me,st["user_id"]):return "به این داستان دسترسی ندارید",403
        if str(st["user_id"])==me:return redirect("/stories")
        q={"story_id":"eq."+story_id,"user_id":"eq."+me}
        c=requests.get(URL+"/rest/v1/cyrus_story_likes",params={"select":"story_id",**q},headers=admin_headers(),timeout=15)
        if c.ok and c.json():requests.delete(URL+"/rest/v1/cyrus_story_likes",params=q,headers=admin_headers(),timeout=15)
        else:requests.post(URL+"/rest/v1/cyrus_story_likes",json={"story_id":story_id,"user_id":me},headers=admin_headers({"Prefer":"return=minimal"}),timeout=15)
        return redirect("/stories")
    @app.route("/stories/<story_id>/viewers")
    def cyrus_story_viewers(story_id):
        if not session.get("access_token"):return redirect("/login")
        try:story_id=str(uuid.UUID(story_id))
        except ValueError:return "شناسه داستان نامعتبر است",400
        me=str(session.get("user_id") or "");st=get_story(story_id)
        if not st:return "داستان منقضی یا پیدا نشد",404
        if str(st["user_id"])!=me:return "فهرست بازدیدکنندگان فقط برای صاحب داستان است",403
        r=requests.get(URL+"/rest/v1/cyrus_story_views",params={"select":"viewer_id,viewed_at","story_id":"eq."+story_id,"order":"viewed_at.desc"},headers=admin_headers(),timeout=15);views=r.json() if r.ok else []
        prof=profiles_for([x.get("viewer_id") for x in views]);rows=""
        for v in views:
            uid=str(v.get("viewer_id") or "");p=prof.get(uid,{});nm=html.escape(str(p.get("display_name") or p.get("username") or "کاربر"));av=str(p.get("avatar_url") or "")
            pic='<img src="'+html.escape(av,quote=True)+'">' if av else '<span>♙</span>'
            rows+='<div class="viewer-row">'+pic+'<b>'+nm+'</b><a href="/start-chat/'+html.escape(uid,quote=True)+'">پیام</a></div>'
        if not rows:rows="<p>هنوز کسی داستان را ندیده است.</p>"
        return page('<main class="container story-page"><style>.viewer-row{display:flex;align-items:center;gap:10px;padding:10px;border-bottom:1px solid #263a4d}.viewer-row img,.viewer-row span{width:40px;height:40px;border-radius:50%;object-fit:cover;background:#20364a;display:grid;place-items:center}.viewer-row b{flex:1}.viewer-row a{color:#8acafa;text-decoration:none}</style><a href="/stories">‹ بازگشت</a><h2>بینندگان · '+str(len(views))+' بازدید</h2><section class="story-form">'+rows+'</section></main>')
    @app.route("/stories/<story_id>/reply",methods=["POST"])
    def cyrus_story_reply(story_id):
        if not session.get("access_token"):return redirect("/login")
        try:story_id=str(uuid.UUID(story_id))
        except ValueError:return "شناسه داستان نامعتبر است",400
        me=str(session.get("user_id") or "");st=get_story(story_id);msg=str(request.form.get("message") or "").strip()
        if not st:return "داستان منقضی یا پیدا نشد",404
        owner=str(st["user_id"])
        if me==owner or not can_view(me,owner):return "اجازه پاسخ به این داستان را ندارید",403
        if not msg or len(msg)>1500:return "متن پاسخ نامعتبر است",400
        try:
            cr=requests.post(URL+"/rest/v1/rpc/create_direct_conversation",json={"other_user":owner},headers=user_headers(),timeout=20)
            if not cr.ok:return "ساخت گفتگوی خصوصی ناموفق بود",400
            val=cr.json();cid=str(val.get("id") if isinstance(val,dict) else val);cid=str(uuid.UUID(cid))
            meta={"story_reply":{"story_id":story_id,"story_caption":str(st.get("caption") or "")[:250],"story_media_type":st.get("media_type")}}
            ins=requests.post(URL+"/rest/v1/cyrus_messages",json={"conversation_id":cid,"sender_id":me,"content":msg,"metadata":meta},headers=user_headers({"Prefer":"return=minimal"}),timeout=20)
            if not ins.ok:return "ارسال پاسخ به گفتگو ناموفق بود",400
            return redirect("/chat/"+cid+"?story_reply=1")
        except Exception:return "ارتباط با سرور برقرار نشد",502
    @app.route("/stories/<story_id>/media")
    def cyrus_story_media(story_id):
        if not session.get("access_token"):return redirect("/login")
        try:story_id=str(uuid.UUID(story_id))
        except ValueError:return "شناسه داستان نامعتبر است",400
        me=str(session.get("user_id") or "");st=get_story(story_id)
        if not st:return "داستان منقضی یا پیدا نشد",404
        if not can_view(me,st["user_id"]):return "به این داستان دسترسی ندارید",403
        target=signed_media(st.get("media_url"));return redirect(target) if target else ("رسانه در دسترس نیست",404)
