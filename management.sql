CREATE OR REPLACE FUNCTION public.cyrus_room_actor_role(p_conversation_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_role text;
BEGIN
 IF auth.uid() IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
 SELECT CASE WHEN c.created_by=auth.uid() THEN 'owner' ELSE m.role END
 INTO v_role FROM cyrus_conversations c
 LEFT JOIN cyrus_members m ON m.conversation_id=c.id AND m.user_id=auth.uid()
 WHERE c.id=p_conversation_id;
 IF v_role IS NULL THEN RAISE EXCEPTION 'دسترسی ندارید'; END IF;
 RETURN v_role;
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_manage_add_member(p_conversation_id uuid,p_user_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_role text;
BEGIN
 v_role:=public.cyrus_room_actor_role(p_conversation_id);
 IF v_role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'اجازه ندارید'; END IF;
 IF NOT EXISTS(SELECT 1 FROM cyrus_profiles WHERE id=p_user_id) THEN RAISE EXCEPTION 'کاربر پیدا نشد'; END IF;
 IF NOT EXISTS(SELECT 1 FROM cyrus_members WHERE conversation_id=p_conversation_id AND user_id=p_user_id) THEN
  INSERT INTO cyrus_members(conversation_id,user_id,role) VALUES(p_conversation_id,p_user_id,'member');
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_manage_remove_member(p_conversation_id uuid,p_user_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_role text; v_target text; v_owner uuid;
BEGIN
 v_role:=public.cyrus_room_actor_role(p_conversation_id);
 SELECT created_by INTO v_owner FROM cyrus_conversations WHERE id=p_conversation_id;
 SELECT role INTO v_target FROM cyrus_members WHERE conversation_id=p_conversation_id AND user_id=p_user_id;
 IF p_user_id=v_owner THEN RAISE EXCEPTION 'مالک قابل حذف نیست'; END IF;
 IF v_role='admin' AND v_target IS DISTINCT FROM 'member' THEN RAISE EXCEPTION 'مدیر فقط عضو عادی را حذف می‌کند'; END IF;
 IF v_role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'اجازه ندارید'; END IF;
 DELETE FROM cyrus_members WHERE conversation_id=p_conversation_id AND user_id=p_user_id;
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_manage_set_role(p_conversation_id uuid,p_user_id uuid,p_role text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_role text; v_owner uuid;
BEGIN
 v_role:=public.cyrus_room_actor_role(p_conversation_id);
 IF v_role<>'owner' THEN RAISE EXCEPTION 'فقط مالک اجازه دارد'; END IF;
 IF p_role NOT IN ('admin','member') THEN RAISE EXCEPTION 'نقش نامعتبر'; END IF;
 SELECT created_by INTO v_owner FROM cyrus_conversations WHERE id=p_conversation_id;
 IF p_user_id=v_owner THEN RAISE EXCEPTION 'نقش مالک قابل تغییر نیست'; END IF;
 UPDATE cyrus_members SET role=p_role WHERE conversation_id=p_conversation_id AND user_id=p_user_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'عضو پیدا نشد'; END IF;
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_manage_rename_room(p_conversation_id uuid,p_title text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_role text;
BEGIN
 v_role:=public.cyrus_room_actor_role(p_conversation_id);
 IF v_role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'اجازه تغییر نام ندارید'; END IF;
 IF length(trim(p_title))<2 OR length(trim(p_title))>60 THEN RAISE EXCEPTION 'نام نامعتبر است'; END IF;
 UPDATE cyrus_conversations SET title=trim(p_title) WHERE id=p_conversation_id;
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_manage_leave_room(p_conversation_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 IF public.cyrus_room_actor_role(p_conversation_id)='owner' THEN RAISE EXCEPTION 'مالک نمی‌تواند خارج شود'; END IF;
 DELETE FROM cyrus_members WHERE conversation_id=p_conversation_id AND user_id=auth.uid();
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_manage_delete_room(p_conversation_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 IF public.cyrus_room_actor_role(p_conversation_id)<>'owner' THEN RAISE EXCEPTION 'فقط مالک اجازه حذف دارد'; END IF;
 DELETE FROM cyrus_messages WHERE conversation_id=p_conversation_id;
 DELETE FROM cyrus_members WHERE conversation_id=p_conversation_id;
 DELETE FROM cyrus_conversations WHERE id=p_conversation_id;
END; $$;

GRANT EXECUTE ON FUNCTION public.cyrus_room_actor_role(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_add_member(uuid,uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_remove_member(uuid,uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_set_role(uuid,uuid,text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_rename_room(uuid,text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_leave_room(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_delete_room(uuid) TO authenticated;


-- CYRUS contact book and saved public profiles
CREATE TABLE IF NOT EXISTS public.cyrus_contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  contact_user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  contact_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT cyrus_contacts_not_self CHECK (owner_id <> contact_user_id),
  CONSTRAINT cyrus_contacts_owner_target_unique UNIQUE (owner_id, contact_user_id)
);
ALTER TABLE public.cyrus_contacts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cyrus_contacts_read_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_read_own ON public.cyrus_contacts FOR SELECT TO authenticated USING (owner_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_contacts_insert_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_insert_own ON public.cyrus_contacts FOR INSERT TO authenticated WITH CHECK (owner_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_contacts_update_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_update_own ON public.cyrus_contacts FOR UPDATE TO authenticated USING (owner_id = (SELECT auth.uid())) WITH CHECK (owner_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_contacts_delete_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_delete_own ON public.cyrus_contacts FOR DELETE TO authenticated USING (owner_id = (SELECT auth.uid()));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.cyrus_contacts TO authenticated;

CREATE TABLE IF NOT EXISTS public.cyrus_saved_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  saved_user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT cyrus_saved_profiles_not_self CHECK (owner_id <> saved_user_id),
  CONSTRAINT cyrus_saved_profiles_owner_user_unique UNIQUE (owner_id, saved_user_id)
);
ALTER TABLE public.cyrus_saved_profiles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cyrus_saved_profiles_read_own ON public.cyrus_saved_profiles;
CREATE POLICY cyrus_saved_profiles_read_own ON public.cyrus_saved_profiles FOR SELECT TO authenticated USING (owner_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_saved_profiles_insert_own ON public.cyrus_saved_profiles;
CREATE POLICY cyrus_saved_profiles_insert_own ON public.cyrus_saved_profiles FOR INSERT TO authenticated WITH CHECK (owner_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_saved_profiles_delete_own ON public.cyrus_saved_profiles;
CREATE POLICY cyrus_saved_profiles_delete_own ON public.cyrus_saved_profiles FOR DELETE TO authenticated USING (owner_id = (SELECT auth.uid()));
GRANT SELECT, INSERT, DELETE ON public.cyrus_saved_profiles TO authenticated;

-- Idempotency key prevents duplicate message rows when the client retries after a connection timeout.
CREATE UNIQUE INDEX IF NOT EXISTS cyrus_messages_client_nonce_unique
ON public.cyrus_messages (conversation_id, sender_id, (metadata->>'client_nonce'))
WHERE metadata ? 'client_nonce';


-- Private Saved Messages (each account can access only its own notes/messages)
CREATE TABLE IF NOT EXISTS public.cyrus_saved_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  content text NOT NULL CHECK (char_length(content) BETWEEN 1 AND 10000),
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.cyrus_saved_messages ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cyrus_saved_messages_read_own ON public.cyrus_saved_messages;
CREATE POLICY cyrus_saved_messages_read_own ON public.cyrus_saved_messages FOR SELECT TO authenticated USING (user_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_saved_messages_insert_own ON public.cyrus_saved_messages;
CREATE POLICY cyrus_saved_messages_insert_own ON public.cyrus_saved_messages FOR INSERT TO authenticated WITH CHECK (user_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_saved_messages_delete_own ON public.cyrus_saved_messages;
CREATE POLICY cyrus_saved_messages_delete_own ON public.cyrus_saved_messages FOR DELETE TO authenticated USING (user_id = (SELECT auth.uid()));
GRANT SELECT, INSERT, DELETE ON public.cyrus_saved_messages TO authenticated;

-- Safe pairwise block check: caller may check only a pair involving their own auth.uid().
CREATE OR REPLACE FUNCTION public.cyrus_is_blocked_pair(other_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT CASE WHEN auth.uid() IS NULL OR other_user_id IS NULL OR other_user_id = auth.uid()
    THEN false
    ELSE EXISTS (
      SELECT 1 FROM public.cyrus_user_blocks b
      WHERE (b.blocker_id = auth.uid() AND b.blocked_id = other_user_id)
         OR (b.blocker_id = other_user_id AND b.blocked_id = auth.uid())
    )
  END
$$;
REVOKE ALL ON FUNCTION public.cyrus_is_blocked_pair(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_is_blocked_pair(uuid) TO authenticated;


-- CYRUS Telegram-like invite preview and explicit join/request flow.
-- GET /invite/<code> only previews; membership is created only by the POST action.
CREATE OR REPLACE FUNCTION public.cyrus_invite_preview(p_invite_code text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE v_room public.cyrus_conversations%ROWTYPE;
BEGIN
 IF auth.uid() IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
 SELECT * INTO v_room FROM public.cyrus_conversations
 WHERE invite_code=trim(p_invite_code) AND type IN ('group','channel') LIMIT 1;
 IF v_room.id IS NULL THEN RAISE EXCEPTION 'لینک دعوت نامعتبر یا لغو شده است'; END IF;
 RETURN jsonb_build_object(
  'id',v_room.id,'title',v_room.title,'type',v_room.type,
  'description',v_room.description,'avatar_url',v_room.avatar_url,
  'member_count',(SELECT count(*) FROM public.cyrus_members m WHERE m.conversation_id=v_room.id),
  'is_public',coalesce(v_room.is_public,false),'join_approval',coalesce(v_room.join_approval,false),
  'already_member',EXISTS(SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=v_room.id AND m.user_id=auth.uid()),
  'request_pending',EXISTS(SELECT 1 FROM public.cyrus_join_requests j WHERE j.conversation_id=v_room.id AND j.user_id=auth.uid())
 );
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_invite_join(p_invite_code text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE v_room public.cyrus_conversations%ROWTYPE;
BEGIN
 IF auth.uid() IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
 SELECT * INTO v_room FROM public.cyrus_conversations
 WHERE invite_code=trim(p_invite_code) AND type IN ('group','channel') LIMIT 1;
 IF v_room.id IS NULL THEN RAISE EXCEPTION 'لینک دعوت نامعتبر یا لغو شده است'; END IF;
 IF EXISTS(SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=v_room.id AND m.user_id=auth.uid()) THEN
  RETURN jsonb_build_object('status','joined','conversation_id',v_room.id);
 END IF;
 IF coalesce(v_room.join_approval,false) THEN
  INSERT INTO public.cyrus_join_requests(conversation_id,user_id) VALUES(v_room.id,auth.uid())
  ON CONFLICT(conversation_id,user_id) DO UPDATE SET requested_at=now();
  RETURN jsonb_build_object('status','requested','conversation_id',v_room.id);
 END IF;
 INSERT INTO public.cyrus_members(conversation_id,user_id,role)
 VALUES(v_room.id,auth.uid(),'member') ON CONFLICT DO NOTHING;
 RETURN jsonb_build_object('status','joined','conversation_id',v_room.id);
END; $$;

REVOKE ALL ON FUNCTION public.cyrus_invite_preview(text) FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.cyrus_invite_join(text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.cyrus_invite_preview(text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.cyrus_invite_join(text) TO authenticated;


-- CYRUS secure server-side message posting permissions (2026-11-27).
-- Remove permissive legacy INSERT policies: PostgreSQL combines policies with OR.
DROP POLICY IF EXISTS cyrus_messages_send ON public.cyrus_messages;
DROP POLICY IF EXISTS cyrus_channel_post_insert_guard ON public.cyrus_messages;
CREATE POLICY cyrus_messages_send_secure
ON public.cyrus_messages
FOR INSERT TO authenticated
WITH CHECK (
  sender_id = (SELECT auth.uid())
  AND EXISTS (
    SELECT 1 FROM public.cyrus_conversations c
    WHERE c.id = cyrus_messages.conversation_id
      AND (
        (c.type = 'private'
          AND EXISTS (SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=c.id AND m.user_id=(SELECT auth.uid()))
          AND NOT EXISTS (SELECT 1 FROM public.cyrus_members other_m WHERE other_m.conversation_id=c.id AND other_m.user_id<>(SELECT auth.uid()) AND public.cyrus_is_blocked_pair(other_m.user_id))
        )
        OR
        (c.type = 'group'
          AND EXISTS (SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=c.id AND m.user_id=(SELECT auth.uid())
            AND (m.role IN ('owner','admin') OR coalesce((c.member_permissions->>'send_messages')::boolean,true))
          )
        )
        OR
        (c.type = 'channel' AND (c.created_by=(SELECT auth.uid()) OR EXISTS (SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=c.id AND m.user_id=(SELECT auth.uid()) AND m.role='admin'))
      )
  )
);


-- CYRUS enforce add-member and pin-message permissions server-side (2026-11-27).
CREATE OR REPLACE FUNCTION public.cyrus_manage_add_member(p_conversation_id uuid,p_user_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE v_role text; v_type text; v_permissions jsonb;
BEGIN
  v_role:=public.cyrus_room_actor_role(p_conversation_id);
  SELECT type,coalesce(member_permissions,'{}'::jsonb) INTO v_type,v_permissions FROM public.cyrus_conversations WHERE id=p_conversation_id;
  IF v_type IS NULL OR v_type NOT IN ('group','channel') THEN RAISE EXCEPTION 'مجموعه پیدا نشد'; END IF;
  IF v_role NOT IN ('owner','admin') THEN
    IF v_type<>'group' OR NOT coalesce((v_permissions->>'add_members')::boolean,false) THEN RAISE EXCEPTION 'اجازه افزودن عضو ندارید'; END IF;
  END IF;
  IF p_user_id IS NULL OR p_user_id=auth.uid() THEN RAISE EXCEPTION 'کاربر نامعتبر است'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.cyrus_profiles WHERE id=p_user_id) THEN RAISE EXCEPTION 'کاربر پیدا نشد'; END IF;
  INSERT INTO public.cyrus_members(conversation_id,user_id,role) VALUES(p_conversation_id,p_user_id,'member') ON CONFLICT DO NOTHING;
END; $$;

CREATE OR REPLACE FUNCTION public.cyrus_pin_message(p_conversation_id uuid,p_message_id uuid,p_pin boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE v_role text; v_type text; v_permissions jsonb;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
  v_role:=public.cyrus_room_actor_role(p_conversation_id);
  SELECT type,coalesce(member_permissions,'{}'::jsonb) INTO v_type,v_permissions FROM public.cyrus_conversations WHERE id=p_conversation_id;
  IF v_type IS NULL THEN RAISE EXCEPTION 'گفتگو پیدا نشد'; END IF;
  IF v_type='channel' AND v_role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'فقط مالک یا مدیر کانال می‌تواند پیام سنجاق کند'; END IF;
  IF v_type='group' AND v_role NOT IN ('owner','admin') AND NOT coalesce((v_permissions->>'pin_messages')::boolean,false) THEN RAISE EXCEPTION 'اجازه سنجاق پیام ندارید'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.cyrus_messages WHERE id=p_message_id AND conversation_id=p_conversation_id) THEN RAISE EXCEPTION 'پیام پیدا نشد'; END IF;
  UPDATE public.cyrus_messages SET metadata=coalesce(metadata,'{}'::jsonb)-'pinned' WHERE conversation_id=p_conversation_id AND coalesce(metadata->>'pinned','false')='true';
  IF p_pin THEN UPDATE public.cyrus_messages SET metadata=jsonb_set(coalesce(metadata,'{}'::jsonb),'{pinned}','true'::jsonb,true) WHERE id=p_message_id AND conversation_id=p_conversation_id; END IF;
END; $$;



-- CYRUS chat media bucket and upload policy (2026-11-27).
INSERT INTO storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
VALUES('cyrus-chat-files','cyrus-chat-files',true,20971520,
ARRAY['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','audio/mpeg','audio/mp4','audio/ogg','audio/webm','application/pdf','text/plain','application/zip','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'])
ON CONFLICT(id) DO UPDATE SET public=true,file_size_limit=20971520,allowed_mime_types=EXCLUDED.allowed_mime_types;
DROP POLICY IF EXISTS cyrus_chat_files_authenticated_upload ON storage.objects;
CREATE POLICY cyrus_chat_files_authenticated_upload ON storage.objects
FOR INSERT TO authenticated WITH CHECK (
 bucket_id='cyrus-chat-files' AND (storage.foldername(name))[2]=(SELECT auth.uid())::text
);
DROP POLICY IF EXISTS cyrus_chat_files_authenticated_update ON storage.objects;
CREATE POLICY cyrus_chat_files_authenticated_update ON storage.objects
FOR UPDATE TO authenticated USING (
 bucket_id='cyrus-chat-files' AND (storage.foldername(name))[2]=(SELECT auth.uid())::text
) WITH CHECK (
 bucket_id='cyrus-chat-files' AND (storage.foldername(name))[2]=(SELECT auth.uid())::text
);

-- Enforce distinct group permissions for text and media posts.
DROP POLICY IF EXISTS cyrus_messages_send_secure ON public.cyrus_messages;
CREATE POLICY cyrus_messages_send_secure
ON public.cyrus_messages FOR INSERT TO authenticated
WITH CHECK (
 sender_id=(SELECT auth.uid()) AND EXISTS(
  SELECT 1 FROM public.cyrus_conversations c WHERE c.id=cyrus_messages.conversation_id AND (
   (c.type='private' AND EXISTS(SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=c.id AND m.user_id=(SELECT auth.uid()))
    AND NOT EXISTS(SELECT 1 FROM public.cyrus_members om WHERE om.conversation_id=c.id AND om.user_id<>(SELECT auth.uid()) AND public.cyrus_is_blocked_pair(om.user_id)))
   OR
   (c.type='group' AND EXISTS(SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=c.id AND m.user_id=(SELECT auth.uid())
    AND (m.role IN ('owner','admin') OR coalesce((c.member_permissions->>CASE WHEN cyrus_messages.message_type IN ('photo','video','audio','document','file') THEN 'send_media' ELSE 'send_messages' END)::boolean,true))))
   OR
   (c.type='channel' AND (c.created_by=(SELECT auth.uid()) OR EXISTS(SELECT 1 FROM public.cyrus_members m WHERE m.conversation_id=c.id AND m.user_id=(SELECT auth.uid()) AND m.role='admin')))
  )
 )
);



-- Keep chat attachments private; app issues membership-checked signed URLs.
UPDATE storage.buckets SET public=false WHERE id='cyrus-chat-files';
DROP POLICY IF EXISTS cyrus_chat_files_authenticated_read ON storage.objects;
CREATE POLICY cyrus_chat_files_authenticated_read ON storage.objects
FOR SELECT TO authenticated USING (
 bucket_id='cyrus-chat-files'
 AND EXISTS (
  SELECT 1 FROM public.cyrus_conversations c
  WHERE c.id=(storage.foldername(name))[1]::uuid
   AND (c.created_by=(SELECT auth.uid()) OR public.cyrus_is_member(c.id)
        OR (c.type='channel' AND c.is_public=true))
 )
);


-- Persistent per-user message reactions (Telegram-like)
create table if not exists public.cyrus_message_reactions (
  message_id uuid not null references public.cyrus_messages(id) on delete cascade,
  conversation_id uuid not null references public.cyrus_conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  emoji text not null check (emoji in ('❤️','👍','👎','🔥','🥰','👏','🇮🇷','😂','😮','😢')),
  created_at timestamptz not null default now(),
  primary key (message_id,user_id)
);
create index if not exists cyrus_message_reactions_conversation_idx on public.cyrus_message_reactions(conversation_id,message_id);
alter table public.cyrus_message_reactions enable row level security;
grant select,insert,delete on public.cyrus_message_reactions to authenticated;
drop policy if exists cyrus_reactions_read_member on public.cyrus_message_reactions;
create policy cyrus_reactions_read_member on public.cyrus_message_reactions for select to authenticated using (
  exists (select 1 from public.cyrus_members m where m.conversation_id=cyrus_message_reactions.conversation_id and m.user_id=(SELECT auth.uid()))
  or exists (select 1 from public.cyrus_conversations c where c.id=cyrus_message_reactions.conversation_id and c.type='channel' and c.is_public=true)
);
drop policy if exists cyrus_reactions_insert_self_member on public.cyrus_message_reactions;
create policy cyrus_reactions_insert_self_member on public.cyrus_message_reactions for insert to authenticated with check (
  user_id=(SELECT auth.uid())
  and exists (select 1 from public.cyrus_messages msg where msg.id=cyrus_message_reactions.message_id and msg.conversation_id=cyrus_message_reactions.conversation_id)
  and exists (select 1 from public.cyrus_members m where m.conversation_id=cyrus_message_reactions.conversation_id and m.user_id=(SELECT auth.uid()))
);
drop policy if exists cyrus_reactions_delete_self on public.cyrus_message_reactions;
create policy cyrus_reactions_delete_self on public.cyrus_message_reactions for delete to authenticated using (user_id=(SELECT auth.uid()));


-- Secure owner transfer for groups and channels.
CREATE OR REPLACE FUNCTION public.cyrus_manage_transfer_ownership(p_conversation_id uuid,p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=public,pg_temp
AS $$
DECLARE
  v_actor uuid := auth.uid();
  v_owner uuid;
  v_type text;
BEGIN
  IF v_actor IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
  IF p_user_id IS NULL OR p_user_id = v_actor THEN RAISE EXCEPTION 'عضو مقصد نامعتبر است'; END IF;
  SELECT created_by,type INTO v_owner,v_type
  FROM public.cyrus_conversations
  WHERE id=p_conversation_id
  FOR UPDATE;
  IF v_owner IS NULL OR v_type NOT IN ('group','channel') THEN RAISE EXCEPTION 'گروه یا کانال پیدا نشد'; END IF;
  IF v_owner <> v_actor THEN RAISE EXCEPTION 'فقط مالک فعلی می‌تواند مالکیت را منتقل کند'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.cyrus_members
    WHERE conversation_id=p_conversation_id AND user_id=p_user_id
  ) THEN RAISE EXCEPTION 'مالک جدید باید ابتدا عضو مجموعه باشد'; END IF;
  INSERT INTO public.cyrus_members(conversation_id,user_id,role)
  VALUES(p_conversation_id,v_actor,'admin')
  ON CONFLICT(conversation_id,user_id) DO UPDATE SET role='admin';
  UPDATE public.cyrus_members SET role='owner'
  WHERE conversation_id=p_conversation_id AND user_id=p_user_id;
  UPDATE public.cyrus_conversations SET created_by=p_user_id
  WHERE id=p_conversation_id;
END;
$$;
REVOKE ALL ON FUNCTION public.cyrus_manage_transfer_ownership(uuid,uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_transfer_ownership(uuid,uuid) TO authenticated;


-- Complete join-request lifecycle for both groups and channels.
CREATE OR REPLACE FUNCTION public.cyrus_manage_review_join_request(p_conversation_id uuid,p_user_id uuid,p_approve boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=public,pg_temp
AS $$
DECLARE v_type text;
BEGIN
  IF public.cyrus_room_actor_role(p_conversation_id) NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'فقط مالک یا مدیر می‌تواند درخواست عضویت را بررسی کند';
  END IF;
  SELECT type INTO v_type FROM public.cyrus_conversations WHERE id=p_conversation_id;
  IF v_type NOT IN ('group','channel') THEN RAISE EXCEPTION 'مجموعه پیدا نشد'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.cyrus_join_requests WHERE conversation_id=p_conversation_id AND user_id=p_user_id) THEN
    RAISE EXCEPTION 'درخواست عضویت پیدا نشد';
  END IF;
  IF p_approve THEN
    INSERT INTO public.cyrus_members(conversation_id,user_id,role)
    VALUES(p_conversation_id,p_user_id,'member') ON CONFLICT DO NOTHING;
  END IF;
  DELETE FROM public.cyrus_join_requests WHERE conversation_id=p_conversation_id AND user_id=p_user_id;
END;
$$;
REVOKE ALL ON FUNCTION public.cyrus_manage_review_join_request(uuid,uuid,boolean) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_review_join_request(uuid,uuid,boolean) TO authenticated;

CREATE OR REPLACE FUNCTION public.cyrus_invite_cancel_request(p_invite_code text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=public,pg_temp
AS $$
DECLARE v_room_id uuid;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
  SELECT id INTO v_room_id FROM public.cyrus_conversations
  WHERE invite_code=trim(p_invite_code) AND type IN ('group','channel');
  IF v_room_id IS NULL THEN RAISE EXCEPTION 'لینک دعوت نامعتبر یا لغو شده است'; END IF;
  DELETE FROM public.cyrus_join_requests
  WHERE conversation_id=v_room_id AND user_id=auth.uid();
END;
$$;
REVOKE ALL ON FUNCTION public.cyrus_invite_cancel_request(text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.cyrus_invite_cancel_request(text) TO authenticated;


-- CYRUS privacy hardening: public discovery must never expose private channels.
DROP POLICY IF EXISTS cyrus_public_channels_read ON public.cyrus_conversations;
CREATE POLICY cyrus_public_channels_read
ON public.cyrus_conversations
FOR SELECT TO authenticated
USING (type='channel' AND coalesce(is_public,false)=true);

DROP POLICY IF EXISTS cyrus_public_channel_posts_read ON public.cyrus_messages;
CREATE POLICY cyrus_public_channel_posts_read
ON public.cyrus_messages
FOR SELECT TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.cyrus_conversations c
    WHERE c.id=cyrus_messages.conversation_id
      AND c.type='channel'
      AND coalesce(c.is_public,false)=true
  )
);

-- A removed member must not retain edit/delete access to old room messages.
DROP POLICY IF EXISTS cyrus_messages_edit ON public.cyrus_messages;
CREATE POLICY cyrus_messages_edit
ON public.cyrus_messages
FOR UPDATE TO authenticated
USING (
  sender_id=(SELECT auth.uid())
  AND public.cyrus_is_member(conversation_id)
)
WITH CHECK (
  sender_id=(SELECT auth.uid())
  AND public.cyrus_is_member(conversation_id)
);

DROP POLICY IF EXISTS cyrus_messages_delete_own ON public.cyrus_messages;
CREATE POLICY cyrus_messages_delete_own
ON public.cyrus_messages
FOR DELETE TO authenticated
USING (
  sender_id=(SELECT auth.uid())
  AND public.cyrus_is_member(conversation_id)
);


-- SECURITY DEFINER RPCs must never be callable by anonymous visitors.
-- Signed-in access is retained; each function performs its own auth/role checks.
REVOKE ALL ON FUNCTION public.cyrus_channel_join(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_channel_join(uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_channel_record_view(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_channel_record_view(uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_is_member(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_is_member(uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_add_member(uuid,uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_add_member(uuid,uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_delete_room(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_delete_room(uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_leave_room(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_leave_room(uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_list_join_requests(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_list_join_requests(uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_remove_member(uuid,uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_remove_member(uuid,uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_rename_room(uuid,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_rename_room(uuid,text) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_set_role(uuid,uuid,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_set_role(uuid,uuid,text) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_manage_update_room_settings(uuid,text,text,text,boolean,boolean,boolean,boolean,integer,boolean,boolean,jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_update_room_settings(uuid,text,text,text,boolean,boolean,boolean,boolean,integer,boolean,boolean,jsonb) TO authenticated;
REVOKE ALL ON FUNCTION public.cyrus_room_actor_role(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.cyrus_room_actor_role(uuid) TO authenticated;


-- CYRUS optional account second factor (server-only; no client policies).
CREATE TABLE IF NOT EXISTS public.cyrus_account_security (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    two_factor_enabled boolean NOT NULL DEFAULT false,
    password_hash text,
    failed_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    pending_password_hash text,
    pending_expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cyrus_account_security_hash_check
      CHECK (two_factor_enabled = false OR (password_hash IS NOT NULL AND length(password_hash) > 20))
);
ALTER TABLE public.cyrus_account_security
    ADD COLUMN IF NOT EXISTS pending_password_hash text,
    ADD COLUMN IF NOT EXISTS pending_expires_at timestamptz;
ALTER TABLE public.cyrus_account_security ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.cyrus_account_security FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.cyrus_account_security TO service_role;

-- Publicly readable group/channel images; uploads are restricted to owners/admins by object RLS.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('cyrus-room-avatars','cyrus-room-avatars',true,5242880,ARRAY['image/jpeg','image/png','image/webp'])
ON CONFLICT (id) DO UPDATE SET
    public=true,
    file_size_limit=5242880,
    allowed_mime_types=ARRAY['image/jpeg','image/png','image/webp'];

DROP POLICY IF EXISTS "CYRUS room avatar upload by managers" ON storage.objects;
CREATE POLICY "CYRUS room avatar upload by managers"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (
    bucket_id = 'cyrus-room-avatars'
    AND (storage.foldername(name))[1] ~* '^[0-9a-f-]{36}$'
    AND (storage.foldername(name))[2] = (SELECT auth.uid())::text
    AND EXISTS (
        SELECT 1 FROM public.cyrus_conversations c
        WHERE c.id::text = (storage.foldername(name))[1]
          AND (
              c.created_by = (SELECT auth.uid())
              OR EXISTS (
                  SELECT 1 FROM public.cyrus_members m
                  WHERE m.conversation_id = c.id
                    AND m.user_id = (SELECT auth.uid())
                    AND m.role IN ('owner','admin')
              )
          )
    )
);

DROP POLICY IF EXISTS "CYRUS room avatar delete by managers" ON storage.objects;
CREATE POLICY "CYRUS room avatar delete by managers"
ON storage.objects FOR DELETE TO authenticated
USING (
    bucket_id = 'cyrus-room-avatars'
    AND (storage.foldername(name))[2] = (SELECT auth.uid())::text
    AND EXISTS (
        SELECT 1 FROM public.cyrus_conversations c
        WHERE c.id::text = (storage.foldername(name))[1]
          AND (
              c.created_by = (SELECT auth.uid())
              OR EXISTS (
                  SELECT 1 FROM public.cyrus_members m
                  WHERE m.conversation_id = c.id
                    AND m.user_id = (SELECT auth.uid())
                    AND m.role IN ('owner','admin')
              )
          )
    )
);


-- Keep the authenticated ownership checks init-plan optimized.
ALTER TABLE public.cyrus_conversations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cyrus_rooms_create ON public.cyrus_conversations;
CREATE POLICY cyrus_rooms_create ON public.cyrus_conversations
  FOR INSERT TO authenticated WITH CHECK (created_by = (SELECT auth.uid()));

ALTER TABLE public.cyrus_members ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cyrus_members_delete_own_membership ON public.cyrus_members;
CREATE POLICY cyrus_members_delete_own_membership ON public.cyrus_members
  FOR DELETE TO authenticated USING (user_id = (SELECT auth.uid()));
DROP POLICY IF EXISTS cyrus_members_update_own_read_state ON public.cyrus_members;
CREATE POLICY cyrus_members_update_own_read_state ON public.cyrus_members
  FOR UPDATE TO authenticated USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));


-- Foreign-key covering indexes identified by Supabase performance advisors.
CREATE INDEX IF NOT EXISTS idx_cyrus_channel_views_user_id ON public.cyrus_channel_views(user_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_contacts_contact_user_id ON public.cyrus_contacts(contact_user_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_conversations_created_by ON public.cyrus_conversations(created_by);
CREATE INDEX IF NOT EXISTS idx_cyrus_join_requests_user_id ON public.cyrus_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_message_reactions_user_id ON public.cyrus_message_reactions(user_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_messages_sender_id ON public.cyrus_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_official_channels_channel_id ON public.cyrus_official_channels(channel_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_saved_messages_user_id ON public.cyrus_saved_messages(user_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_saved_profiles_saved_user_id ON public.cyrus_saved_profiles(saved_user_id);
CREATE INDEX IF NOT EXISTS idx_cyrus_user_links_contact_user_id ON public.cyrus_user_links(contact_user_id);
