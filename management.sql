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
CREATE POLICY cyrus_contacts_read_own ON public.cyrus_contacts FOR SELECT TO authenticated USING (owner_id = auth.uid());
DROP POLICY IF EXISTS cyrus_contacts_insert_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_insert_own ON public.cyrus_contacts FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
DROP POLICY IF EXISTS cyrus_contacts_update_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_update_own ON public.cyrus_contacts FOR UPDATE TO authenticated USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());
DROP POLICY IF EXISTS cyrus_contacts_delete_own ON public.cyrus_contacts;
CREATE POLICY cyrus_contacts_delete_own ON public.cyrus_contacts FOR DELETE TO authenticated USING (owner_id = auth.uid());
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
CREATE POLICY cyrus_saved_profiles_read_own ON public.cyrus_saved_profiles FOR SELECT TO authenticated USING (owner_id = auth.uid());
DROP POLICY IF EXISTS cyrus_saved_profiles_insert_own ON public.cyrus_saved_profiles;
CREATE POLICY cyrus_saved_profiles_insert_own ON public.cyrus_saved_profiles FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid());
DROP POLICY IF EXISTS cyrus_saved_profiles_delete_own ON public.cyrus_saved_profiles;
CREATE POLICY cyrus_saved_profiles_delete_own ON public.cyrus_saved_profiles FOR DELETE TO authenticated USING (owner_id = auth.uid());
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
