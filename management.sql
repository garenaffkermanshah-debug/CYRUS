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
