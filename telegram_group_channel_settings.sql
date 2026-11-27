-- CYRUS Telegram-style group/channel settings migration
-- Safe additive migration; already applied to the connected CYRUS Supabase project.
ALTER TABLE public.cyrus_conversations
  ADD COLUMN IF NOT EXISTS is_public boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS join_approval boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS history_visible boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS slow_mode_seconds integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS topics_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS sign_messages boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS member_permissions jsonb NOT NULL DEFAULT '{"send_messages":true,"send_media":true,"add_members":true,"pin_messages":true,"change_info":false}'::jsonb;
ALTER TABLE public.cyrus_members ADD COLUMN IF NOT EXISTS last_message_at timestamptz;
UPDATE public.cyrus_conversations SET is_public=true WHERE type='channel' AND invite_code IS NOT NULL;
ALTER TABLE public.cyrus_conversations DROP CONSTRAINT IF EXISTS cyrus_conversations_slow_mode_seconds_check;
ALTER TABLE public.cyrus_conversations ADD CONSTRAINT cyrus_conversations_slow_mode_seconds_check CHECK (slow_mode_seconds IN (0,10,30,60,300,900,3600));
DROP FUNCTION IF EXISTS public.cyrus_manage_update_room_settings(uuid,text,text,text,boolean);
CREATE OR REPLACE FUNCTION public.cyrus_manage_update_room_settings(
 p_conversation_id uuid,p_title text,p_description text,p_avatar_url text,p_reactions_enabled boolean,
 p_is_public boolean,p_join_approval boolean,p_history_visible boolean,p_slow_mode_seconds integer,
 p_topics_enabled boolean,p_sign_messages boolean,p_member_permissions jsonb
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_role text; v_type text;
BEGIN
 v_role:=public.cyrus_room_actor_role(p_conversation_id);
 SELECT type INTO v_type FROM public.cyrus_conversations WHERE id=p_conversation_id;
 IF v_role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'اجازه ندارید'; END IF;
 IF v_role='admin' AND p_is_public IS DISTINCT FROM (SELECT is_public FROM public.cyrus_conversations WHERE id=p_conversation_id) THEN
   RAISE EXCEPTION 'فقط مالک می‌تواند عمومی یا خصوصی بودن را تغییر دهد';
 END IF;
 IF length(trim(p_title))<2 OR length(trim(p_title))>60 THEN RAISE EXCEPTION 'نام نامعتبر است'; END IF;
 IF length(coalesce(p_description,''))>500 THEN RAISE EXCEPTION 'توضیحات بیش از حد طولانی است'; END IF;
 IF p_slow_mode_seconds NOT IN (0,10,30,60,300,900,3600) THEN RAISE EXCEPTION 'محدودیت زمانی نامعتبر است'; END IF;
 IF jsonb_typeof(p_member_permissions)<>'object' THEN RAISE EXCEPTION 'مجوزها نامعتبرند'; END IF;
 UPDATE public.cyrus_conversations SET title=trim(p_title),description=coalesce(p_description,''),
 avatar_url=nullif(trim(coalesce(p_avatar_url,'')),''),reactions_enabled=p_reactions_enabled,
 is_public=p_is_public,join_approval=p_join_approval,history_visible=p_history_visible,
 slow_mode_seconds=p_slow_mode_seconds,topics_enabled=(v_type='group' AND p_topics_enabled),
 sign_messages=(v_type='channel' AND p_sign_messages),member_permissions=p_member_permissions
 WHERE id=p_conversation_id;
END; $$;
GRANT EXECUTE ON FUNCTION public.cyrus_manage_update_room_settings(uuid,text,text,text,boolean,boolean,boolean,boolean,integer,boolean,boolean,jsonb) TO authenticated;
CREATE OR REPLACE FUNCTION public.cyrus_channel_join(p_conversation_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_public boolean; v_approval boolean; v_type text;
BEGIN
 IF auth.uid() IS NULL THEN RAISE EXCEPTION 'ورود لازم است'; END IF;
 SELECT is_public,join_approval,type INTO v_public,v_approval,v_type FROM public.cyrus_conversations WHERE id=p_conversation_id;
 IF v_type IS DISTINCT FROM 'channel' OR NOT coalesce(v_public,false) THEN RAISE EXCEPTION 'کانال خصوصی است یا وجود ندارد'; END IF;
 IF v_approval THEN RAISE EXCEPTION 'عضویت نیازمند تأیید مدیر است؛ از لینک دعوت استفاده کنید'; END IF;
 INSERT INTO public.cyrus_members(conversation_id,user_id,role) VALUES(p_conversation_id,auth.uid(),'member') ON CONFLICT DO NOTHING;
END; $$;
