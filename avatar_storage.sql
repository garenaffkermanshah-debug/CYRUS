-- CYRUS profile avatar storage setup
-- Run once in Supabase SQL Editor for project dcabjkeilsiuedfjfofq.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'cyrus-avatars',
  'cyrus-avatars',
  true,
  5242880,
  array['image/jpeg','image/png','image/webp']
)
on conflict (id) do update
set public = true,
    file_size_limit = 5242880,
    allowed_mime_types = array['image/jpeg','image/png','image/webp'];

drop policy if exists "cyrus_avatars_public_read" on storage.objects;
create policy "cyrus_avatars_public_read"
on storage.objects for select
using (bucket_id = 'cyrus-avatars');

drop policy if exists "cyrus_avatars_owner_upload" on storage.objects;
create policy "cyrus_avatars_owner_upload"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'cyrus-avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "cyrus_avatars_owner_update" on storage.objects;
create policy "cyrus_avatars_owner_update"
on storage.objects for update to authenticated
using (
  bucket_id = 'cyrus-avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
)
with check (
  bucket_id = 'cyrus-avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "cyrus_avatars_owner_delete" on storage.objects;
create policy "cyrus_avatars_owner_delete"
on storage.objects for delete to authenticated
using (
  bucket_id = 'cyrus-avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
);
