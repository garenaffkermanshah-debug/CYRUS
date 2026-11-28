-- CYRUS 24-hour stories: server-side access only (Flask uses service-role key).
create extension if not exists pgcrypto;

create table if not exists public.cyrus_stories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  media_url text not null,
  media_type text not null check (media_type in ('image','video','text')),
  caption text not null default '',
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  check (expires_at > created_at)
);
create index if not exists cyrus_stories_expiry_idx on public.cyrus_stories (expires_at desc);
create index if not exists cyrus_stories_owner_idx on public.cyrus_stories (user_id, created_at desc);

create table if not exists public.cyrus_story_views (
  story_id uuid not null references public.cyrus_stories(id) on delete cascade,
  viewer_id uuid not null references auth.users(id) on delete cascade,
  viewed_at timestamptz not null default now(),
  primary key (story_id, viewer_id)
);
create index if not exists cyrus_story_views_viewer_idx on public.cyrus_story_views (viewer_id, viewed_at desc);

create table if not exists public.cyrus_story_likes (
  story_id uuid not null references public.cyrus_stories(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (story_id, user_id)
);

alter table public.cyrus_stories enable row level security;
alter table public.cyrus_story_views enable row level security;
alter table public.cyrus_story_likes enable row level security;

revoke all on public.cyrus_stories from anon, authenticated;
revoke all on public.cyrus_story_views from anon, authenticated;
revoke all on public.cyrus_story_likes from anon, authenticated;
grant all on public.cyrus_stories to service_role;
grant all on public.cyrus_story_views to service_role;
grant all on public.cyrus_story_likes to service_role;
