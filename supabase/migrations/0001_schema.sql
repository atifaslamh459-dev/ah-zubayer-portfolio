-- 0001_schema.sql : core tables. Apply first.
create extension if not exists pgcrypto;

create or replace function public.set_updated_at() returns trigger
language plpgsql as $$ begin new.updated_at = now(); return new; end $$;

-- ---------- Authorization ----------
create table public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null
);

-- Server-verified role check. SECURITY DEFINER so RLS on admin_users cannot recurse.
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.admin_users where user_id = auth.uid());
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- ---------- Site settings (singleton row) ----------
create table public.site_settings (
  id smallint primary key default 1 check (id = 1),
  brand_name text not null default 'AH Zubayer' check (char_length(brand_name) <= 80),
  tagline text not null default '[Editable tagline]' check (char_length(tagline) <= 200),
  intro text not null default '[Editable introduction]' check (char_length(intro) <= 1000),
  bio text not null default '[Editable biography - not yet supplied]' check (char_length(bio) <= 8000),
  work_approach text not null default '[Editable process description]' check (char_length(work_approach) <= 4000),
  available_for_work boolean not null default false,
  availability_note text check (char_length(availability_note) <= 200),
  contact_email text check (contact_email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  social_links jsonb not null default '[]'::jsonb,   -- [{label,url}]
  cv_url text check (cv_url is null or cv_url ~* '^https?://'),
  seo_title text check (char_length(seo_title) <= 70),
  seo_description text check (char_length(seo_description) <= 200),
  analytics_enabled boolean not null default true,
  updated_at timestamptz not null default now()
);
insert into public.site_settings (id) values (1);
create trigger trg_site_settings_updated before update on public.site_settings
  for each row execute function public.set_updated_at();

-- ---------- Portfolio ----------
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and char_length(slug) <= 80),
  title text not null check (char_length(title) between 1 and 120),
  summary text not null check (char_length(summary) <= 400),
  case_study text check (char_length(case_study) <= 20000),
  thumbnail_url text check (thumbnail_url is null or thumbnail_url ~* '^https?://'),
  thumbnail_alt text check (char_length(thumbnail_alt) <= 200),
  category text check (char_length(category) <= 60),
  technologies text[] not null default '{}',
  role text check (char_length(role) <= 100),
  year smallint check (year between 1990 and 2100),
  live_url text check (live_url is null or live_url ~* '^https?://'),
  source_url text check (source_url is null or source_url ~* '^https?://'),
  status text not null default 'draft' check (status in ('draft','published')),
  featured boolean not null default false,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index projects_public_idx on public.projects (status, sort_order);
create trigger trg_projects_updated before update on public.projects
  for each row execute function public.set_updated_at();

create table public.services (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 120),
  description text not null check (char_length(description) <= 2000),
  deliverables text[] not null default '{}',
  starting_price numeric(10,2) check (starting_price is null or starting_price >= 0),
  currency char(3) not null default 'USD',
  show_price boolean not null default false,
  timeline text check (char_length(timeline) <= 100),
  is_visible boolean not null default true,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index services_public_idx on public.services (is_visible, sort_order);
create trigger trg_services_updated before update on public.services
  for each row execute function public.set_updated_at();

create table public.skills (
  id uuid primary key default gen_random_uuid(),
  name text not null unique check (char_length(name) between 1 and 60),
  category text check (char_length(category) <= 60),
  is_visible boolean not null default true,
  sort_order integer not null default 0
);

create table public.experience_entries (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('experience','education')),
  title text not null check (char_length(title) <= 120),
  organization text check (char_length(organization) <= 120),
  start_date date,
  end_date date,
  description text check (char_length(description) <= 2000),
  is_visible boolean not null default true,
  sort_order integer not null default 0,
  check (end_date is null or start_date is null or end_date >= start_date)
);

-- ---------- Contact ----------
create table public.contact_submissions (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 100),
  email text not null check (email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' and char_length(email) <= 254),
  project_type text not null check (char_length(project_type) <= 60),
  budget_range text check (char_length(budget_range) <= 60),
  website_url text check (website_url is null or website_url ~* '^https?://'),
  message text not null check (char_length(message) between 10 and 5000),
  consent boolean not null check (consent = true),
  status text not null default 'unread' check (status in ('unread','read','archived')),
  requester_hash text,            -- salted hash for abuse detection; never a raw IP
  created_at timestamptz not null default now()
);
create index contact_status_idx on public.contact_submissions (status, created_at desc);

-- ---------- Audits ----------
create table public.audit_jobs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  normalized_url text not null,
  host text not null,
  status text not null default 'queued' check (status in ('queued','running','completed','failed')),
  score smallint check (score between 0 and 100),
  report jsonb,                    -- full evidence-based report payload
  error_code text,                 -- safe, generic code; never raw server errors
  requester_hash text,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  expires_at timestamptz not null default (now() + interval '90 days')
);
create index audit_user_idx on public.audit_jobs (user_id, created_at desc);
create index audit_cache_idx on public.audit_jobs (normalized_url, created_at desc) where status = 'completed';
create index audit_expiry_idx on public.audit_jobs (expires_at);

-- ---------- Analytics (first-party, no raw IPs, no fingerprinting) ----------
create table public.analytics_events (
  id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),
  event_type text not null check (event_type in ('page_view','cta_click','audit_submit','contact_submit')),
  path text not null check (char_length(path) <= 200),
  is_landing boolean not null default false,
  referrer_category text check (referrer_category in ('direct','search','social','other')),
  device_category text check (device_category in ('mobile','tablet','desktop')),
  browser_category text check (char_length(browser_category) <= 30),
  -- Hash of (daily-rotating salt + coarse UA + IP), computed server-side. Rotates daily,
  -- so it cannot track a person across days. Used only to estimate daily unique visitors.
  visitor_hash text,
  country char(2)                  -- only if a legitimate source (e.g. Cloudflare header) exists
);
create index analytics_time_idx on public.analytics_events (occurred_at desc);
create index analytics_path_idx on public.analytics_events (path, occurred_at desc);

-- ---------- Rate limiting (server-only) ----------
create table public.rate_limits (
  key text not null,
  window_start timestamptz not null,
  count integer not null default 1,
  primary key (key, window_start)
);
