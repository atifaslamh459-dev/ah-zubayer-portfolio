-- 0002_rls.sql : deny by default, then grant narrowly. Apply after 0001.
alter table public.admin_users        enable row level security;
alter table public.site_settings      enable row level security;
alter table public.projects           enable row level security;
alter table public.services           enable row level security;
alter table public.skills             enable row level security;
alter table public.experience_entries enable row level security;
alter table public.contact_submissions enable row level security;
alter table public.audit_jobs         enable row level security;
alter table public.analytics_events   enable row level security;
alter table public.rate_limits        enable row level security;

-- Strip default grants, then re-grant only what is needed.
revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;

-- Public read of published content
grant select on public.site_settings, public.projects, public.services,
                public.skills, public.experience_entries to anon, authenticated;
create policy settings_public_read on public.site_settings for select using (true);
create policy projects_public_read on public.projects for select using (status = 'published');
create policy services_public_read on public.services for select using (is_visible);
create policy skills_public_read on public.skills for select using (is_visible);
create policy exp_public_read on public.experience_entries for select using (is_visible);

-- Admin write access (verified in the database via is_admin(), not via client claims)
grant insert, update, delete on public.site_settings, public.projects, public.services,
      public.skills, public.experience_entries to authenticated;
create policy settings_admin_write on public.site_settings for update to authenticated
  using (public.is_admin()) with check (public.is_admin() and id = 1);
create policy projects_admin_all on public.projects for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy services_admin_all on public.services for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy skills_admin_all on public.skills for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy exp_admin_all on public.experience_entries for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
-- (the "for all" policies above also let admins read drafts and hidden rows)

-- admin_users: admins may list/add/revoke. Nobody else can see or write it.
grant select, insert, delete on public.admin_users to authenticated;
create policy admin_users_admin_all on public.admin_users for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- Contact: NO public insert. Inserts happen only in the server Function (service role).
grant select, update, delete on public.contact_submissions to authenticated;
create policy contact_admin_all on public.contact_submissions for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- Audits: owners read their own history; admins read/delete all. Writes via server only.
grant select, delete on public.audit_jobs to authenticated;
create policy audit_owner_read on public.audit_jobs for select to authenticated
  using (user_id = auth.uid());
create policy audit_admin_all on public.audit_jobs for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- Analytics: public has NO read or write. Server inserts with service role; admins read.
grant select on public.analytics_events to authenticated;
create policy analytics_admin_read on public.analytics_events for select to authenticated
  using (public.is_admin());

-- rate_limits: no policies and no grants = inaccessible except to the service role.
