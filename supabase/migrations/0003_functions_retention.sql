-- 0003_functions_retention.sql : atomic rate limiter, retention, admin stats. Apply after 0002.

-- Atomic counter used by Pages Functions (service role only). Returns true if allowed.
create or replace function public.hit_rate_limit(p_key text, p_window_seconds int, p_max int)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
  w timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  c int;
begin
  insert into public.rate_limits as r (key, window_start, count) values (p_key, w, 1)
  on conflict (key, window_start) do update set count = r.count + 1
  returning r.count into c;
  return c <= p_max;
end $$;
revoke all on function public.hit_rate_limit(text,int,int) from public, anon, authenticated;

-- Retention: analytics 180 days, rate-limit rows 2 days, audits past expires_at,
-- archived contact messages 365 days. Schedule with pg_cron or run manually (see README).
create or replace function public.purge_expired_data() returns void
language plpgsql security definer set search_path = '' as $$
begin
  delete from public.analytics_events where occurred_at < now() - interval '180 days';
  delete from public.rate_limits where window_start < now() - interval '2 days';
  delete from public.audit_jobs where expires_at < now();
  delete from public.contact_submissions where status = 'archived' and created_at < now() - interval '365 days';
end $$;
revoke all on function public.purge_expired_data() from public, anon, authenticated;

-- Admin analytics summary. is_admin() is checked inside, so non-admins get zero rows.
create or replace function public.admin_analytics_summary(p_from timestamptz, p_to timestamptz)
returns table (day date, page_views bigint, unique_visitors bigint)
language sql stable security definer set search_path = '' as $$
  select (occurred_at at time zone 'UTC')::date,
         count(*) filter (where event_type = 'page_view'),
         count(distinct visitor_hash)
  from public.analytics_events
  where public.is_admin() and occurred_at >= p_from and occurred_at < p_to
  group by 1 order by 1;
$$;
revoke all on function public.admin_analytics_summary(timestamptz,timestamptz) from public, anon;
grant execute on function public.admin_analytics_summary(timestamptz,timestamptz) to authenticated;

-- Starter services (editable suggestions, not claims). No fabricated prices.
insert into public.services (title, description, timeline, sort_order) values
 ('Website Design','[Editable description]','[Editable]',1),
 ('Website Development','[Editable description]','[Editable]',2),
 ('Landing Page Development','[Editable description]','[Editable]',3),
 ('Website Redesign','[Editable description]','[Editable]',4),
 ('Portfolio Websites','[Editable description]','[Editable]',5),
 ('Website Maintenance','[Editable description]','[Editable]',6);
