-- Site Sentinel: 状態管理・イベント・認証・巡回キュー

alter table public.monitored_sites
  add column if not exists status text not null default 'unknown'
    check (status in ('unknown','up','down')),
  add column if not exists consecutive_failures int not null default 0,
  add column if not exists last_checked_at timestamptz,
  add column if not exists last_status_changed_at timestamptz;

alter table public.monitored_sites
  add constraint monitored_sites_url_scheme check (url ~* '^https?://'),
  add constraint monitored_sites_url_len check (char_length(url) <= 2048),
  add constraint monitored_sites_interval check (interval_min between 1 and 60);

alter table public.site_checks add column if not exists error text;

-- ダウン/復旧イベント
create table public.site_events (
  id bigint generated always as identity primary key,
  site_id uuid not null references public.monitored_sites(id) on delete cascade,
  kind text not null check (kind in ('down','recovered')),
  detail text,
  created_at timestamptz not null default now()
);
create index idx_site_events_site_created on public.site_events(site_id, created_at desc);
alter table public.site_events enable row level security;
create policy "tenant events" on public.site_events for select to authenticated
  using (site_id in (select s.id from public.monitored_sites s
         join public.tenants t on t.id = s.tenant_id
         where t.owner_id = (select auth.uid())));
grant select on public.site_events to authenticated;

-- 巡回の効率化
create index idx_monitored_sites_due on public.monitored_sites(last_checked_at nulls first);

-- 無料枠保護: テナントあたり25サイトまで
create or replace function public.enforce_site_limit() returns trigger
language plpgsql security invoker set search_path = '' as $$
begin
  if (select count(*) from public.monitored_sites where tenant_id = new.tenant_id) >= 25 then
    raise exception 'site limit reached (25 per tenant)';
  end if;
  return new;
end $$;
create trigger trg_site_limit before insert on public.monitored_sites
  for each row execute function public.enforce_site_limit();

-- 巡回対象を原子的に確保 (skip locked で多重実行時の二重チェックを防ぐ)
create or replace function public.claim_due_sites(p_limit int default 50)
returns table(id uuid, tenant_id uuid, url text, interval_min int, status text, consecutive_failures int)
language sql security invoker set search_path = '' as $$
  with due as (
    select s.id from public.monitored_sites s
    where s.last_checked_at is null
       or s.last_checked_at + make_interval(mins => s.interval_min) <= now() + interval '10 seconds'
    order by s.last_checked_at nulls first
    limit p_limit
    for update skip locked
  )
  update public.monitored_sites m set last_checked_at = now()
  from due where m.id = due.id
  returning m.id, m.tenant_id, m.url, m.interval_min, m.status, m.consecutive_failures;
$$;
revoke execute on function public.claim_due_sites(int) from public, anon, authenticated;
grant execute on function public.claim_due_sites(int) to service_role;

-- 共有シークレット照合 (Vaultの値は関数内でのみ参照。service_roleのみ実行可)
create or replace function public.verify_sentinel_secret(p_secret text) returns boolean
language sql security definer set search_path = '' as $$
  select exists (
    select 1 from vault.decrypted_secrets
    where name = 'sentinel_secret' and p_secret <> '' and decrypted_secret = p_secret);
$$;
revoke execute on function public.verify_sentinel_secret(text) from public, anon, authenticated;
grant execute on function public.verify_sentinel_secret(text) to service_role;
