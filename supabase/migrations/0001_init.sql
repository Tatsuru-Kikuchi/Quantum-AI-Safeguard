create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null references auth.users(id),
  created_at timestamptz default now()
);
create table public.audit_logs (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id),
  action text not null,            -- masked | blocked | passed
  pii_types text[] default '{}',
  threat_flags text[] default '{}',
  prev_hash text,
  entry_hash text not null,        -- ハッシュチェーン(改ざん検知)
  created_at timestamptz default now()
);
create table public.monitored_sites (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  url text not null,
  interval_min int default 5,
  created_at timestamptz default now()
);
create table public.site_checks (
  id bigint generated always as identity primary key,
  site_id uuid not null references public.monitored_sites(id),
  status_code int, latency_ms int, ok boolean,
  checked_at timestamptz default now()
);
alter table public.tenants enable row level security;
alter table public.audit_logs enable row level security;
alter table public.monitored_sites enable row level security;
alter table public.site_checks enable row level security;

create policy "own tenant" on public.tenants for all using (owner_id = auth.uid());
create policy "tenant logs" on public.audit_logs for select using (
  tenant_id in (select id from public.tenants where owner_id = auth.uid()));
create policy "tenant sites" on public.monitored_sites for all using (
  tenant_id in (select id from public.tenants where owner_id = auth.uid()));
create policy "tenant checks" on public.site_checks for select using (
  site_id in (select s.id from public.monitored_sites s join public.tenants t on t.id=s.tenant_id where t.owner_id = auth.uid()));
