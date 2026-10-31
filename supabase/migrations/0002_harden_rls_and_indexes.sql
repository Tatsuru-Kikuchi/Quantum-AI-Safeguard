create index if not exists idx_tenants_owner_id on public.tenants(owner_id);
create index if not exists idx_audit_logs_tenant_created on public.audit_logs(tenant_id, created_at desc);
create index if not exists idx_monitored_sites_tenant_id on public.monitored_sites(tenant_id);
create index if not exists idx_site_checks_site_checked on public.site_checks(site_id, checked_at desc);

drop policy "own tenant" on public.tenants;
drop policy "tenant logs" on public.audit_logs;
drop policy "tenant sites" on public.monitored_sites;
drop policy "tenant checks" on public.site_checks;

create policy "own tenant" on public.tenants for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
create policy "tenant logs" on public.audit_logs for select to authenticated
  using (tenant_id in (select id from public.tenants where owner_id = (select auth.uid())));
create policy "tenant sites" on public.monitored_sites for all to authenticated
  using (tenant_id in (select id from public.tenants where owner_id = (select auth.uid())))
  with check (tenant_id in (select id from public.tenants where owner_id = (select auth.uid())));
create policy "tenant checks" on public.site_checks for select to authenticated
  using (site_id in (select s.id from public.monitored_sites s
         join public.tenants t on t.id = s.tenant_id
         where t.owner_id = (select auth.uid())));

revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
