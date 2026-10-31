-- 監査ログのハッシュチェーン追記 (service_roleのみ実行可)
-- 時刻はUTC固定書式でハッシュ化(セッションのタイムゾーンに依存させない)
create or replace function public.append_audit_log(
  p_tenant uuid, p_action text, p_pii text[], p_threats text[]
) returns bigint
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_prev text;
  v_ts timestamptz := now();
  v_hash text;
  v_id bigint;
begin
  if p_action not in ('masked','blocked','passed') then
    raise exception 'invalid action';
  end if;
  -- テナント単位で直列化し、チェーンの分岐を防ぐ
  perform pg_advisory_xact_lock(hashtextextended(p_tenant::text, 0));
  select entry_hash into v_prev from public.audit_logs
    where tenant_id = p_tenant order by id desc limit 1;
  v_hash := encode(sha256(convert_to(
    coalesce(v_prev,'') || '|' || p_tenant::text || '|' || p_action || '|' ||
    array_to_string(coalesce(p_pii,'{}'), ',') || '|' ||
    array_to_string(coalesce(p_threats,'{}'), ',') || '|' ||
    to_char(v_ts at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), 'UTF8')), 'hex');
  insert into public.audit_logs(tenant_id, action, pii_types, threat_flags, prev_hash, entry_hash, created_at)
    values (p_tenant, p_action, coalesce(p_pii,'{}'), coalesce(p_threats,'{}'), v_prev, v_hash, v_ts)
    returning id into v_id;
  return v_id;
end $$;

revoke execute on function public.append_audit_log(uuid, text, text[], text[]) from public, anon, authenticated;
grant execute on function public.append_audit_log(uuid, text, text[], text[]) to service_role;

-- チェーン検証 (RLSにより自分のテナントのみ)。ダッシュボードの改ざん検知に使用
create or replace function public.verify_audit_chain(p_tenant uuid)
returns table(valid boolean, broken_at bigint)
language plpgsql
security invoker
set search_path = ''
as $$
declare r record; v_prev text := null; v_calc text;
begin
  for r in select * from public.audit_logs where tenant_id = p_tenant order by id loop
    v_calc := encode(sha256(convert_to(
      coalesce(v_prev,'') || '|' || p_tenant::text || '|' || r.action || '|' ||
      array_to_string(r.pii_types, ',') || '|' || array_to_string(r.threat_flags, ',') || '|' ||
      to_char(r.created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), 'UTF8')), 'hex');
    if r.prev_hash is distinct from v_prev or r.entry_hash <> v_calc then
      return query select false, r.id; return;
    end if;
    v_prev := r.entry_hash;
  end loop;
  return query select true, null::bigint;
end $$;

revoke execute on function public.verify_audit_chain(uuid) from public, anon;
grant execute on function public.verify_audit_chain(uuid) to authenticated;
