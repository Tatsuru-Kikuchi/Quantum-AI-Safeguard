create extension if not exists pg_cron with schema pg_catalog;
create extension if not exists pg_net with schema extensions;

-- 共有シークレットはDB内で生成(リポジトリ・チャットには出さない)
select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'sentinel_secret',
  'Site Sentinel invocation secret')
where not exists (select 1 from vault.secrets where name = 'sentinel_secret');

-- 毎分: Site Sentinelを起動 (各サイトのinterval_minはclaim_due_sitesが判定)
select cron.schedule('site-sentinel-run', '* * * * *', $job$
  select net.http_post(
    url := 'https://zgrgomcurdyctkdtatci.supabase.co/functions/v1/site-sentinel',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-sentinel-secret', (select decrypted_secret from vault.decrypted_secrets where name = 'sentinel_secret')),
    body := '{}'::jsonb,
    timeout_milliseconds := 55000);
$job$);

-- 毎日 03:00 UTC: 30日より古いチェック履歴を削除
select cron.schedule('site-checks-retention', '0 3 * * *', $job$
  delete from public.site_checks where checked_at < now() - interval '30 days';
$job$);
