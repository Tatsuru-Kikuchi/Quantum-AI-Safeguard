# Site Sentinel
MVPはSupabase側で稼働: `pg_cron`(毎分) → `pg_net` → Edge Function `site-sentinel` (東京)。
Google Cloud (Cloud Run Job + Scheduler) は **第2の監視拠点(外部視点の二重化)** としてPhase 2.5で追加予定。

## 既知の制約
- DNSリバインディング(検証後の再解決)は完全には防げない。ただしEdge Functionは内部ネットワークを持たない。
- 通知先は環境変数 `ALERT_WEBHOOK_URL`(運営者設定)のみ。テナント別通知は未実装。
