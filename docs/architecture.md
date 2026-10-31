# Architecture (MVP)
Client App → [Supabase Edge Function: ai-guard] → (PII mask / Prompt Shield / audit log) → 外部AI API
Supabase Postgres: tenants, audit_logs, monitored_sites, site_checks (全テーブルRLS)
Google Cloud: Cloud Scheduler → Cloud Run Job (Site Sentinel) → Supabase / Webhook通知
Crypto: AES-256-GCM (MVP) / 鍵ID付与で将来PQCハイブリッドへ移行可能
