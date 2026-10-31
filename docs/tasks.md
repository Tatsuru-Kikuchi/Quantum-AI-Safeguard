# タスク進捗ログ (Quantum-AI-Safeguard)
更新ルール: 完了ごとに [ ] → [x]、日付を追記。

## Phase 0: 基盤 (Day 1)
- [x] ローカルディレクトリ構成の作成
- [x] README / .gitignore / .env.example / tasks.md 作成
- [x] GitHubリポジトリ作成 (Tatsuru-Kikuchi/Quantum-AI-Safeguard)
- [x] Supabaseプロジェクト作成 (ref: zgrgomcurdyctkdtatci, ap-northeast-1)
- [ ] Google Cloudプロジェクト作成(請求アラート設定)

## Phase 1: コア防御 (Day 2-5)
- [x] DBスキーマ+RLS ドラフト `supabase/migrations/0001_init.sql`
- [x] PII検出/マスキング ドラフト `supabase/functions/_shared/pii.ts`
- [x] Edge Function `ai-guard` 実装・デプロイ (認証→マスク→検知→監査ログ) ※AI転送は未実装
- [x] Prompt Shield ルール実装・テスト (tests/pii.test.mjs)
- [x] 監査ログ(ハッシュチェーン)実装・改ざん検知 `verify_audit_chain()`
- [ ] AES-256-GCM フィールド暗号化
- [ ] 外部AIへの転送(キー管理・レート制限)

## Phase 2: 監視 (Day 5-8)
- [x] Site Sentinel 実装・稼働 (Edge Function + pg_cron 毎分) ※SSRF対策・連続2回失敗でダウン判定
- [ ] Site Sentinel 第2拠点 (Google Cloud Run Job + Scheduler) ※任意・外部視点の二重化
- [x] ダウン/復旧イベント記録・Webhook通知 (ALERT_WEBHOOK_URL設定が必要)
- [ ] メール通知 (テナント別)

## Phase 3: UI (Day 7-11)
- [ ] ログイン(Supabase Auth)
- [ ] ダッシュボード(検知件数・マスク件数・サイト稼働)
- [ ] 設定画面(ルール・通知先)

## Phase 4: 公開 (Day 11-14)
- [ ] セキュリティ自己点検(RLS・シークレット・レート制限)
- [ ] 本番デプロイ・独自ドメイン
- [ ] 公開告知・利用ガイド
