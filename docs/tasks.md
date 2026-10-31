# タスク進捗ログ (Quantum-AI-Safeguard)
更新ルール: 完了ごとに [ ] → [x]、日付を追記。

## Phase 0: 基盤 (Day 1)
- [x] ローカルディレクトリ構成の作成
- [x] README / .gitignore / .env.example / tasks.md 作成
- [ ] GitHubリポジトリ作成 (Tatsuru-Kikuchi/Quantum-AI-Safeguard) → `scripts/setup_github.sh`
- [ ] Supabaseプロジェクト作成・キー設定
- [ ] Google Cloudプロジェクト作成(請求アラート設定)

## Phase 1: コア防御 (Day 2-5)
- [x] DBスキーマ+RLS ドラフト `supabase/migrations/0001_init.sql`
- [x] PII検出/マスキング ドラフト `supabase/functions/_shared/pii.ts`
- [ ] Edge Function `ai-guard` 実装 (マスク→監査ログ→転送)
- [ ] Prompt Shield ルール実装・テスト
- [ ] 監査ログ(ハッシュチェーン)実装
- [ ] AES-256-GCM フィールド暗号化

## Phase 2: 監視 (Day 5-8)
- [ ] Site Sentinel (Cloud Run Job + Scheduler)
- [ ] ダウン検知→Webhook/メール通知

## Phase 3: UI (Day 7-11)
- [ ] ログイン(Supabase Auth)
- [ ] ダッシュボード(検知件数・マスク件数・サイト稼働)
- [ ] 設定画面(ルール・通知先)

## Phase 4: 公開 (Day 11-14)
- [ ] セキュリティ自己点検(RLS・シークレット・レート制限)
- [ ] 本番デプロイ・独自ドメイン
- [ ] 公開告知・利用ガイド
