# Quantum-AI-Safeguard
AIから顧客データを守るセキュリティサービス。Supabase + Google Cloud 無料枠で最短ローンチ(1〜2週間)を目指すMVP。

## MVP 3機能
1. **AI Data Guard** – 顧客データ(PII)をAIへ送る前に検知・マスキングするゲートウェイ
2. **Prompt Shield** – プロンプトインジェクション/機密流出パターンの検知とブロック
3. **Site Sentinel** – 病院等のWebサイトの稼働・応答監視とダウン通知

> 「量子」要素は段階導入: MVPはAES-256-GCM + 鍵ローテーション設計(暗号アジリティ確保)、Phase2でML-KEM等のPQCハイブリッド化。

## ディレクトリ構成
```
Quantum-AI-Safeguard/
├── .github/            # CI・Issue/PRテンプレート
├── docs/               # tasks.md(進捗), architecture.md, security-policy.md
├── scripts/            # セットアップ・デプロイ補助
├── supabase/
│   ├── migrations/     # DBスキーマ + RLS
│   ├── functions/      # Edge Functions (ai-guard, _shared)
│   └── tests/
├── web/                # ダッシュボードUI (src/pages, components, lib)
├── cloud/
│   ├── monitor/        # Site Sentinel (Cloud Run Jobs/Scheduler)
│   └── cloud-run-gateway/
└── tests/
```

## 進捗
`docs/tasks.md` を参照。
