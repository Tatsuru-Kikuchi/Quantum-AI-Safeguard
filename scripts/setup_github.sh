#!/usr/bin/env bash
# 事前: gh auth login 済みであること
set -e
git init -b main
git add .
git commit -m "chore: initial scaffold (Phase 0)"
gh repo create Tatsuru-Kikuchi/Quantum-AI-Safeguard --public --source=. --remote=origin --push \
  --description "AIから顧客データを守る量子AIセキュリティサービス"
