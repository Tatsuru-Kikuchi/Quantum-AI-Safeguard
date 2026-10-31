// AI Data Guard + Prompt Shield
// 流れ: 認証(JWT) → テナント特定(RLS) → 脅威検知 → PIIマスク → 監査ログ(ハッシュチェーン)
import { createClient } from "npm:@supabase/supabase-js@2.49.4";
import { detectThreats, maskPII } from "../_shared/pii.ts";

const MAX_PROMPT_CHARS = 20_000;

const cors = {
  "Access-Control-Allow-Origin": "*", // TODO(Phase4): 本番ドメインに限定
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

// 新キー(JSON辞書)があれば優先、なければレガシーキー
function key(newVar: string, legacyVar: string): string {
  const raw = Deno.env.get(newVar);
  if (raw) {
    try { const v = JSON.parse(raw)["default"]; if (v) return v; } catch { /* fallthrough */ }
  }
  return Deno.env.get(legacyVar) ?? "";
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return json({ error: "unauthorized" }, 401);

  // 入力検証
  let prompt: unknown;
  try { ({ prompt } = await req.json()); } catch { return json({ error: "invalid_json" }, 400); }
  if (typeof prompt !== "string" || prompt.length === 0) return json({ error: "prompt_required" }, 400);
  if (prompt.length > MAX_PROMPT_CHARS) return json({ error: "prompt_too_long", max: MAX_PROMPT_CHARS }, 413);

  const url = Deno.env.get("SUPABASE_URL")!;
  // ユーザー権限のクライアント(RLS適用)
  const userClient = createClient(url, key("SUPABASE_PUBLISHABLE_KEYS", "SUPABASE_ANON_KEY"), {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: userData, error: userErr } = await userClient.auth.getUser(authHeader.slice(7));
  if (userErr || !userData?.user) return json({ error: "unauthorized" }, 401);

  // テナント特定: RLSにより自分のテナントしか見えない
  const { data: tenant } = await userClient.from("tenants").select("id").limit(1).maybeSingle();
  if (!tenant) return json({ error: "no_tenant", hint: "先にテナントを作成してください" }, 403);

  // 検知・マスキング
  const threats = detectThreats(prompt);
  const { masked, types } = maskPII(prompt);
  const action = threats.length ? "blocked" : types.length ? "masked" : "passed";

  // 監査ログ: service_roleのみ実行可能なDB関数でハッシュチェーンに追記(生テキストは保存しない)
  const admin = createClient(url, key("SUPABASE_SECRET_KEYS", "SUPABASE_SERVICE_ROLE_KEY"));
  const { error: logErr } = await admin.rpc("append_audit_log", {
    p_tenant: tenant.id, p_action: action, p_pii: types, p_threats: threats,
  });
  if (logErr) {
    console.error("audit_log_failed", logErr.message);
    return json({ error: "audit_unavailable" }, 503); // 監査できない場合は通さない(fail closed)
  }

  if (action === "blocked") return json({ action, threats }, 403);
  return json({ action, masked_prompt: masked, pii_types: types });
});
