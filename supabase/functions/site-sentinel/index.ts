// Site Sentinel: 登録サイトの稼働を巡回チェックし、ダウン/復旧を記録・通知する。
// 起動: pg_cron(毎分) → pg_net → この関数。認証は共有シークレット(Vault)。
import { createClient } from "npm:@supabase/supabase-js@2.49.4";
import { isPrivateIp, validateUrlSyntax } from "../_shared/ssrf.ts";

const TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 3;
const BATCH = 50;
const CONCURRENCY = 10;
const DOWN_AFTER_FAILURES = 2; // 連続2回失敗でダウン判定(誤報抑制)

function key(newVar: string, legacyVar: string): string {
  const raw = Deno.env.get(newVar);
  if (raw) { try { const v = JSON.parse(raw)["default"]; if (v) return v; } catch { /* fallthrough */ } }
  return Deno.env.get(legacyVar) ?? "";
}

type Site = {
  id: string; tenant_id: string; url: string; interval_min: number;
  status: "unknown" | "up" | "down"; consecutive_failures: number;
};
type Result = { ok: boolean; status_code: number | null; latency_ms: number; error: string | null };

// DNS解決後のIPも検証(公開IPのみ許可)
async function assertPublicHost(u: URL, hostIsIp: boolean): Promise<string | null> {
  if (hostIsIp) return null; // 構文検証で判定済み
  try {
    const [a, aaaa] = await Promise.all([
      Deno.resolveDns(u.hostname, "A").catch(() => [] as string[]),
      Deno.resolveDns(u.hostname, "AAAA").catch(() => [] as string[]),
    ]);
    const ips = [...a, ...aaaa];
    if (ips.length === 0) return "dns_failure";
    if (ips.some(isPrivateIp)) return "resolves_to_private_ip";
    return null;
  } catch { return "dns_failure"; }
}

async function checkSite(rawUrl: string): Promise<Result> {
  const started = performance.now();
  let current = rawUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const v = validateUrlSyntax(current);
    if (!v.ok) return fail(started, null, `blocked:${v.reason}`);
    const dnsErr = await assertPublicHost(v.url, v.hostIsIp);
    if (dnsErr) return fail(started, null, dnsErr);
    try {
      const res = await fetch(v.url, {
        method: "GET", redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { "User-Agent": "Quantum-AI-Safeguard-SiteSentinel/1.0" },
      });
      await res.body?.cancel(); // 本文は読まない
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        current = new URL(res.headers.get("location")!, v.url).toString(); // リダイレクト先も毎回検証
        continue;
      }
      // 5xxのみ「ダウン」。4xx(WAF/認証)は到達できているので稼働扱い
      return {
        ok: res.status < 500, status_code: res.status,
        latency_ms: Math.round(performance.now() - started),
        error: res.status < 500 ? null : `http_${res.status}`,
      };
    } catch (e) {
      const name = (e as Error).name;
      return fail(started, null, name === "TimeoutError" ? "timeout" : "network_error");
    }
  }
  return fail(started, null, "too_many_redirects");
}
const fail = (started: number, code: number | null, error: string): Result =>
  ({ ok: false, status_code: code, latency_ms: Math.round(performance.now() - started), error });

async function notify(text: string) {
  const hook = Deno.env.get("ALERT_WEBHOOK_URL");
  if (!hook) return;
  try {
    await fetch(hook, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, content: text }), // Slack/Discord互換
      signal: AbortSignal.timeout(5_000),
    });
  } catch (e) { console.error("webhook_failed", (e as Error).message); }
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return new Response("method_not_allowed", { status: 405 });
  const url = Deno.env.get("SUPABASE_URL")!;
  const admin = createClient(url, key("SUPABASE_SECRET_KEYS", "SUPABASE_SERVICE_ROLE_KEY"));

  // 共有シークレット検証(Vault上の値とDB関数で照合)
  const secret = req.headers.get("x-sentinel-secret") ?? "";
  const { data: authorized } = await admin.rpc("verify_sentinel_secret", { p_secret: secret });
  if (authorized !== true) return new Response("unauthorized", { status: 401 });

  const { data: sites, error } = await admin.rpc("claim_due_sites", { p_limit: BATCH });
  if (error) { console.error("claim_failed", error.message); return new Response("error", { status: 500 }); }

  const queue = [...((sites ?? []) as Site[])];
  let down = 0, recovered = 0;

  async function worker() {
    for (let s = queue.shift(); s; s = queue.shift()) {
      const r = await checkSite(s.url);
      await admin.from("site_checks").insert({
        site_id: s.id, status_code: r.status_code, latency_ms: r.latency_ms, ok: r.ok, error: r.error,
      });
      const failures = r.ok ? 0 : s.consecutive_failures + 1;
      let status = s.status;
      if (r.ok) {
        if (s.status === "down") { status = "up"; recovered++; await event(s, "recovered", `HTTP ${r.status_code}, ${r.latency_ms}ms`); }
        else if (s.status === "unknown") status = "up";
      } else if (failures >= DOWN_AFTER_FAILURES && s.status !== "down") {
        status = "down"; down++; await event(s, "down", r.error ?? "unknown");
      }
      await admin.from("monitored_sites").update({
        status, consecutive_failures: failures,
        ...(status !== s.status ? { last_status_changed_at: new Date().toISOString() } : {}),
      }).eq("id", s.id);
    }
  }
  async function event(s: Site, kind: "down" | "recovered", detail: string) {
    await admin.from("site_events").insert({ site_id: s.id, kind, detail });
    await notify(kind === "down"
      ? `🚨 サイトがダウンしています: ${s.url} (${detail})`
      : `✅ サイトが復旧しました: ${s.url} (${detail})`);
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
  return Response.json({ checked: (sites ?? []).length, down, recovered });
});
