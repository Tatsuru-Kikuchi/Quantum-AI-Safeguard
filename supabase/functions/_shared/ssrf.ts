// SSRF対策: 利用者が登録したURLをサーバーが取得するため、内部ネットワーク宛てを遮断する。
// 純粋関数のみ(DNS解決はDeno側 index.ts で実施)。

const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443"]);

export function isPrivateIPv4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // 不正は拒否
  const [a, b] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||   // CGNAT
    (a === 169 && b === 254) ||             // link-local / クラウドmetadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && p[2] === 0) || // 192.0.0.0/24
    (a === 198 && (b === 18 || b === 19)) ||// benchmark
    a >= 224                                // multicast / reserved / broadcast
  );
}

export function isPrivateIPv6(ip: string): boolean {
  const s = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (s === "::" || s === "::1") return true;
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  if (s.startsWith("::ffff:") || s.startsWith("64:ff9b:")) return true; // 16進表記のマップ/NAT64は一律拒否
  return /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || s.startsWith("ff"); // ULA / link-local / multicast
}

export function isPrivateIp(ip: string): boolean {
  return ip.includes(":") ? isPrivateIPv6(ip) : isPrivateIPv4(ip);
}

export type UrlCheck = { ok: true; url: URL; hostIsIp: boolean } | { ok: false; reason: string };

// 構文・ホスト名レベルの検証 (DNS解決前)
export function validateUrlSyntax(raw: string): UrlCheck {
  let u: URL;
  try { u = new URL(raw); } catch { return { ok: false, reason: "invalid_url" }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, reason: "scheme_not_allowed" };
  if (u.username || u.password) return { ok: false, reason: "credentials_not_allowed" };
  if (!ALLOWED_PORTS.has(u.port)) return { ok: false, reason: "port_not_allowed" };
  const h = u.hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") ||
      h.endsWith(".lan") || h.endsWith(".home.arpa") || !h.includes(".") && !h.includes(":")) {
    return { ok: false, reason: "internal_hostname" };
  }
  const bare = h.replace(/^\[|\]$/g, "");
  const isV6 = bare.includes(":");
  // 数字だけ/16進/8進などの変則IPv4表記(例: 2130706433, 0x7f.1)は拒否
  const isDotted = /^\d+\.\d+\.\d+\.\d+$/.test(bare);
  if (!isV6 && !isDotted && /^[\d.x]+$/i.test(bare)) return { ok: false, reason: "ambiguous_ip_format" };
  if ((isV6 || isDotted) && isPrivateIp(bare)) return { ok: false, reason: "private_ip" };
  return { ok: true, url: u, hostIsIp: isV6 || isDotted };
}
