import test from "node:test";
import assert from "node:assert/strict";
import { isPrivateIp, validateUrlSyntax } from "../supabase/functions/_shared/ssrf.ts";

test("プライベート/予約IPv4を遮断", () => {
  for (const ip of ["127.0.0.1","10.1.2.3","172.16.0.1","172.31.255.255","192.168.1.1","169.254.169.254","100.64.0.1","0.0.0.0","224.0.0.1","255.255.255.255"])
    assert.ok(isPrivateIp(ip), ip);
});
test("公開IPv4は許可", () => {
  for (const ip of ["8.8.8.8","93.184.216.34","172.32.0.1","100.63.0.1"]) assert.ok(!isPrivateIp(ip), ip);
});
test("IPv6の内部アドレスを遮断", () => {
  for (const ip of ["::1","::","fd00::1","fe80::1","ff02::1","::ffff:127.0.0.1","::ffff:10.0.0.1"]) assert.ok(isPrivateIp(ip), ip);
  assert.ok(!isPrivateIp("2606:4700:4700::1111"));
});
test("危険なURLを拒否", () => {
  const bad = ["file:///etc/passwd","ftp://example.com","http://localhost","http://127.0.0.1","http://[::1]/",
    "http://169.254.169.254/latest/meta-data","http://metadata.google.internal","http://intranet",
    "http://user:pass@example.com","https://example.com:22","http://2130706433","http://0x7f.1","not a url"];
  for (const u of bad) assert.equal(validateUrlSyntax(u).ok, false, u);
});
test("通常の公開URLは許可", () => {
  for (const u of ["https://example.com","http://example.co.jp/path?x=1","https://hospital.example.jp:8443/"])
    assert.equal(validateUrlSyntax(u).ok, true, u);
});
