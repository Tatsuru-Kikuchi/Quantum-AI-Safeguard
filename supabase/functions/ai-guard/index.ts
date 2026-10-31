// TODO(Phase1): 認証→maskPII→detectThreats→監査ログ→AI転送
import { maskPII, detectThreats } from "../_shared/pii.ts";
Deno.serve(async (req) => {
  const { prompt } = await req.json();
  const threats = detectThreats(prompt);
  if (threats.length) return Response.json({ blocked: true, threats }, { status: 403 });
  const { masked, types } = maskPII(prompt);
  return Response.json({ blocked: false, masked, pii_types: types });
});
