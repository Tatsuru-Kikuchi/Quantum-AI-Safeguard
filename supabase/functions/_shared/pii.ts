// 日本向けPIIの簡易検出・マスキング (MVP)
const RULES: Record<string, RegExp> = {
  email: /[\w.+-]+@[\w-]+\.[\w.-]+/g,
  phone_jp: /0\d{1,4}-?\d{1,4}-?\d{3,4}/g,
  credit_card: /\b(?:\d[ -]?){13,16}\b/g,
  my_number: /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g,
  postal_jp: /〒?\d{3}-\d{4}/g,
};
export function maskPII(text: string) {
  const found: string[] = [];
  let out = text;
  for (const [type, re] of Object.entries(RULES)) {
    out = out.replace(re, () => { found.push(type); return `[${type.toUpperCase()}]`; });
  }
  return { masked: out, types: [...new Set(found)] };
}
const INJECTION = [/ignore (all )?previous instructions/i, /system prompt/i, /以前の指示を(無視|忘れ)/];
export function detectThreats(text: string) {
  return INJECTION.filter((r) => r.test(text)).map((r) => r.source);
}
