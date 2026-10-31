// PII検出・マスキング & Prompt Shield (MVP)
// 方針: 生のテキストは保存しない。検出した「種別」だけを監査ログへ残す。

// 順序が重要: 長い数字列(カード)→12桁(マイナンバー)→メール→電話→郵便番号
const PII_RULES: Array<[string, RegExp]> = [
  ["credit_card", /\b(?:\d[ -]?){13,16}\b/g],
  ["my_number", /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g],
  ["email", /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g],
  ["phone_jp", /\b0\d{1,4}-\d{1,4}-\d{3,4}\b|\b0[789]0\d{8}\b/g],
  ["postal_jp", /〒?\b\d{3}-\d{4}\b/g],
];

export function maskPII(text: string): { masked: string; types: string[] } {
  const found = new Set<string>();
  let out = text;
  for (const [type, re] of PII_RULES) {
    out = out.replace(re, () => {
      found.add(type);
      return `[${type.toUpperCase()}]`;
    });
  }
  return { masked: out, types: [...found] };
}

// Prompt Shield: ルール名のみ返す(パターン自体は外に出さない)
const THREAT_RULES: Array<[string, RegExp]> = [
  ["ignore_previous", /ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules)/i],
  ["reveal_system_prompt", /(reveal|show|print|repeat|display|tell)\s+(me\s+)?(your\s+|the\s+)?(hidden\s+)?system\s+prompt/i],
  ["jailbreak_persona", /\b(DAN|developer mode|jailbreak)\b/i],
  ["ja_ignore_instructions", /(以前|これまで|上記)の(指示|命令|ルール)を(無視|忘れ|破棄)/],
  ["ja_reveal_system_prompt", /システムプロンプト(を|は).{0,10}(表示|教え|出力|見せ)/],
  ["exfiltrate_data", /(send|post|upload|送信).{0,30}(all|every|全て|全件).{0,30}(customer|user|patient|顧客|患者|個人情報)/i],
];

export function detectThreats(text: string): string[] {
  return THREAT_RULES.filter(([, re]) => re.test(text)).map(([name]) => name);
}
