import type { PasswordPayload, UnlockedEntry } from './format'

export type PasswordWarning = 'short' | 'common' | 'repeated' | 'sequence'
export const WARNING_LABELS: Record<PasswordWarning, string> = {
  short: 'Fewer than 12 characters',
  common: 'Common password pattern',
  repeated: 'Repeated characters or blocks',
  sequence: 'Keyboard or counting sequence',
}

// A small, explicit local heuristic, not a breach database or entropy estimate.
export function passwordWarnings(password: string): PasswordWarning[] {
  const warnings: PasswordWarning[] = []
  const characters = Array.from(password)
  if (characters.length < 12) warnings.push('short')
  const lower = password.toLowerCase()
  const simplified = lower.replace(/[013457@$!]/g, (char) => ({ '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' })[char]!)
  if (/^(password|qwerty|letmein|welcome|admin|iloveyou|changeme|monkey|football|dragon)[\d\W_]*$/i.test(lower) ||
      /^(password|letmein|welcome|admin|iloveyou|changeme)[a-z\d\W_]{0,4}$/i.test(simplified)) warnings.push('common')
  if (characters.length > 0 && [1, 2, 3, 4].some((size) =>
    characters.length >= size * 3 && characters.every((char, index) => char === characters[index % size]))) warnings.push('repeated')
  const sequences = ['01234567890123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm']
  if (lower.length >= 6 && sequences.some((sequence) => sequence.includes(lower) || Array.from(sequence).reverse().join('').includes(lower))) warnings.push('sequence')
  return warnings
}

export function analyzePasswords(entries: readonly UnlockedEntry[]) {
  const passwords = entries.filter((entry): entry is UnlockedEntry & { data: PasswordPayload } => entry.data.schema_version === 1)
  const counts = new Map<string, number>()
  for (const entry of passwords) counts.set(entry.data.password, (counts.get(entry.data.password) ?? 0) + 1)
  const findings = passwords.map((entry) => ({ id: entry.envelope.id,
    warnings: passwordWarnings(entry.data.password), reuseCount: counts.get(entry.data.password)! }))
  // Only identifiers and findings escape this function; no password copies in the report.
  return {
    total: passwords.length,
    weak: findings.filter((item) => item.warnings.length > 0).length,
    reused: findings.filter((item) => item.reuseCount > 1).length,
    review: findings.filter((item) => item.warnings.length > 0 || item.reuseCount > 1).length,
    findings,
  }
}
