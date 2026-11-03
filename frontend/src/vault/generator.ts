export type GeneratorOptions = { uppercase: boolean; lowercase: boolean; digits: boolean; symbols: boolean; excludeSimilar: boolean }
export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = { uppercase: true, lowercase: true, digits: true, symbols: true, excludeSimilar: true }
const GROUPS = { uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lowercase: 'abcdefghijklmnopqrstuvwxyz', digits: '0123456789', symbols: '!@#$%^&*()-_=+[]{}:,.?' }

function randomIndex(length: number) {
  const limit = 256 - 256 % length
  const byte = new Uint8Array(1)
  do { crypto.getRandomValues(byte) } while (byte[0] >= limit)
  return byte[0] % length
}

export function generatePassword(length = 20, options: Partial<GeneratorOptions> = {}): string {
  if (!Number.isInteger(length) || length < 12 || length > 128) throw new Error('Choose a length from 12 to 128.')
  const settings = { ...DEFAULT_GENERATOR_OPTIONS, ...options }
  if (Object.keys(options).some((key) => !Object.hasOwn(DEFAULT_GENERATOR_OPTIONS, key)) || Object.values(settings).some((value) => typeof value !== 'boolean')) throw new Error('Invalid generator options.')
  const groups = Object.entries(GROUPS).filter(([name]) => settings[name as keyof typeof GROUPS])
    .map(([, group]) => settings.excludeSimilar ? group.replace(/[Il1O0o]/g, '') : group)
  if (!groups.length) throw new Error('Select at least one character group.')
  const alphabet = groups.join('')
  // Reject whole candidates to sample uniformly from strings containing every selected group.
  for (;;) {
    const characters = Array.from({ length }, () => alphabet[randomIndex(alphabet.length)])
    if (groups.every((group) => characters.some((char) => group.includes(char)))) return characters.join('')
  }
}
