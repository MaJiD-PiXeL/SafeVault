const GROUPS = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*()-_=+[]{}:,.?']

function randomIndex(length: number) {
  const limit = 256 - 256 % length
  const byte = new Uint8Array(1)
  do { crypto.getRandomValues(byte) } while (byte[0] >= limit)
  return byte[0] % length
}

export function generatePassword(length = 20): string {
  if (!Number.isInteger(length) || length < 12 || length > 128) throw new Error('Choose a length from 12 to 128.')
  const alphabet = GROUPS.join('')
  const characters = GROUPS.map((group) => group[randomIndex(group.length)])
  while (characters.length < length) characters.push(alphabet[randomIndex(alphabet.length)])
  for (let i = characters.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1)
    ;[characters[i], characters[j]] = [characters[j], characters[i]]
  }
  return characters.join('')
}
