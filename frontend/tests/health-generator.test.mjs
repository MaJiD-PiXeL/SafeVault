import assert from 'node:assert/strict'
import { test } from 'node:test'
import { analyzePasswords, passwordWarnings } from '../src/vault/health.ts'
import { generatePassword } from '../src/vault/generator.ts'

function entry(id, password) {
  return { envelope: { id }, data: { password } }
}

test('health finds exact reuse, counts overlapping entries once, and returns no passwords', () => {
  const secret = 'password123!'
  const report = analyzePasswords([entry('a', secret), entry('b', secret), entry('c', 'jH8%vN2+rQ5!zL9@')])
  assert.deepEqual({ total: report.total, weak: report.weak, reused: report.reused, review: report.review }, { total: 3, weak: 2, reused: 2, review: 2 })
  assert.deepEqual(report.findings.map((item) => item.id), ['a', 'b', 'c'])
  assert.equal(report.findings[0].reuseCount, 2)
  assert.ok(!JSON.stringify(report).includes(secret))
  assert.deepEqual(analyzePasswords([]), { total: 0, weak: 0, reused: 0, review: 0, findings: [] })
})

test('health preserves case, whitespace and Unicode in reuse comparisons', () => {
  const report = analyzePasswords(['Exact phrase 42!', 'exact phrase 42!', ' Exact phrase 42!', 'Exact phrase 42! ', '\u00e9', 'e\u0301'].map((password, index) => entry(String(index), password)))
  assert.equal(report.reused, 0)
})

test('local warnings cover short Unicode, common substitutions, repeated blocks and sequences', () => {
  assert.ok(passwordWarnings('🔐'.repeat(11)).includes('short'))
  assert.ok(!passwordWarnings('🔐'.repeat(12)).includes('short'))
  for (const password of ['password123!', 'P@ssw0rd123!', 'Welcome2026!', 'letmein!!']) assert.ok(passwordWarnings(password).includes('common'), password)
  for (const password of ['a'.repeat(10000), 'abcd'.repeat(2500), '🔐😀'.repeat(6)]) assert.ok(passwordWarnings(password).includes('repeated'))
  for (const password of ['1234567890', 'qwertyuiop', 'zyxwvuts']) assert.ok(passwordWarnings(password).includes('sequence'))
  assert.deepEqual(passwordWarnings('orchard river lantern meadow'), [])
  assert.deepEqual(passwordWarnings('jH8%vN2+rQ5!zL9@'), [])
})

test('generator supports every nonempty character-group combination with crypto randomness', (t) => {
  t.mock.method(Math, 'random', () => { throw new Error('weak randomness forbidden') })
  const names = ['uppercase', 'lowercase', 'digits', 'symbols']
  const patterns = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/]
  for (let mask = 1; mask < 16; mask += 1) {
    const options = Object.fromEntries(names.map((name, index) => [name, Boolean(mask & (1 << index))]))
    for (const length of [12, 128]) {
      const password = generatePassword(length, options)
      assert.equal(password.length, length)
      names.forEach((name, index) => assert.equal(patterns[index].test(password), options[name]))
      assert.doesNotMatch(password, /[Il1O0o]/)
    }
  }
  const digits = generatePassword(128, { uppercase: false, lowercase: false, symbols: false, excludeSimilar: false })
  assert.match(digits, /^[0-9]+$/)
})

test('generator rejects missing groups, invalid lengths and malformed options', () => {
  assert.throws(() => generatePassword(20, { uppercase: false, lowercase: false, digits: false, symbols: false }), /at least one/)
  for (const length of [0, 11, 129, 12.5, NaN, Infinity]) assert.throws(() => generatePassword(length))
  for (const options of [{ uppercase: 'yes' }, { excludeSimilar: undefined }, { unknown: true }, { toString: true }]) assert.throws(() => generatePassword(20, options), /Invalid generator/)
})
