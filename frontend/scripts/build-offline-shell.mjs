import { createHash } from 'node:crypto'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = new URL('../dist/', import.meta.url)
const worker = 'offline-shell.js'
const paths = (await readdir(root, { recursive: true, withFileTypes: true }))
  .filter((file) => file.isFile() && file.name !== worker && !file.name.endsWith('.map'))
  .map((file) => relative(fileURLToPath(root), join(file.parentPath, file.name)))
  .map((path) => '/' + path.split(sep).map(encodeURIComponent).join('/'))
  .sort()
if (!paths.includes('/index.html') || !paths.some((path) => path.startsWith('/assets/'))) {
  throw new Error('Build the frontend before generating the offline shell.')
}

const body = await readFile(new URL('offline-shell.js', import.meta.url), 'utf8')
const prefix = 'safevault-offline-shell-'
const hash = createHash('sha256').update(body).update(JSON.stringify(paths))
for (const path of paths) hash.update(await readFile(new URL(path.slice(1), root)))
const cache = prefix + hash.digest('hex').slice(0, 20)
const header = `const PREFIX = ${JSON.stringify(prefix)};\nconst CACHE = ${JSON.stringify(cache)};\nconst ASSETS = ${JSON.stringify(paths)};\n`
await writeFile(new URL(worker, root), header + body)
