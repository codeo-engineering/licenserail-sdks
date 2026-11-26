// The files that licenserail-youtrack adds to an app, run like YouTrack does, with real HTTP behind postAsync.
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import Module, { createRequire } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const e = process.env
const app = mkdtempSync(join(e.LR_STORAGE, 'app-'))
writeFileSync(join(app, 'manifest.json'), JSON.stringify({ name: 'e2e', widgets: [] }))
const bin = fileURLToPath(new URL('node_modules/@codeo-engineering/licenserail-youtrack/bin/licenserail-youtrack.mjs', import.meta.url))
execFileSync(process.execPath, [bin, 'add', app, '--vendor', e.LR_VENDOR, '--product', e.LR_PRODUCT, '--key-id', 'none',
  '--public-key', e.LR_PUBLIC_KEY_FILE, '--api-url', e.LR_URL], { encoding: 'utf8' })

const calls = []
class Connection {
  constructor(url) { this.url = url; this.headers = {} }
  addHeader(name, value) { this.headers[name] = value; return this }
  bearerAuth(secret) { this.headers.Authorization = `Bearer ${secret.value}`; return this }
  postAsync(uri, query, payload, callback) { calls.push({ url: this.url + uri, payload, callback, headers: this.headers }) }
}
const fakes = { '@jetbrains/youtrack-scripting-api/http': { Connection }, '@jetbrains/youtrack-scripting-api/license': { licenseInfo: { currentUserCount: 12 } } }
const resolve = Module._resolveFilename
Module._resolveFilename = function (request, ...rest) { return fakes[request] ? request : resolve.call(this, request, ...rest) }
for (const [name, exports] of Object.entries(fakes)) Module._cache[name] = { id: name, filename: name, loaded: true, exports }
const handler = createRequire(join(app, 'manifest.json'))('./licenserail-license.js').httpHandler

// App storage: the token and the last run as files (like the other drivers), the rest in one JSON file.
const FILES = { licenserailToken: 'license.lic', licenserailLastSeen: 'license.seen' }
const path = (name) => join(e.LR_STORAGE, name)
const storage = existsSync(path('storage.json')) ? JSON.parse(readFileSync(path('storage.json'), 'utf8')) : {}
for (const [k, f] of Object.entries(FILES)) storage[k] = existsSync(path(f)) ? readFileSync(path(f), 'utf8') : null

const [op, key] = process.argv.slice(2)
const m = (e.LR_DEVICE ?? '').split(',')[0].toLowerCase()
const installationId = m ? `${m.slice(0, 8)}-${m.slice(8, 12)}-${m.slice(12, 16)}-${m.slice(16, 20)}-${m.slice(20, 32)}` : 'c0368d08-878f-4f47-b836-724248d8f7e8'
const context = (extra = {}) => ({
  globalStorage: { extensionProperties: storage }, settings: { licenseKey: key === undefined ? null : { value: key } },
  currentUser: { hasPermission: () => true }, request: { json: () => ({ installationId }) }, invokeAsync() {},
  response: { statusCode: 200, body: null, json(o) { this.body = o } }, ...extra,
})

async function call(name, method = 'POST') {
  const c = context()
  handler.endpoints.find((x) => x.path === name && x.method === method).handle(c)
  if (c.response.statusCode >= 400) throw new Error(JSON.stringify(c.response.body))
  while (calls.length) {
    const r = calls.shift()
    let code = 0, body = ''
    try {
      const res = await fetch(r.url, { method: 'POST', headers: r.headers, body: r.payload, signal: AbortSignal.timeout(Number(e.LR_TIMEOUT) * 1000) })
      body = await res.text()
      code = res.status
    } catch { code = 0; body = '' }
    handler.asyncFunctions[r.callback](context({ response: { code, body } }))
  }
  return c.response.body
}

storage.licenserailInstallation = installationId   // the License page sends it with every action
async function state() { return call('status', 'GET') }
async function action(name) {
  await call(name)
  const s = await state()
  if (s.pending) throw new Error(`${name} is still pending after the response`)
  return s.lastError ? { success: false, errorCode: s.lastError.code, message: s.lastError.message } : { success: true }
}

let out
if (op === 'check') {
  let s = await state()
  if (['Expired', 'Suspended', 'OfflineTooLong', 'ClockTampered', 'Unverified'].includes(s.status)) {
    await call('refresh')   // the Refresh button of the License page
    s = await state()
  }
  out = { status: s.status, features: s.entitlements, test: s.isTest }
} else out = await action(op)

for (const [k, f] of Object.entries(FILES)) {
  if (storage[k]) writeFileSync(path(f), storage[k])
  else rmSync(path(f), { force: true })
  delete storage[k]
}
writeFileSync(path('storage.json'), JSON.stringify(storage))
rmSync(app, { recursive: true, force: true })
console.log(JSON.stringify(out))
