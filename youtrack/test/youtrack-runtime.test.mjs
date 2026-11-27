import { strict as assert } from 'node:assert'
import { execFileSync } from 'node:child_process'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import Module from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

// Runs the app files the way YouTrack does (CommonJS, require of '@jetbrains/youtrack-scripting-api/*') against a fake
// runtime: async HTTP calls are captured and their responses delivered to the named async functions.

const root = fileURLToPath(new URL('..', import.meta.url))
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const pem = publicKey.export({ type: 'spki', format: 'pem' })
const VENDOR = 'ten_0123456789abcdef0123456789abcdef'
const UUID = 'c0368d08-878f-4f47-b836-724248d8f7e8'

// The example app with LicenseRail added by the CLI, in a temp folder.
const app = mkdtempSync(join(tmpdir(), 'lr-yt-'))
for (const f of readdirSync(join(root, 'example'))) writeFileSync(join(app, f), readFileSync(join(root, 'example', f)))
writeFileSync(join(app, 'key.pem'), pem)
execFileSync(process.execPath, [join(root, 'bin', 'licenserail-youtrack.mjs'), 'add', app, '--vendor', VENDOR, '--product', 'yt-app',
  '--key-id', 'kid-1', '--public-key', join(app, 'key.pem'), '--api-url', 'https://api.example'], { encoding: 'utf8' })

// Fake YouTrack scripting API.
const calls = []
const licenseInfo = { currentUserCount: 12, maxUserCount: 25, licenseUsername: 'acme', isCloud: true }
class Connection {
  constructor(url) { this.url = url; this.headers = {}; this.bearer = null }
  addHeader(name, value) { this.headers[name] = value; return this }
  bearerAuth(token) { this.bearer = token; return this }
  postAsync(uri, query, payload, callback) { calls.push({ base: this.url, uri, payload, callback, headers: this.headers, bearer: this.bearer }) }
}
const fakes = {
  '@jetbrains/youtrack-scripting-api/http': { Connection },
  '@jetbrains/youtrack-scripting-api/license': { licenseInfo },
}
const resolve = Module._resolveFilename
Module._resolveFilename = function (request, ...rest) { return fakes[request] ? request : resolve.call(this, request, ...rest) }
for (const [name, exports] of Object.entries(fakes)) Module._cache[name] = { id: name, filename: name, loaded: true, exports }

const requireApp = createRequire(join(app, 'manifest.json'))
const handler = requireApp('./licenserail-license.js').httpHandler
const report = requireApp('./report.js').httpHandler
const lr = requireApp('./licenserail.js')

const SECRET = { secretReference: true }   // scripts never see the key, only an opaque reference
const storage = {}
function ctx(extra = {}) {
  const response = { statusCode: 200, body: null, json(o) { this.body = o } }
  return {
    globalStorage: { extensionProperties: storage }, settings: { licenseKey: SECRET },
    currentUser: { hasPermission: (key) => key === 'ADMIN_UPDATE_APP' }, request: { json: () => ({ installationId: UUID }) },
    response, invoked: [], invokeAsync(name, delay, key) { this.invoked.push({ name, delay, key }) }, ...extra,
  }
}
const endpoint = (path, method) => handler.endpoints.find((e) => e.path === path && e.method === method)
const b64url = (b) => Buffer.from(b).toString('base64url')
function token(over = {}) {
  const now = Date.now()
  const payload = {
    licenseId: 'l', activationId: 'a', licenseKey: 'K', product: 'yt-app', customer: 'Çağrı Yazılım A.Ş.', kind: 'full', expiresAt: null,
    issuedAt: new Date(now).toISOString(), refreshAfter: new Date(now + 86400000).toISOString(),
    offlineUntil: new Date(now + 30 * 86400000).toISOString(), fingerprint: JSON.parse(calls.at(-1).payload).fingerprint, suspended: false,
    entitlements: ['advanced-reports'], ...over,
  }
  const body = b64url(JSON.stringify(payload))
  return `${body}.${b64url(sign('sha256', Buffer.from(body), { key: privateKey, dsaEncoding: 'ieee-p1363' }))}`
}
function deliver(code, body) {
  const call = calls.at(-1)
  const c = ctx({ response: { code, body: typeof body === 'string' ? body : JSON.stringify(body) } })
  handler.asyncFunctions[call.callback](c)
}

test('the CLI merged settings, storage, the License page and the minimum version', () => {
  const settings = JSON.parse(readFileSync(join(app, 'settings.json'), 'utf8'))
  assert.equal(settings.properties.licenseKey.format, 'secret')
  const ext = JSON.parse(readFileSync(join(app, 'entity-extensions.json'), 'utf8'))
  assert.ok(ext.entityTypeExtensions.find((e) => e.entityType === 'AppGlobalStorage').properties.licenserailToken)
  const manifest = JSON.parse(readFileSync(join(app, 'manifest.json'), 'utf8'))
  assert.equal(manifest.widgets.filter((w) => w.key === 'licenserail-license').length, 1)
  assert.equal(manifest.minYouTrackVersion, '2026.2')
  assert.ok(readFileSync(join(app, 'licenserail-config.js'), 'utf8').includes('BEGIN PUBLIC KEY'))
})

test('a feature is refused without a license', () => {
  const c = ctx()
  report.endpoints[0].handle(c)
  assert.equal(c.response.statusCode, 402)
  assert.equal(c.response.body.status, 'Missing')
})

test('activation sends the key as a secret header, the installation and the user count; the response stores the token', () => {
  const c = ctx()
  endpoint('activate', 'POST').handle(c)
  assert.equal(c.response.statusCode, 202)
  const call = calls.at(-1)
  assert.equal(call.base + call.uri, 'https://api.example/api/client/v2/activate')
  assert.equal(call.bearer, SECRET)
  const body = JSON.parse(call.payload)
  assert.equal(body.fingerprint.os, 'youtrack')
  assert.equal(body.hostUsers, 12)
  assert.equal(body.licenseKey, undefined)
  assert.ok(call.headers['LicenseRail-Installation'].startsWith('youtrack:'))
  assert.equal(c.response.body.pending, 'activate')

  deliver(200, { token: token() })
  const status = ctx()
  endpoint('status', 'GET').handle(status)
  assert.equal(status.response.body.status, 'Valid')
  assert.equal(status.response.body.pending, null)
  assert.equal(JSON.stringify(status.response.body).includes('licenseKey'), false)

  const feature = ctx()
  report.endpoints[0].handle(feature)
  assert.deepEqual(feature.response.body, { message: 'Licensed feature', trial: false, advanced: true })
})

test('a due refresh is scheduled once from any handler and keeps the license on network errors', () => {
  deliver(200, { token: token({ refreshAfter: new Date(Date.now() - 1000).toISOString() }) })
  const c = ctx()
  report.endpoints[0].handle(c)
  assert.deepEqual(c.invoked, [{ name: 'licenserailRefresh', delay: 0, key: 'licenserail-refresh' }])
  report.asyncFunctions.licenserailRefresh(ctx())
  assert.equal(calls.at(-1).uri, '/api/client/v2/refresh')
  assert.equal(calls.at(-1).bearer, null)
  deliver(0, '')
  const after = ctx()
  endpoint('status', 'GET').handle(after)
  assert.equal(after.response.body.valid, true)
  assert.equal(after.response.body.lastError.code, 'network_error')
})

test('a revoked license is removed; a trial uses the key id and no key', () => {
  report.asyncFunctions.licenserailRefresh(ctx())
  deliver(403, { code: 'license_revoked', message: 'The license has been revoked.' })
  const s = ctx()
  endpoint('status', 'GET').handle(s)
  assert.equal(s.response.body.status, 'Missing')

  endpoint('trial', 'POST').handle(ctx({ request: { json: () => ({ installationId: UUID, baseUrls: ['https://acme.youtrack.cloud', 'javascript:x', 7] }) } }))
  const call = calls.at(-1)
  assert.equal(call.uri, '/api/client/v2/trial')
  assert.equal(call.bearer, null)
  const sent = JSON.parse(call.payload)
  assert.equal(sent.keyId, 'kid-1')
  // The server checks this instance at the address the admin page was opened from.
  assert.deepEqual(sent.host, { instanceId: UUID, baseUrls: ['https://acme.youtrack.cloud'] })
  // Started later from the app's own code (no address given): the address remembered from the License page is used.
  lr.startTrial(ctx())
  assert.deepEqual(JSON.parse(calls.at(-1).payload).host, { instanceId: UUID, baseUrls: ['https://acme.youtrack.cloud'] })
  deliver(200, { token: token({ kind: 'trial', trial: true, licenseKey: '', expiresAt: new Date(Date.now() + 14 * 86400000).toISOString() }) })
  const feature = ctx()
  report.endpoints[0].handle(feature)
  assert.equal(feature.response.body.trial, true)
})

test('only administrators reach the license endpoints, and a bad installation id is refused', () => {
  const c = ctx({ currentUser: { hasPermission: () => false } })
  endpoint('status', 'GET').handle(c)
  assert.equal(c.response.statusCode, 403)
  const bad = ctx({ request: { json: () => ({ installationId: '../../x' }) } })
  endpoint('activate', 'POST').handle(bad)
  assert.equal(bad.response.statusCode, 400)
})

test('the bundled core loads without web or Node globals (YouTrack backend)', () => {
  const script = `
    for (const g of ['TextEncoder','TextDecoder','atob','btoa','Buffer','crypto','fetch']) Object.defineProperty(globalThis, g, { value: undefined, configurable: true });
    const core = require(${JSON.stringify(join(app, 'licenserail-core.js'))});
    const fp = core.installationFingerprint('${VENDOR}', 'yt-app', 'youtrack', '${UUID}');
    process.stdout.write(fp.os + ':' + fp.machineId.length);
  `
  assert.equal(execFileSync(process.execPath, ['-e', script], { encoding: 'utf8' }), 'youtrack:64')
})
