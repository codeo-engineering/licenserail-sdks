import { strict as assert } from 'node:assert'
import { generateKeyPairSync, sign } from 'node:crypto'
import { test } from 'node:test'
import { activateRequest, createLicenseClient, installationFingerprint, readResponse, refreshRequest, trialRequest, INSTALLATION_HEADER } from '../dist/esm/index.js'

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const pem = publicKey.export({ type: 'spki', format: 'pem' })
const b64url = (b) => Buffer.from(b).toString('base64url')
function token(payload) {
  const body = b64url(JSON.stringify(payload))
  return `${body}.${b64url(sign('sha256', Buffer.from(body), { key: privateKey, dsaEncoding: 'ieee-p1363' }))}`
}

const fp = installationFingerprint('ten_x', 'yt-app', 'youtrack', 'uuid-1')
const t0 = new Date('2026-11-24T10:00:00Z')
const base = (over = {}) => ({
  licenseId: 'l', activationId: 'a', licenseKey: 'K', product: 'yt-app', customer: 'Acme', kind: 'full', expiresAt: null,
  issuedAt: t0.toISOString(), refreshAfter: new Date(t0.getTime() + 86400000).toISOString(),
  offlineUntil: new Date(t0.getTime() + 30 * 86400000).toISOString(), fingerprint: fp, suspended: false, ...over,
})

function memoryStorage() {
  const m = new Map()
  return { get: (k) => m.get(k) ?? null, set: (k, v) => void m.set(k, v), remove: (k) => void m.delete(k), m }
}

test('requests carry the key in the header, the installation header and only the fields given', () => {
  const r = activateRequest({ apiUrl: 'https://api.example/', product: 'yt-app', fingerprint: fp, licenseKey: 'KEY', hostUsers: 12 })
  assert.equal(r.url, 'https://api.example/api/client/v2/activate')
  assert.equal(r.headers.Authorization, 'Bearer KEY')
  assert.equal(r.headers[INSTALLATION_HEADER], `youtrack:${fp.machineId}`)
  assert.deepEqual(JSON.parse(r.body), { product: 'yt-app', fingerprint: fp, hostUsers: 12 })
  const inBody = activateRequest({ apiUrl: 'https://api.example', product: 'yt-app', fingerprint: fp, licenseKey: 'KEY', keyInHeader: false })
  assert.equal(inBody.headers.Authorization, undefined)
  assert.equal(JSON.parse(inBody.body).licenseKey, 'KEY')
  assert.equal(JSON.parse(refreshRequest({ apiUrl: 'x', product: 'p', fingerprint: fp, token: 't' }).body).appVersion, null)
  assert.equal(trialRequest({ apiUrl: 'x', product: 'p', fingerprint: fp, keyId: 'kid' }).url, 'x/api/client/v2/trial')
})

test('responses: tokens, revoking errors and errors to retry later', () => {
  assert.deepEqual(readResponse(200, '{"token":"abc"}'), { ok: true, token: 'abc' })
  assert.deepEqual(readResponse(204, ''), { ok: true, token: null })
  const revoked = readResponse(403, '{"code":"license_revoked","message":"Revoked."}')
  assert.equal(revoked.revokesLocalLicense, true)
  assert.equal(revoked.retryLater, false)
  const broke = readResponse(402, '{"code":"insufficient_balance","message":"x"}')
  assert.equal(broke.revokesLocalLicense, false)
  assert.equal(broke.retryLater, true)
  assert.equal(readResponse(0, '').code, 'network_error')
  assert.equal(readResponse(502, '<html>').retryLater, true)
})

test('client: activate, check offline, refresh when due, keep the token on network errors, drop it when revoked', async () => {
  let now = t0
  const storage = memoryStorage()
  const replies = []
  const sent = []
  const client = createLicenseClient({
    apiUrl: 'https://api.example', publicKeyPem: pem, product: 'yt-app', fingerprint: fp, storage, now: () => now, hostUsers: () => 7,
    transport: async (r) => { sent.push(r); return replies.shift() },
  })
  assert.equal((await client.state()).status, 'Missing')

  replies.push({ status: 200, body: JSON.stringify({ token: token(base({ maxHostUsers: 5, hostUserPolicy: 'report', entitlements: ['sla'] })) }) })
  const activated = await client.activate('KEY')
  assert.equal(activated.ok, true)
  assert.equal(activated.state.status, 'Valid')
  assert.equal(activated.state.summary.hostUsersOverLimit, true)   // 7 host users, limit 5
  assert.deepEqual(activated.state.summary.entitlements, ['sla'])
  assert.equal(JSON.parse(sent[0].body).hostUsers, 7)

  assert.equal((await client.refresh()).ok, true)                  // not due yet: no request
  assert.equal(sent.length, 1)
  now = new Date(t0.getTime() + 2 * 86400000)
  replies.push({ status: 0, body: '' })
  const offline = await client.refresh()
  assert.equal(offline.ok, false)
  assert.equal(offline.code, 'network_error')
  assert.equal(offline.state.status, 'Valid')                      // still licensed offline

  replies.push({ status: 403, body: '{"code":"license_revoked","message":"Revoked."}' })
  const revoked = await client.refresh()
  assert.equal(revoked.state.status, 'Missing')
})

test('client: a trial is never refreshed and a token that does not verify is refused', async () => {
  const storage = memoryStorage()
  const replies = [
    { status: 200, body: JSON.stringify({ token: token(base({ kind: 'trial', trial: true, licenseKey: '', expiresAt: new Date(t0.getTime() + 14 * 86400000).toISOString() })) }) },
    { status: 200, body: '{"token":"bad.token"}' },
  ]
  const client = createLicenseClient({ apiUrl: 'x', publicKeyPem: pem, product: 'yt-app', fingerprint: fp, storage, now: () => new Date(t0.getTime() + 5 * 86400000), transport: async () => replies.shift() })
  const trial = await client.startTrial('kid')
  assert.equal(trial.state.summary.isTrial, true)
  assert.equal((await client.refresh()).ok, true)                  // trials are not refreshed
  assert.equal(replies.length, 1)
  const bad = await client.activate('KEY')
  assert.equal(bad.ok, false)
  assert.equal(bad.code, 'invalid_token')
})
