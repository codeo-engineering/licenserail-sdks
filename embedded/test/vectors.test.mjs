import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { evaluate, fingerprintMatches, hashComponent, installationFingerprint, utf8Decode, utf8Encode, verifyToken, verifyTokenAsync } from '../dist/esm/index.js'

const load = (name) => JSON.parse(readFileSync(new URL(`../../test-vectors/${name}`, import.meta.url), 'utf8'))

function checkPayload(name, payload, expected) {
  for (const [k, val] of Object.entries(expected)) assert.deepEqual(payload[k], val, `${name}: ${k}`)
}

test('tokens (bundled verifier and WebCrypto agree)', async () => {
  const v = load('tokens.json')
  for (const c of v.cases) {
    const sync = verifyToken(c.token, v.publicKeyPem)
    const viaSubtle = await verifyTokenAsync(c.token, v.publicKeyPem)
    assert.equal(sync !== null, c.expect.signatureValid, c.name)
    assert.equal(viaSubtle !== null, c.expect.signatureValid, `${c.name} (subtle)`)
    if (c.expect.payload) checkPayload(c.name, sync, c.expect.payload)
  }
})

test('fingerprint hashing', () => {
  for (const c of load('fingerprint.json').cases) assert.equal(hashComponent(c.vendor, c.product, c.part, c.raw), c.hash, `${c.vendor}:${c.part}:${c.raw}`)
})

test('device matching', () => {
  for (const c of load('match.json').cases) assert.equal(fingerprintMatches(c.registered, c.presented), c.matches, c.name)
})

test('evaluation', () => {
  const v = load('evaluate.json')
  for (const c of v.cases) {
    const status = evaluate(verifyToken(c.token, v.publicKeyPem), c.product, c.machine, new Date(c.now), c.lastSeen ? new Date(c.lastSeen) : null)
    assert.equal(status, c.status, c.name)
  }
})

test('installations, trials, host user limits and non-ASCII payloads', () => {
  const v = load('installation.json')
  const h = v.installationHash
  assert.equal(hashComponent(h.vendor, h.product, h.part, h.raw), h.hash)
  assert.equal(installationFingerprint(h.vendor, h.product, 'YouTrack', h.raw).machineId, h.hash)
  for (const c of v.tokens) {
    const payload = verifyToken(c.token, v.publicKeyPem)
    assert.equal(payload !== null, c.expect.signatureValid, c.name)
    checkPayload(c.name, payload, c.expect.payload)
  }
  for (const c of v.matches) assert.equal(fingerprintMatches(c.registered, c.presented), c.matches, c.name)
})

test('UTF-8 round trip, including astral characters and invalid input', () => {
  for (const s of ['', 'ascii', 'Çağrı Yazılım A.Ş.', 'é€ 日本 😀', '\u0000\u007f\u0080߿ࠀ￿']) assert.equal(utf8Decode(utf8Encode(s)), s)
  assert.deepEqual(utf8Encode('😀'), [0xf0, 0x9f, 0x98, 0x80])
  assert.equal(utf8Decode([0xff, 0x41, 0xc0, 0xaf]), '�A��')
})
