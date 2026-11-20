import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { evaluate, fingerprintMatches, hashComponent, verifyToken } from '../dist/index.js'

const load = (name) => JSON.parse(readFileSync(new URL(`../../test-vectors/${name}`, import.meta.url), 'utf8'))

test('tokens', () => {
  const v = load('tokens.json')
  for (const c of v.cases) {
    const payload = verifyToken(c.token, v.publicKeyPem)
    assert.equal(payload !== null, c.expect.signatureValid, c.name)
    if (c.expect.payload) for (const [k, val] of Object.entries(c.expect.payload)) assert.deepEqual(payload[k], val, `${c.name}: ${k}`)
  }
})

test('fingerprint hashing', () => {
  for (const c of load('fingerprint.json').cases) assert.equal(hashComponent(c.product, c.part, c.raw), c.hash, `${c.part}:${c.raw}`)
})

test('matching', () => {
  for (const c of load('match.json').cases) assert.equal(fingerprintMatches(c.registered, c.presented), c.matches, c.name)
})

test('evaluation', () => {
  const v = load('evaluate.json')
  for (const c of v.cases) {
    const status = evaluate(verifyToken(c.token, v.publicKeyPem), c.product, c.machine, new Date(c.now), c.lastSeen ? new Date(c.lastSeen) : null)
    assert.equal(status, c.status, c.name)
  }
})
