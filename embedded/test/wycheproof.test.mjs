import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { verifyP256 } from '../dist/esm/index.js'

// Project Wycheproof, ecdsa_secp256r1_sha256_p1363_test.json (Apache License 2.0, https://github.com/C2SP/wycheproof).
const suite = JSON.parse(readFileSync(new URL('./fixtures/ecdsa_secp256r1_sha256_p1363_test.json', import.meta.url), 'utf8'))
const bytes = (h) => (h.match(/../g) ?? []).map((b) => parseInt(b, 16))

test(`Wycheproof ECDSA P-256 SHA-256 P1363 (${suite.numberOfTests} cases)`, () => {
  let count = 0
  for (const group of suite.testGroups) {
    for (const t of group.tests) {
      const ok = verifyP256(group.publicKeyPem, bytes(t.msg), bytes(t.sig))
      // "acceptable" cases have no required outcome; valid must pass and invalid must fail.
      if (t.result === 'valid') assert.equal(ok, true, `#${t.tcId} ${t.comment}`)
      if (t.result === 'invalid') assert.equal(ok, false, `#${t.tcId} ${t.comment}`)
      count++
    }
  }
  assert.equal(count, suite.numberOfTests)
})
