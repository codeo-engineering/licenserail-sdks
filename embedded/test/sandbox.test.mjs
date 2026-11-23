import { strict as assert } from 'node:assert'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

// The CommonJS build must work in a host without TextEncoder, TextDecoder, atob, btoa, Buffer, crypto or fetch
// (what a YouTrack app backend offers), loaded with plain require().
test('CommonJS build verifies tokens with web and Node globals removed', () => {
  const dir = fileURLToPath(new URL('..', import.meta.url))
  const script = `
    const fs = require('fs');
    const vectors = JSON.parse(fs.readFileSync('../test-vectors/installation.json', 'utf8'));
    const tokens = JSON.parse(fs.readFileSync('../test-vectors/tokens.json', 'utf8'));
    for (const g of ['TextEncoder', 'TextDecoder', 'atob', 'btoa', 'Buffer', 'crypto', 'fetch']) {
      Object.defineProperty(globalThis, g, { value: undefined, configurable: true, writable: true });
    }
    const lr = require('./dist/cjs/index');
    const out = vectors.tokens.map(t => { const p = lr.verifyToken(t.token, vectors.publicKeyPem); return p && (p.customer || p.kind); });
    out.push(lr.verifyToken(tokens.cases[0].token, tokens.publicKeyPem) !== null);
    out.push(lr.verifyToken(tokens.cases[4].token, tokens.publicKeyPem) === null);
    process.stdout.write(JSON.stringify(out));
  `
  const result = JSON.parse(execFileSync(process.execPath, ['-e', script], { cwd: dir, encoding: 'utf8' }))
  assert.deepEqual(result, ['Çağrı Yazılım A.Ş.', 'trial', true, true])
})
