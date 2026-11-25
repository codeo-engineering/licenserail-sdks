// End-to-end tests: every SDK, installed from its built package into an empty project, against a real API.
//
//   node e2e/run.mjs <sdk...>        (env: E2E_API, E2E_MAIL = the API's mail outbox folder, E2E_WORK = work folder)
//
// Each SDK has a small driver (drivers/<sdk>) that runs one operation per process and prints one JSON line, so every step
// also crosses an app restart. The scenarios and the expected results are the same for every SDK.
import { spawn } from 'node:child_process'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { sdks } from './sdks.mjs'

const API = process.env.E2E_API ?? 'http://127.0.0.1:5090'
const MAIL = process.env.E2E_MAIL
const OFFLINE = 'http://127.0.0.1:9'   // nothing listens here
if (/licenserail\.com/i.test(API)) throw new Error('The end-to-end tests must not run against production.')
if (!MAIL) throw new Error('Set E2E_MAIL to the API\'s Mail:OutboxDirectory.')
const work = process.env.E2E_WORK ? resolve(process.env.E2E_WORK) : mkdtempSync(join(tmpdir(), 'lr-e2e-'))
mkdirSync(work, { recursive: true })
const wanted = process.argv.slice(2)
for (const name of wanted) if (!sdks[name]) throw new Error(`Unknown SDK ${name}; known: ${Object.keys(sdks).join(', ')}`)
if (!wanted.length) throw new Error(`Name at least one SDK: ${Object.keys(sdks).join(', ')}`)

// ---------------------------------------------------------------- the vendor's side (management API, Test environment)

let apiKey = null
async function api(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`)
  return text ? JSON.parse(text) : null
}

async function signUp() {
  const email = `e2e-${randomBytes(6).toString('hex')}@vendor-${randomBytes(4).toString('hex')}.example`
  const { loginId } = await api('POST', '/api/auth/login-code', { email, purpose: 'cli' })
  const mail = readdirSync(MAIL).filter((f) => f.endsWith('.json')).sort().reverse()
    .map((f) => JSON.parse(readFileSync(join(MAIL, f), 'utf8'))).find((m) => m.to === email)
  const code = mail?.link.match(/\b\d{6}\b/)?.[0]
  if (!code) throw new Error('No sign-in code in the mail outbox.')
  const account = await api('POST', '/api/auth/login-code/verify', { loginId, code })
  return { vendor: account.tenantId, key: account.testApiKey }
}

async function createVendor() {
  apiKey = null
  const other = await signUp()
  apiKey = other.key
  const otherPem = (await api('GET', '/api/v2/environment/public-key')).publicKeyPem
  apiKey = null
  const { vendor, key } = await signUp()
  apiKey = key
  const pem = (await api('GET', '/api/v2/environment/public-key')).publicKeyPem
  const product = await api('POST', '/api/v2/products', { code: 'e2e-app', name: 'E2E App' })
  const otherProduct = await api('POST', '/api/v2/products', { code: 'e2e-other', name: 'E2E Other' })
  for (const code of ['export', 'reports']) await api('POST', `/api/v2/products/${product.id}/features`, { code, name: code })
  const customer = await api('POST', '/api/v2/customers', { name: 'Müşteri Ğüşİö A.Ş.' })
  const license = async (extra = {}, of = product) =>
    (await api('POST', '/api/v2/licenses', { productId: of.id, customerId: customer.id, features: of === product ? ['export'] : undefined, ...extra })).data[0]
  return { vendor, pem, otherPem, product, otherProduct, license }
}

const activations = async (license) => (await api('GET', `/api/v2/licenses/${license.id}/activations`)).data.filter((a) => a.active !== false && !a.deactivatedAt)

// ---------------------------------------------------------------- a server that misbehaves

function badServer() {
  const server = createServer((req, res) => {
    req.resume()
    const kind = req.url.split('/')[1]
    if (kind === 'hang') return
    if (kind === 'reset') return void req.socket.destroy()
    if (kind === 'garbage') return void req.socket.end('this is not HTTP\r\n\r\n')
    if (kind === 'truncated') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 5000 })
      return void res.write('{"token":"', () => req.socket.destroy())
    }
    if (kind === 'redirect') {
      res.writeHead(302, { Location: '/html200' })
      return void res.end()
    }
    const [status, type, body] = {
      html502: [502, 'text/html', '<html><body>Bad gateway</body></html>'],
      html200: [200, 'text/html', '<html><body>Sign in to the hotel Wi-Fi</body></html>'],
      empty200: [200, 'application/json', ''],
      empty500: [500, 'application/json', ''],
      json500: [500, 'application/json', '{"code":"internal_error","message":"Something went wrong."}'],
      notoken: [200, 'application/json', '{}'],
      forged: [200, 'application/json', '{"token":"eyJhIjoxfQ.AAAA"}'],
      binary: [200, 'application/json', Buffer.from([0xff, 0xfe, 0x80, 0x00, 0xc3])],
      nulls: [403, 'application/json', '{"code":null,"message":null}'],
      array: [200, 'application/json', '[]'],
    }[kind] ?? [404, 'text/plain', 'not found']
    res.writeHead(status, { 'Content-Type': type })
    res.end(body)
  })
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok({ url: `http://127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections?.(); server.close() } })))
}

// ---------------------------------------------------------------- the app's side (the SDK's driver)

function exec(cmd, env, timeoutMs) {
  return new Promise((done) => {
    const p = spawn(cmd[0], cmd.slice(1), { env, windowsHide: true })
    let out = '', err = '', late = false
    const timer = setTimeout(() => { late = true; p.kill('SIGKILL') }, timeoutMs)
    p.stdout.on('data', (d) => { out += d })
    p.stderr.on('data', (d) => { err += d })
    p.on('error', (e) => { err += e })
    p.on('close', (code) => { clearTimeout(timer); done({ code, out, err, late }) })
  })
}

const hex = (s) => createHash('sha256').update(s).digest('hex').toUpperCase()
/** A fixed device (instead of this computer's own fingerprint): four components and the OS. */
const device = (name) => [hex(name + 'm'), hex(name + 'd'), hex(name + 'h'), hex(name + 'b')].map((x) => x.slice(0, 32)).join(',')

class App {
  constructor(sdk, cmd, v, over = {}) {
    Object.assign(this, { sdk, cmd, v })
    this.dir = over.dir ?? mkdtempSync(join(work, 'depo ğüş '))   // spaces and non-ASCII on purpose
    this.url = over.url ?? API
    this.device = over.device ?? ''
    this.product = over.product ?? 'e2e-app'
    this.pem = over.pem ?? v.pem
    this.keyFile = join(this.dir, 'key.pem')
    writeFileSync(this.keyFile, this.pem)
  }

  with(over) { return new App(this.sdk, this.cmd, this.v, { dir: this.dir, url: this.url, device: this.device, product: this.product, pem: this.pem, ...over }) }
  file(name) { return join(this.dir, name) }
  token() { return existsSync(this.file('license.lic')) ? readFileSync(this.file('license.lic'), 'utf8').trim() : null }
  payload() { return JSON.parse(Buffer.from(this.token().split('.')[0], 'base64url').toString('utf8')) }

  async run(op, key) {
    writeFileSync(this.keyFile, this.pem)
    const env = {
      ...process.env, LR_URL: this.url, LR_VENDOR: this.v.vendor, LR_PRODUCT: this.product, LR_PUBLIC_KEY_FILE: this.keyFile,
      LR_STORAGE: this.dir, LR_DEVICE: this.device, LR_TIMEOUT: '3',
    }
    const r = await exec([...this.cmd, op, ...(key === undefined ? [] : [key])], env, 40_000)
    const line = r.out.trim().split(/\r?\n/).reverse().find((l) => l.startsWith('{'))
    if (r.late) throw new Error(`${op}: no answer within 40 s`)
    if (r.code !== 0 || !line) throw new Error(`${op}: crashed (exit ${r.code}) ${(r.err || r.out).trim().slice(-600)}`)
    return JSON.parse(line)
  }

  activate(key) { return this.run('activate', key) }
  check() { return this.run('check') }
  refresh() { return this.run('refresh') }
  deactivate() { return this.run('deactivate') }
}

// ---------------------------------------------------------------- scenarios

class Failure extends Error {}
function same(actual, expected, what) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected)
  if (a !== e) throw new Failure(`${what}: expected ${e}, got ${a}`)
}
const ok = (r, what) => { if (!r.success) throw new Failure(`${what}: expected success, got ${JSON.stringify(r)}`) }
const refused = (r, codes, what) => {
  if (r.success || ![].concat(codes).includes(r.errorCode)) throw new Failure(`${what}: expected ${[].concat(codes).join(' or ')}, got ${JSON.stringify(r)}`)
}
const is = async (app, status, what) => same((await app.check()).status, status, what)
const offline = (app) => app.with({ url: OFFLINE })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const scenarios = {
  'no license yet': async ({ app }) => {
    same((await app().check()).status, 'Missing', 'status')
    ok(await app().deactivate(), 'deactivate without a license')
  },

  'wrong keys are refused and leave nothing behind': async ({ app, v }) => {
    const a = app()
    refused(await a.activate('TEST-AAAAA-AAAAA-AAAAA-AAAAA'), 'license_not_found', 'unknown key')
    refused(await a.activate('   '), 'bad_request', 'empty key')
    refused(await a.activate((await v.license({}, v.otherProduct)).key), 'wrong_product', 'key of another product')
    same(a.token(), null, 'license file')
    await is(a, 'Missing', 'status')
  },

  'activation on this computer, after a restart and offline': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    const r = await a.activate(l.key)
    ok(r, 'activate')
    const c = await a.check()
    same([c.status, c.features, c.test], ['Valid', ['export'], true], 'state')
    same((await activations(l)).length, 1, 'seats used')
    same(a.payload().customer, 'Müşteri Ğüşİö A.Ş.', 'customer name')
    await is(offline(a), 'Valid', 'offline')
    ok(await a.activate(l.key), 'activate again')
    rmSync(a.file('license.lic'))
    ok(await a.activate(l.key), 'activate after the license file was deleted')
    same((await activations(l)).length, 1, 'seats used after activating again')
  },

  'a key typed in lowercase with spaces around it': async ({ app, v }) => {
    const l = await v.license()
    ok(await app().activate(`  ${l.key.toLowerCase()} `), 'activate')
  },

  'no connection: nothing is lost': async ({ app, v, sdk }) => {
    const network = sdk.networkCode ?? 'network'
    const l = await v.license()
    const fresh = offline(app())
    refused(await fresh.activate(l.key), network, 'activate')
    const a = app()
    ok(await a.activate(l.key), 'activate')
    await offline(a).refresh()
    refused(await offline(a).deactivate(), network, 'deactivate')
    await is(a, 'Valid', 'status')
    same((await activations(l)).length, 1, 'seats used')
  },

  'a misbehaving server or proxy: no crash, the license stays': async ({ app, v, bad }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    for (const kind of ['html502', 'html200', 'empty200', 'empty500', 'json500', 'notoken', 'forged', 'nulls', 'array', 'binary', 'redirect', 'reset', 'garbage', 'truncated', 'hang']) {
      const broken = a.with({ url: `${bad.url}/${kind}` })
      await broken.refresh()
      await is(offline(a), 'Valid', `${kind}: status after refresh`)
      const d = await app({ url: `${bad.url}/${kind}` }).activate(l.key)
      if (d.success) throw new Failure(`${kind}: activation reported success`)
    }
  },

  'deactivation against a broken server keeps the license': async ({ app, v, bad }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    for (const kind of ['html502', 'html200', 'redirect', 'empty500', 'json500', 'nulls', 'reset', 'garbage', 'truncated', 'hang']) {
      const r = await a.with({ url: `${bad.url}/${kind}` }).deactivate()
      if (r.success) throw new Failure(`${kind}: deactivation reported success`)
      await is(offline(a), 'Valid', `${kind}: status`)
    }
    same((await activations(l)).length, 1, 'seats used')
  },

  'seat limits': async ({ app, v }) => {
    const one = await v.license()
    const a = app({ device: device('seat-a') }), b = app({ device: device('seat-b') }), c = app({ device: device('seat-c') })
    ok(await a.activate(one.key), 'first device')
    refused(await b.activate(one.key), 'license_in_use', 'second device on one seat')
    same(b.token(), null, 'license file of the refused device')
    const two = await v.license({ maxActivations: 2 })
    ok(await b.activate(two.key), 'two seats: first device')
    ok(await c.activate(two.key), 'two seats: second device')
    refused(await app({ device: device('seat-d') }).activate(two.key), 'seat_limit_reached', 'two seats: third device')
  },

  'a device that cannot be identified uses no seat': async ({ app, v }) => {
    const l = await v.license()
    const weak = ['none', 'none', device('weak').split(',')[2], 'none']   // e.g. a container without /etc/machine-id
    const a = app({ device: weak.join(',') })
    refused(await a.activate(l.key), 'device_not_identified', 'activate')
    same(a.token(), null, 'license file')
    // The server refuses it too, for apps with an older SDK.
    const res = await fetch(`${API}/api/client/v2/activate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        licenseKey: l.key, product: 'e2e-app', machineName: 'container', appVersion: null,
        fingerprint: { machineId: weak[0], diskId: weak[1], hostName: weak[2], boardId: weak[3], os: 'linux' },
      }),
    })
    same([res.status, (await res.json()).code], [400, 'device_not_identified'], 'server')
    same((await activations(l)).length, 0, 'seats used')
  },

  'deactivation frees the seat': async ({ app, v }) => {
    const l = await v.license()
    const a = app({ device: device('free-a') }), b = app({ device: device('free-b') })
    ok(await a.activate(l.key), 'activate')
    ok(await a.deactivate(), 'deactivate')
    same(a.token(), null, 'license file')
    await is(a, 'Missing', 'status')
    same((await activations(l)).length, 0, 'seats used')
    ok(await b.activate(l.key), 'another device takes the seat')
  },

  'refresh brings changes from the dashboard': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    const before = a.token()
    await api('PATCH', `/api/v2/licenses/${l.id}`, { features: ['export', 'reports'], metadata: { plan: 'gold', seats: 5 } })
    await a.refresh()
    if (a.token() === before) throw new Failure('refresh did not store a new license')
    const c = await a.check()
    same([c.status, [...c.features].sort()], ['Valid', ['export', 'reports']], 'state')
  },

  'suspend and resume': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    await api('POST', `/api/v2/licenses/${l.id}/suspend`)
    await a.refresh()
    await is(a, 'Suspended', 'status')
    await is(offline(a), 'Suspended', 'status offline')
    refused(await app({ device: device('susp') }).activate(l.key), 'license_suspended', 'activate while suspended')
    await api('POST', `/api/v2/licenses/${l.id}/resume`)
    await is(a, 'Valid', 'status after resuming')
  },

  'revoked licenses are removed': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    await api('POST', `/api/v2/licenses/${l.id}/revoke`)
    await is(offline(a), 'Valid', 'offline, before the app hears about it')
    await a.refresh()
    await is(a, 'Missing', 'status')
    same(a.token(), null, 'license file')
    refused(await a.activate(l.key), 'license_revoked', 'activate')
  },

  'a device removed in the dashboard loses its license': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    await api('POST', `/api/v2/activations/${(await activations(l))[0].id}/deactivate`)
    await a.refresh()
    await is(a, 'Missing', 'status')
  },

  'expiry offline, and an extension clears it': async ({ app, v }) => {
    const l = await v.license({ expiresAt: new Date(Date.now() + 12_000).toISOString() })
    const a = app()
    ok(await a.activate(l.key), 'activate')
    await sleep(Math.max(0, Date.parse(a.payload().expiresAt) - Date.now()) + 1500)
    await is(offline(a), 'Expired', 'offline after the end')
    refused(await app({ device: device('exp') }).activate(l.key), 'license_expired', 'activate after the end')
    await api('PATCH', `/api/v2/licenses/${l.id}`, { expiresAt: new Date(Date.now() + 3_600_000).toISOString() })
    await is(a, 'Valid', 'online after the extension')
  },

  'an expired license is removed when the server says so': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    await api('PATCH', `/api/v2/licenses/${l.id}`, { expiresAt: new Date(Date.now() - 1000).toISOString() })
    await a.refresh()
    await is(a, 'Missing', 'status')
  },

  'a changed license file is rejected': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    const [body, signature] = a.token().split('.')
    const p = { ...a.payload(), entitlements: ['export', 'reports'] }
    writeFileSync(a.file('license.lic'), `${Buffer.from(JSON.stringify(p)).toString('base64url')}.${signature}`)
    await is(offline(a), 'InvalidSignature', 'changed content')
    const flipped = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1)
    for (const junk of [`${body}.${flipped}`, body, 'garbage', '.', 'a.b', `${body}.`, '{"json":true}', '\u0000\u0001']) {
      writeFileSync(a.file('license.lic'), junk)
      await is(offline(a), 'InvalidSignature', `junk ${JSON.stringify(junk.slice(0, 12))}`)
    }
    ok(await a.activate(l.key), 'activate again')
    await is(a, 'Valid', 'status')
  },

  'a license copied to another device is rejected': async ({ app, v }) => {
    const l = await v.license()
    const a = app({ device: device('copy-a') })
    ok(await a.activate(l.key), 'activate')
    const b = app({ device: device('copy-b') })
    for (const f of ['license.lic', 'license.seen']) writeFileSync(b.file(f), readFileSync(a.file(f)))
    await is(b, 'WrongMachine', 'copy')
    await b.deactivate()
    same((await activations(l)).length, 1, 'the copy must not free the seat')
    await is(a, 'Valid', 'original')
  },

  'a token signed by another vendor is not accepted': async ({ app, v }) => {
    const l = await v.license()
    const a = app({ pem: v.otherPem })
    refused(await a.activate(l.key), 'invalid_token', 'activate')
    same(a.token(), null, 'license file')
    const b = a.with({ pem: v.pem })
    ok(await b.activate(l.key), 'activate with the right key')
    await is(offline(b).with({ pem: v.otherPem }), 'InvalidSignature', 'file checked with another key')
  },

  'deleting the run history needs the server once': async ({ app, v }) => {
    const l = await v.license()
    const a = app()
    ok(await a.activate(l.key), 'activate')
    rmSync(a.file('license.seen'))
    await is(offline(a), 'Unverified', 'offline')
    await is(a, 'Valid', 'online')
    await is(offline(a), 'Valid', 'offline afterwards')
  },

  'a clock turned back is noticed': async ({ app, v, sdk }) => {
    const l = await v.license()
    const dev = device('clock')
    const a = app({ device: dev })
    ok(await a.activate(l.key), 'activate')
    // The history says the app already ran three hours from now.
    const ms = String(Date.now() + 3 * 3_600_000)
    const [machine, , , board] = dev.split(',')
    const key = createHash('sha256').update(`${v.vendor}:run-history:e2e-app:${machine}:${board}`).digest()
    const mac = createHmac('sha256', key).update(ms).digest('hex').toUpperCase().slice(0, 32)
    writeFileSync(a.file('license.seen'), sdk.plainHistory ? ms : `${ms}.${mac}`)
    await is(offline(a), 'ClockTampered', 'offline')
    await is(a, 'Valid', 'online')
  },

  'floating licenses: check out, heartbeat, release': async ({ app, v }) => {
    const l = await v.license({ isFloating: true, leaseMinutes: 5 })
    const a = app({ device: device('float-a') }), b = app({ device: device('float-b') })
    ok(await a.activate(l.key), 'check out')
    await is(a, 'Valid', 'status')
    refused(await b.activate(l.key), ['license_in_use', 'seat_limit_reached'], 'second device')
    const before = a.token()
    await sleep(1100)
    await a.refresh()
    if (a.token() === before) throw new Failure('the heartbeat did not store a new lease')
    ok(await a.deactivate(), 'release')
    ok(await b.activate(l.key), 'second device after the release')
  },
}

// The CLI does the vendor's side, so it has its own scenarios.
const cliScenarios = {
  'sign-in by email code': async ({ cli }) => {
    const email = `cli-${randomBytes(6).toString('hex')}@vendor-${randomBytes(4).toString('hex')}.example`
    const p = cli.start(['login', '--email', email, '--json'])
    let code
    for (let i = 0; i < 50 && !code; i++) {
      await sleep(200)
      code = readdirSync(MAIL).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(MAIL, f), 'utf8')))
        .find((m) => m.to === email)?.link.match(/\b\d{6}\b/)?.[0]
    }
    if (!code) throw new Failure('no code was sent')
    p.child.stdin.end(code + '\n')
    const r = await p.done
    same(r.code, 0, `exit code (${r.err})`)
    await cli.json(['whoami'])
  },
  'a wrong API key fails': async ({ cli }) => {
    const r = await cli.run(['products', 'list', '--json'], { LICENSERAIL_API_KEY: 'lr_test_wrong' })
    if (r.code === 0) throw new Failure('exit code 0')
  },
  'product to activation': async ({ cli, key, v }) => {
    const env = { LICENSERAIL_API_KEY: key }
    same((await cli.run(['public-key', '--pem'], env)).out.trim(), v.pem.trim(), 'public key')
    const product = await cli.json(['products', 'create', '--code', 'cli-app', '--name', 'CLI App'], env)
    await cli.json(['features', 'create', '--product', product.id, '--code', 'export'], env)
    const customer = await cli.json(['customers', 'create', '--name', 'Ğüşİö A.Ş.'], env)
    const made = await cli.json(['licenses', 'create', '--product', product.id, '--customer', customer.id, '--seats', '3', '--feature', 'export', '--meta', 'plan=gold'], env)
    const l = made.data[0]
    same([l.maxActivations, l.features, l.metadata], [3, ['export'], { plan: 'gold' }], 'license')
    const t = await cli.json(['test', 'activate', '--key', l.key], env)
    same(t.ok, true, 'test activation')
    same((await cli.json(['licenses', 'suspend', l.id], env)).status, 'suspended', 'suspended')
    const resumed = (await cli.json(['licenses', 'resume', l.id], env)).status
    if (resumed === 'suspended') throw new Failure('resume did not change the status')
    same((await cli.json(['licenses', 'revoke', l.id, '--yes'], env)).status, 'revoked', 'revoked')
    const list = await cli.json(['licenses', 'list', '--product', product.id], env)
    same((list.data ?? list).length, 1, 'licenses listed')
  },
  'integration code for every SDK': async ({ cli, key }) => {
    for (const lang of ['dotnet', 'typescript', 'python', 'go', 'rust', 'java', 'swift', 'cpp', 'php']) {
      const r = await cli.json(['init', lang], { LICENSERAIL_API_KEY: key })
      if (!r.install || !r.code) throw new Failure(`${lang}: no install command or code`)
    }
  },
}

function cliFor(cmd, dir) {
  const base = { ...process.env, LICENSERAIL_API_URL: API, XDG_CONFIG_HOME: dir, APPDATA: dir, HOME: dir }
  delete base.LICENSERAIL_API_KEY
  const start = (args, env = {}) => {
    const child = spawn(cmd[0], args, { env: { ...base, ...env }, windowsHide: true })
    let out = '', err = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { err += d })
    return { child, done: new Promise((ok, bad) => { child.on('error', bad); child.on('close', (code) => ok({ code, out, err })) }) }
  }
  const run = async (args, env) => { const p = start(args, env); p.child.stdin.end(); return p.done }
  const json = async (args, env) => {
    const r = await run([...args, '--json'], env)
    if (r.code !== 0) throw new Failure(`licenserail ${args.join(' ')}: exit ${r.code} ${r.err || r.out}`)
    return JSON.parse(r.out)
  }
  return { start, run, json }
}

// ---------------------------------------------------------------- run

const only = process.env.E2E_ONLY
let failed = 0
const report = []
for (const name of wanted) {
  const sdk = sdks[name]
  console.log(`\n=== ${name}`)
  let cmd
  try {
    cmd = await sdk.build(join(work, name))
  } catch (e) {
    console.log(`BUILD FAILED\n${e.message}`)
    failed++
    report.push({ name, passed: 0, failed: ['build'] })
    continue
  }
  const v = await createVendor()
  const bad = await badServer()
  const bads = []
  let passed = 0
  const cli = sdk.cli ? cliFor(cmd, mkdtempSync(join(work, 'cli-'))) : null
  for (const [title, run] of Object.entries(sdk.cli ? cliScenarios : scenarios)) {
    if ((only && !title.includes(only)) || sdk.skip?.includes(title)) continue
    try {
      await run({ v, bad, sdk, cli, key: apiKey, app: (over) => new App(sdk, cmd, v, over) })
      passed++
      console.log(`ok    ${title}`)
    } catch (e) {
      bads.push(title)
      console.log(`FAIL  ${title}\n      ${e instanceof Failure ? e.message : e.stack.split('\n').slice(0, 4).join('\n      ')}`)
    }
  }
  bad.close()
  failed += bads.length
  report.push({ name, passed, failed: bads })
}
console.log('\n' + report.map((r) => `${r.name}: ${r.passed} passed, ${r.failed.length} failed`).join('\n'))
process.exit(failed ? 1 : 0)
