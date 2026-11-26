import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createLicenseClient, installationFingerprint } from '@codeo-engineering/licenserail-embedded'

const e = process.env
const [m, d, h, b] = (e.LR_DEVICE ?? '').split(',')
const file = (k) => join(e.LR_STORAGE, { 'licenserail:token': 'license.lic', 'licenserail:lastSeen': 'license.seen' }[k])
const client = createLicenseClient({
  apiUrl: e.LR_URL, product: e.LR_PRODUCT, publicKeyPem: readFileSync(e.LR_PUBLIC_KEY_FILE, 'utf8'), appVersion: '1.2.3', timeoutMs: Number(e.LR_TIMEOUT) * 1000, machineName: 'host',
  fingerprint: m ? { machineId: m, diskId: d, hostName: h, boardId: b, os: 'linux' }
    : installationFingerprint(e.LR_VENDOR, e.LR_PRODUCT, 'youtrack', 'c0368d08-878f-4f47-b836-724248d8f7e8'),
  storage: {
    get: (k) => (existsSync(file(k)) ? readFileSync(file(k), 'utf8') : null), set: (k, v) => writeFileSync(file(k), v), remove: (k) => rmSync(file(k), { force: true }),
  },
})
const result = (r) => (r.ok ? { success: true } : { success: false, errorCode: r.code, message: r.message })
const [op, key] = process.argv.slice(2)
let out
if (op === 'activate') {
  let r = await client.activate(key)
  if (!r.ok && r.code === 'bad_request' && /floating/i.test(r.message)) r = await client.activate(key, true)
  out = result(r)
} else if (op === 'deactivate') out = result(await client.deactivate())
else if (op === 'refresh') out = result(await client.refresh(true))
else {
  // The app's part: refresh when due, or when only the server can clear the state.
  let s = await client.state()
  s = (await client.refresh(['Expired', 'Suspended', 'OfflineTooLong', 'ClockTampered', 'Unverified'].includes(s.status))).state
  out = { status: s.status, features: s.payload?.entitlements ?? [], test: s.payload?.test === true }
}
console.log(JSON.stringify(out))
