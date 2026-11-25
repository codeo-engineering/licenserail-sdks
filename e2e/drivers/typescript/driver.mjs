import { readFileSync } from 'node:fs'
import { LicenseClient } from 'licenserail'

const e = process.env
const [m, d, h, b] = (e.LR_DEVICE ?? '').split(',')
const client = new LicenseClient({
  serverUrl: e.LR_URL, vendor: e.LR_VENDOR, product: e.LR_PRODUCT, publicKeyPem: readFileSync(e.LR_PUBLIC_KEY_FILE, 'utf8'),
  storageDir: e.LR_STORAGE, appVersion: '1.2.3', timeoutMs: Number(e.LR_TIMEOUT) * 1000,
  ...(m ? { fingerprint: () => ({ machineId: m, diskId: d, hostName: h, boardId: b, os: 'linux' }) } : {}),
})
const [op, key] = process.argv.slice(2)
let out
if (op === 'activate') out = await client.activate(key)
else if (op === 'deactivate') out = await client.deactivate()
else if (op === 'refresh') {
  try { await client.refresh(); out = { success: true } } catch (x) { out = { success: false, errorCode: 'network', message: String(x) } }
} else {
  const r = await client.check()
  out = { status: r.status, features: r.license?.features ?? [], test: r.license?.isTest ?? false }
}
console.log(JSON.stringify(out))
// Not process.exit(): a floating license's heartbeat must not keep the app running.
