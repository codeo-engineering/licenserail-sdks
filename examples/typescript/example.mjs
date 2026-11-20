// Minimal app: node example.mjs <license-key>  (env: LICENSERAIL_URL, LICENSERAIL_PRODUCT, LICENSERAIL_PUBLIC_KEY_FILE)
import { readFileSync } from 'node:fs'
import { LicenseClient } from '../../typescript/dist/index.js'

const client = new LicenseClient({
  serverUrl: process.env.LICENSERAIL_URL ?? 'https://api.licenserail.com',
  vendor: process.env.LICENSERAIL_VENDOR ?? 'acme',
  vendor: process.env.LICENSERAIL_VENDOR ?? 'acme',
  product: process.env.LICENSERAIL_PRODUCT ?? 'my-app',
  publicKeyPem: readFileSync(process.env.LICENSERAIL_PUBLIC_KEY_FILE ?? 'public-key.pem', 'utf8'),
  appVersion: '1.0.0',
  storageDir: process.env.LICENSERAIL_STORAGE,
})

let result = await client.check()
console.log('startup:', result.status)
if (!result.valid && process.argv[2]) {
  const activation = await client.activate(process.argv[2])
  console.log('activate:', activation.success, activation.message)
  result = await client.check()
}
console.log('status:', result.status, 'features:', client.license?.features, 'test:', client.license?.isTest)
if (process.argv.includes('--deactivate')) console.log('deactivate:', (await client.deactivate()).message)
