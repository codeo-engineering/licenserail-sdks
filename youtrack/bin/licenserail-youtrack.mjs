#!/usr/bin/env node
// Adds LicenseRail to a YouTrack app:
//   npx licenserail-youtrack add <app folder> [--vendor ten_...] [--product code] [--key-id id] [--public-key key.pem]
//                                             [--api-url https://api.licenserail.com] [--backend <folder of backend .js files>]
// Copies the backend modules and the License page, merges settings.json, entity-extensions.json and manifest.json, and
// writes licenserail-config.js (only if it doesn't exist yet). Running it again updates the LicenseRail files.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const files = join(here, '..', 'dist', 'app-files')
const fragments = JSON.parse(readFileSync(join(files, 'fragments.json'), 'utf8'))

// Not cpSync: Node 22's crashes on Windows when the path has non-ASCII characters (e.g. the user's name).
function copyFolder(from, to) {
  mkdirSync(to, { recursive: true })
  for (const f of readdirSync(from, { withFileTypes: true })) {
    if (f.isDirectory()) copyFolder(join(from, f.name), join(to, f.name))
    else writeFileSync(join(to, f.name), readFileSync(join(from, f.name)))
  }
}

function usage(message) {
  if (message) console.error(message)
  console.error('Usage: licenserail-youtrack add <app folder> [--vendor ten_...] [--product code] [--key-id id] [--public-key key.pem] [--api-url url] [--backend folder]')
  process.exit(1)
}

const args = process.argv.slice(2)
if (args[0] !== 'add' || !args[1]) usage()
const appDir = resolve(args[1])
const opt = {}
for (let i = 2; i < args.length; i += 2) {
  if (!args[i].startsWith('--') || args[i + 1] === undefined) usage(`Unexpected argument: ${args[i]}`)
  opt[args[i].slice(2)] = args[i + 1]
}
const manifestPath = join(appDir, 'manifest.json')
if (!existsSync(manifestPath)) usage(`No manifest.json in ${appDir}`)
const backend = resolve(appDir, opt.backend ?? '.')

const readJson = (path, fallback) => (existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : fallback)
const writeJson = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n')

// Backend modules and the License page (always replaced, so updates land).
for (const name of ['licenserail-core.js', 'licenserail.js', 'licenserail-license.js']) writeFileSync(join(backend, name), readFileSync(join(files, name)))
copyFolder(join(files, 'widgets', 'licenserail-license'), join(backend, 'widgets', 'licenserail-license'))

// Configuration (kept once written).
const configPath = join(backend, 'licenserail-config.js')
if (!existsSync(configPath)) {
  let config = readFileSync(join(files, 'licenserail-config.js'), 'utf8')
  const pem = opt['public-key'] ? readFileSync(resolve(opt['public-key']), 'utf8').trim() : null
  if (opt['api-url']) config = config.replace('https://api.licenserail.com', opt['api-url'])
  if (opt.vendor) config = config.replace('__VENDOR_ID__', opt.vendor)
  if (opt.product) config = config.replace('__PRODUCT_CODE__', opt.product)
  if (opt['key-id']) config = config.replace('__KEY_ID__', opt['key-id'])
  if (pem) config = config.replace("'__PUBLIC_KEY_PEM__'", JSON.stringify(pem + '\n'))
  writeFileSync(configPath, config)
}

// settings.json: the secret license key setting.
const settingsPath = join(backend, 'settings.json')
const settings = readJson(settingsPath, { $schema: 'http://json-schema.org/draft-07/schema#', type: 'object', properties: {} })
settings.properties = Object.assign({}, fragments.settings, settings.properties ?? {})
writeJson(settingsPath, settings)

// entity-extensions.json: where the token and state are kept.
const extensionsPath = join(backend, 'entity-extensions.json')
const extensions = readJson(extensionsPath, { entityTypeExtensions: [] })
let storage = extensions.entityTypeExtensions.find((e) => e.entityType === 'AppGlobalStorage')
if (!storage) extensions.entityTypeExtensions.push((storage = { entityType: 'AppGlobalStorage', properties: {} }))
storage.properties = Object.assign({}, storage.properties ?? {}, fragments.appGlobalStorage)
writeJson(extensionsPath, extensions)

// manifest.json: the License page and the minimum YouTrack version (async HTTP needs 2026.2).
const manifest = readJson(manifestPath, {})
manifest.widgets = (manifest.widgets ?? []).filter((w) => w.key !== fragments.widget.key)
const widget = { ...fragments.widget }
if (backend !== appDir) widget.indexPath = join(backend.slice(appDir.length + 1), widget.indexPath).replace(/\\/g, '/')
manifest.widgets.push(widget)
const version = (v) => (v ?? '0').split('.').map(Number)
const [a1, a2] = version(manifest.minYouTrackVersion), [b1, b2] = version(fragments.minYouTrackVersion)
if (a1 < b1 || (a1 === b1 && (a2 ?? 0) < b2)) manifest.minYouTrackVersion = fragments.minYouTrackVersion
writeJson(manifestPath, manifest)

console.log(`LicenseRail added to ${appDir}`)
if (readFileSync(configPath, 'utf8').includes('__')) console.log(`Fill in ${configPath} with the values from the LicenseRail dashboard.`)
console.log('In your handlers: const licenserail = require(\'./licenserail\'); licenserail.check(ctx).valid; asyncFunctions: licenserail.asyncFunctions')
