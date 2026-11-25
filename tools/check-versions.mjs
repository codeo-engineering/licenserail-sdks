// Every package must carry the version that is being released: node tools/check-versions.mjs 0.1.0
import { readFileSync } from 'node:fs'

const version = process.argv[2]
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
  console.error('Usage: node tools/check-versions.mjs <x.y.z>')
  process.exit(2)
}
const places = {
  'typescript/package.json': /"version": "([^"]+)"/,
  'typescript/package-lock.json': /"version": "([^"]+)"/,
  'embedded/package.json': /"version": "([^"]+)"/,
  'embedded/package-lock.json': /"version": "([^"]+)"/,
  'youtrack/package.json': /"version": "([^"]+)"/,
  'youtrack/package-lock.json': /"version": "([^"]+)"/,
  'python/pyproject.toml': /^version = "([^"]+)"/m,
  'python/src/licenserail/__init__.py': /__version__ = "([^"]+)"/,
  'rust/Cargo.toml': /^version = "([^"]+)"/m,
  'java/pom.xml': /<version>([^<]+)<\/version>/,
  'dotnet/src/LicenseRail/LicenseRail.csproj': /<Version>([^<]+)<\/Version>/,
  'cpp/CMakeLists.txt': /project\(licenserail VERSION ([\d.]+)/,
  'cli/main.go': /const version = "([^"]+)"/,
}
let bad = 0
for (const [file, pattern] of Object.entries(places)) {
  const found = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8').match(pattern)?.[1]
  if (found !== version) {
    console.error(`${file}: ${found ?? 'no version'} instead of ${version}`)
    bad++
  }
}
if (bad) process.exit(1)
console.log(`All packages are ${version}.`)
