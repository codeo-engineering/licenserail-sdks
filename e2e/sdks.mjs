// How to build each SDK's package and its driver. build(dir) returns the command that runs the driver.
import { execFileSync } from 'node:child_process'
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const driver = (name) => join(root, 'e2e', 'drivers', name)
const windows = process.platform === 'win32'
const exe = windows ? '.exe' : ''

function sh(cmd, args, cwd) {
  try {
    // npm and mvn are .cmd files on Windows and need a shell there.
    const shell = windows && ['npm', 'mvn'].includes(cmd)
    const list = shell ? args.map((a) => (/[\s&()^]/.test(a) ? `"${a}"` : a)) : args
    return execFileSync(cmd, list, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], shell, maxBuffer: 1 << 26 })
  } catch (e) {
    throw new Error(`${cmd} ${args.join(' ')}\n${(e.stdout ?? '').slice(-3000)}\n${(e.stderr ?? '').slice(-3000) || e.message}`)
  }
}

function empty(dir) {
  rmSync(dir, { recursive: true, force: true })
  mkdirSync(dir, { recursive: true })
  return dir
}

/** Copies a folder. Not cpSync: Node 22's crashes on Windows paths with non-ASCII characters. */
function copy(from, to) {
  mkdirSync(to, { recursive: true })
  for (const f of readdirSync(from, { withFileTypes: true })) {
    if (f.isDirectory()) copy(join(from, f.name), join(to, f.name))
    else writeFileSync(join(to, f.name), readFileSync(join(from, f.name)))
  }
}

/** Packs an npm package and installs the .tgz into an empty project that contains the driver. */
function npmProject(name, dir, needs = []) {
  empty(dir)
  for (const n of needs) sh('npm', ['ci', '--no-audit', '--no-fund'], join(root, n))
  sh('npm', ['ci', '--no-audit', '--no-fund'], join(root, name))
  sh('npm', ['run', 'build'], join(root, name))
  sh('npm', ['pack', '--pack-destination', dir], join(root, name))
  const app = empty(join(dir, 'uygulama ğüş'))   // non-ASCII on purpose
  writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'e2e-app', private: true, type: 'module' }))
  sh('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', join(dir, readdirSync(dir).find((f) => f.endsWith('.tgz')))], app)
  copy(driver(name), app)
  return [process.execPath, join(app, 'driver.mjs')]
}

export const sdks = {
  typescript: { build: async (dir) => npmProject('typescript', dir) },

  embedded: { plainHistory: true, networkCode: 'network_error', build: async (dir) => npmProject('embedded', dir) },

  // Floating licenses are not offered in YouTrack.
  youtrack: {
    // An installation always has an id.
    plainHistory: true, networkCode: 'network_error', skip: ['floating licenses: check out, heartbeat, release', 'a device that cannot be identified uses no seat'],
    build: async (dir) => npmProject('youtrack', dir, ['embedded']),
  },

  cli: {
    cli: true,
    async build(dir) {
      empty(dir)
      sh('go', ['build', '-o', join(dir, 'licenserail' + exe), '.'], join(root, 'cli'))
      return [join(dir, 'licenserail' + exe)]
    },
  },

  dotnet: {
    async build(dir) {
      empty(dir)
      const feed = join(dir, 'feed')
      sh('dotnet', ['pack', join(root, 'dotnet', 'src', 'LicenseRail', 'LicenseRail.csproj'), '-c', 'Release', '-o', feed], root)
      const app = join(dir, 'app')
      copy(driver('dotnet'), app)
      const version = readdirSync(feed).find((f) => f.endsWith('.nupkg')).match(/LicenseRail\.(.+)\.nupkg/)[1]
      // Own package folder: a package of the same version from an earlier run must not be reused.
      writeFileSync(join(app, 'nuget.config'), `<configuration><config><add key="globalPackagesFolder" value="${join(dir, 'packages')}" /></config>
<packageSources><clear /><add key="built" value="${feed}" /><add key="nuget" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>`)
      sh('dotnet', ['publish', 'Driver.csproj', '-c', 'Release', '-o', 'out', `-p:LicenseRailVersion=${version}`], app)
      return ['dotnet', join(app, 'out', 'Driver.dll')]
    },
  },

  python: {
    async build(dir) {
      empty(dir)
      sh(process.env.PYTHON ?? (windows ? 'python' : 'python3'), ['-m', 'venv', 'venv'], dir)
      const py = join(dir, 'venv', windows ? 'Scripts' : 'bin', 'python' + exe)
      const pip = ['-m', 'pip', 'install', '-q', '--disable-pip-version-check']
      sh(py, [...pip, 'build'], dir)
      sh(py, ['-m', 'build', '--wheel', '--outdir', join(dir, 'dist'), join(root, 'python')], dir)
      sh(py, [...pip, join(dir, 'dist', readdirSync(join(dir, 'dist')).find((f) => f.endsWith('.whl')))], dir)
      copy(driver('python'), dir)
      return [py, join(dir, 'driver.py')]
    },
  },

  go: {
    async build(dir) {
      empty(dir)
      copy(driver('go'), dir)
      sh('go', ['mod', 'init', 'e2e'], dir)
      sh('go', ['mod', 'edit', '-require=github.com/codeo-engineering/licenserail-sdks/go@v0.0.0',
        `-replace=github.com/codeo-engineering/licenserail-sdks/go=${join(root, 'go')}`], dir)
      sh('go', ['build', '-o', 'driver' + exe, '.'], dir)
      return [join(dir, 'driver' + exe)]
    },
  },

  rust: {
    async build(dir) {
      empty(dir)
      // The .crate that would be uploaded, unpacked.
      sh('cargo', ['package', '--allow-dirty', '--no-verify', '--target-dir', join(dir, 'package')], join(root, 'rust'))
      const crates = join(dir, 'package', 'package')
      sh('tar', ['xzf', readdirSync(crates).find((f) => f.endsWith('.crate'))], crates)
      const crate = join(crates, readdirSync(crates).find((f) => /^licenserail-[\d.]+$/.test(f)))
      const app = join(dir, 'app')
      copy(driver('rust'), app)
      writeFileSync(join(app, 'Cargo.toml'), `[package]\nname = "driver"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nlicenserail = { path = ${JSON.stringify(crate)} }\nserde_json = "1"\n[workspace]\n`)
      sh('cargo', ['build', '-q'], app)
      return [join(app, 'target', 'debug', 'driver' + exe)]
    },
  },

  java: {
    async build(dir) {
      empty(dir)
      sh('mvn', ['-B', '-q', '-Prelease', '-Dgpg.skip', 'verify'], join(root, 'java'))
      const jar = join(root, 'java', 'target', readdirSync(join(root, 'java', 'target')).find((f) => /^licenserail-[\d.]+\.jar$/.test(f)))
      copy(driver('java'), dir)
      sh('javac', ['-cp', jar, '-d', join(dir, 'classes'), join(dir, 'Driver.java')], dir)
      return ['java', '-cp', [jar, join(dir, 'classes')].join(windows ? ';' : ':'), 'Driver']
    },
  },

  php: {
    async build(dir) {
      empty(dir)
      copy(driver('php'), dir)
      writeFileSync(join(dir, 'composer.json'), JSON.stringify({
        repositories: [{ type: 'path', url: join(root, 'php'), options: { symlink: false } }], require: { 'licenserail/licenserail': '*@dev' },
      }))
      sh('composer', ['install', '--no-interaction', '--quiet'], dir)
      return ['php', join(dir, 'driver.php')]
    },
  },

  cpp: {
    async build(dir) {
      empty(dir)
      copy(driver('cpp'), dir)
      // As in the docs: FetchContent of the repository with SOURCE_SUBDIR cpp.
      writeFileSync(join(dir, 'CMakeLists.txt'), `cmake_minimum_required(VERSION 3.18)
project(driver LANGUAGES C CXX)
include(FetchContent)
FetchContent_Declare(licenserail SOURCE_DIR "${root.replaceAll('\\', '/')}" SOURCE_SUBDIR cpp)
FetchContent_MakeAvailable(licenserail)
add_executable(driver main.cpp)
target_link_libraries(driver PRIVATE licenserail)
set_target_properties(driver PROPERTIES CXX_STANDARD 17)
`)
      sh('cmake', ['-S', '.', '-B', 'build', '-DCMAKE_BUILD_TYPE=Release'], dir)
      sh('cmake', ['--build', 'build', '-j', '--target', 'driver'], dir)
      return [join(dir, 'build', 'driver' + exe)]
    },
  },

  swift: {
    async build(dir) {
      empty(dir)
      copy(driver('swift'), dir)
      // A package named like the mirror repository, with only what the mirror contains.
      copy(join(root, 'swift'), join(dir, 'licenserail-swift'))
      writeFileSync(join(dir, 'Package.swift'), `// swift-tools-version:5.7
import PackageDescription
let package = Package(name: "Driver", platforms: [.macOS(.v12)], dependencies: [.package(path: "licenserail-swift")],
  targets: [.executableTarget(name: "Driver", dependencies: [.product(name: "LicenseRail", package: "licenserail-swift")])])
`)
      sh('swift', ['build', '-c', 'release'], dir)
      return [join(dir, '.build', 'release', 'Driver')]
    },
  },
}
