// Builds dist/app-files: the files a YouTrack app copies in. licenserail-core.js is licenserail-embedded bundled into one
// readable CommonJS file (Marketplace rule: no obfuscation; plain bundling is fine).
import { build } from 'esbuild'
import { cpSync, mkdirSync, rmSync } from 'node:fs'

rmSync('dist', { recursive: true, force: true })
mkdirSync('dist/app-files', { recursive: true })
cpSync('app-files', 'dist/app-files', { recursive: true })
await build({
  entryPoints: ['../embedded/src/index.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'neutral',
  target: 'es2020',
  minify: false,
  legalComments: 'inline',
  banner: { js: '// licenserail-embedded (MIT, Codeo Solutions Limited), bundled for YouTrack apps. Do not edit; update with licenserail-youtrack.' },
  outfile: 'dist/app-files/licenserail-core.js',
})
console.log('dist/app-files ready')
