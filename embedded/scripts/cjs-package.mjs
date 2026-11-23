// Marks dist/cjs as CommonJS (the package itself is "type": "module") and rewrites the ".js" in require() calls to plain
// module names, so the files load with require() in Node and in hosts like YouTrack apps (which resolve "./x" and "./x.js").
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'

writeFileSync('dist/cjs/package.json', JSON.stringify({ type: 'commonjs' }) + '\n')
for (const file of readdirSync('dist/cjs').filter((f) => f.endsWith('.js'))) {
  const path = `dist/cjs/${file}`
  writeFileSync(path, readFileSync(path, 'utf8').replace(/require\("\.\/([\w-]+)\.js"\)/g, 'require("./$1")'))
}
