import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { hostname, platform } from 'node:os'
import { hashComponent, type Fingerprint } from './core.js'

function run(cmd: string, args: string[]): string | null {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout: 5000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return null
  }
}

function readFirst(...paths: string[]): string | null {
  for (const p of paths) {
    try {
      if (existsSync(p)) {
        const v = readFileSync(p, 'utf8').trim()
        if (v) return v
      }
    } catch {
      // not readable (often root-only)
    }
  }
  return null
}

/** SMBIOS placeholders some vendors ship instead of a real UUID. */
const placeholder = (v: string | null) =>
  !v || /^[0F-]+$/i.test(v.replace(/-/g, '')) || /^(03000200-0400-0500-0006-000700080009|FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF)$/i.test(v)

function windows(): [string | null, string | null, string | null, string | null] {
  const reg = run('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid', '/reg:64'])
  const machine = reg?.match(/MachineGuid\s+REG_SZ\s+(\S+)/i)?.[1] ?? null
  const vol = run('cmd', ['/c', 'vol', process.env.SystemDrive ?? 'C:'])
  const serial = vol?.match(/([0-9A-F]{4})-([0-9A-F]{4})/i)
  const disk = serial ? `${serial[1]}${serial[2]}`.toUpperCase() : null
  const uuidOut = run('powershell', ['-NoProfile', '-Command', '(Get-CimInstance Win32_ComputerSystemProduct).UUID'])?.trim() ?? null
  return [machine, disk, hostname(), placeholder(uuidOut) ? null : uuidOut]
}

function macos(): [string | null, string | null, string | null, string | null] {
  const io = run('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice']) ?? ''
  const platformUuid = io.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/)?.[1] ?? null
  const serial = io.match(/"IOPlatformSerialNumber"\s*=\s*"([^"]+)"/)?.[1] ?? null
  const diskInfo = run('diskutil', ['info', '/']) ?? ''
  const volume = diskInfo.match(/Volume UUID:\s*([0-9A-F-]+)/i)?.[1] ?? null
  const host = run('scutil', ['--get', 'LocalHostName'])?.trim() || hostname()
  // machine = hardware serial (independent of the board UUID, so 2 signals remain), board = IOPlatformUUID.
  return [serial, volume, host, platformUuid]
}

function linux(): [string | null, string | null, string | null, string | null] {
  const machine = readFirst('/etc/machine-id', '/var/lib/dbus/machine-id')
  let disk: string | null = null
  const mounts = readFirst('/proc/self/mountinfo')
  const root = mounts?.split('\n').map((l) => l.split(' ')).find((f) => f[4] === '/')
  const device = root ? root[root.indexOf('-') + 2] : null
  if (device) {
    const out = run('blkid', ['-s', 'UUID', '-o', 'value', device])?.trim()
    disk = out || null
  }
  const board = readFirst('/sys/class/dmi/id/product_uuid')
  return [machine, disk, hostname(), placeholder(board) ? null : board]
}

/** Collects and hashes the device fingerprint for `vendor` (organization slug) and `product` (Windows, macOS, Linux). */
export function collectFingerprint(vendor: string, product: string): Fingerprint {
  const os = platform() === 'win32' ? 'windows' : platform() === 'darwin' ? 'macos' : 'linux'
  const [m, d, h, b] = os === 'windows' ? windows() : os === 'macos' ? macos() : linux()
  return {
    machineId: hashComponent(vendor, product, 'machine', m),
    diskId: hashComponent(vendor, product, 'disk', d),
    hostName: hashComponent(vendor, product, 'host', h),
    boardId: hashComponent(vendor, product, 'board', b),
    os,
  }
}
