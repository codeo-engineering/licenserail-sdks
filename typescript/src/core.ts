import { createHash, createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify, type KeyObject } from 'node:crypto'

/** Hashed device components; raw hardware values never leave the device. */
export interface Fingerprint {
  machineId: string
  diskId: string
  hostName: string
  boardId: string
  /** windows, macos, linux, android or ios. */
  os?: string | null
}

/** The signed license content (token payload). v2 fields are optional. */
export interface LicensePayload {
  licenseId: string
  activationId: string
  licenseKey: string
  product: string
  customer: string
  kind: 'full' | 'trial' | string
  expiresAt: string | null
  issuedAt: string
  refreshAfter: string
  offlineUntil: string
  fingerprint: Fingerprint
  suspended: boolean
  environmentId?: string
  test?: boolean
  entitlements?: string[]
  metadata?: Record<string, unknown>
  floating?: boolean
  leaseExpiresAt?: string
}

export type LicenseStatus =
  | 'Valid'
  | 'Missing'
  | 'InvalidSignature'
  | 'WrongProduct'
  | 'WrongMachine'
  | 'Expired'
  | 'OfflineTooLong'
  | 'ClockTampered'
  | 'Unverified'
  | 'Suspended'

export const UNAVAILABLE = 'none'
/** The clock going back slightly during NTP sync is normal. */
export const CLOCK_TOLERANCE_MS = 10 * 60 * 1000
/** The device clock may lag the server; a token "from the future" by less than this is accepted. */
export const ISSUED_AT_TOLERANCE_MS = 24 * 60 * 60 * 1000

/** Error codes on which the local license is deleted; on any other error (network, 402…) it is kept. */
export const REVOKING_CODES = new Set([
  'license_not_found', 'license_suspended', 'license_expired', 'activation_revoked', 'wrong_machine', 'invalid_token', 'license_revoked',
])

function fromBase64Url(text: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw new Error('invalid base64url')
  return Buffer.from(text, 'base64url')
}

export function importPublicKey(pem: string): KeyObject {
  return createPublicKey({ key: pem, format: 'pem' })
}

/**
 * Verifies `base64url(json).base64url(signature)` (ECDSA P-256 / SHA-256, IEEE P1363 r||s) over the ASCII bytes of the encoded
 * body and returns the payload, or null if the signature or format is invalid.
 */
export function verifyToken(token: string, publicKey: KeyObject | string): LicensePayload | null {
  if (!token || typeof token !== 'string') return null
  const parts = token.trim().split('.')
  if (parts.length !== 2) return null
  try {
    const key = typeof publicKey === 'string' ? importPublicKey(publicKey) : publicKey
    const signature = fromBase64Url(parts[1])
    if (signature.length !== 64) return null
    const ok = cryptoVerify('sha256', Buffer.from(parts[0], 'ascii'), { key, dsaEncoding: 'ieee-p1363' }, signature)
    if (!ok) return null
    const payload = JSON.parse(fromBase64Url(parts[0]).toString('utf8')) as LicensePayload
    return payload && typeof payload === 'object' && payload.fingerprint ? payload : null
  } catch {
    return null
  }
}

/** component = hex(SHA256("codeo:" + product + ":" + part + ":" + upper(trim(raw)))); blank → "none". */
export function hashComponent(product: string, part: 'machine' | 'disk' | 'host' | 'board', raw: string | null | undefined): string {
  if (raw == null || raw.trim() === '') return UNAVAILABLE
  return createHash('sha256').update(`codeo:${product}:${part}:${raw.trim().toUpperCase()}`, 'utf8').digest('hex')
}

const available = (v: string | null | undefined): v is string => !!v && v !== UNAVAILABLE
const same = (a: string | null | undefined, b: string | null | undefined) => available(a) && a === b

/** Whether `presented` is the device `registered` was issued for (call on the registered fingerprint). */
export function fingerprintMatches(registered: Fingerprint, presented: Fingerprint): boolean {
  if (registered.os && presented.os && registered.os.toLowerCase() !== presented.os.toLowerCase()) return false
  let matches = 0
  if (same(registered.machineId, presented.machineId)) matches++
  if (same(registered.diskId, presented.diskId)) matches++
  if (same(registered.hostName, presented.hostName)) matches++
  return available(registered.boardId) ? same(registered.boardId, presented.boardId) && matches >= 1 : matches >= 2
}

/** Offline check, identical in every SDK (see the shared test vectors). */
export function evaluate(payload: LicensePayload | null, product: string, machine: Fingerprint, now: Date, lastSeen: Date | null): LicenseStatus {
  if (!payload) return 'InvalidSignature'
  if (payload.product.toLowerCase() !== product.toLowerCase()) return 'WrongProduct'
  if (!fingerprintMatches(payload.fingerprint, machine)) return 'WrongMachine'
  if (payload.suspended) return 'Suspended'
  if (!lastSeen) return 'Unverified'
  const t = now.getTime()
  if (t + ISSUED_AT_TOLERANCE_MS < Date.parse(payload.issuedAt) || t + CLOCK_TOLERANCE_MS < lastSeen.getTime()) return 'ClockTampered'
  if (payload.expiresAt && t >= Date.parse(payload.expiresAt)) return 'Expired'
  if (t >= Date.parse(payload.offlineUntil)) return 'OfflineTooLong'
  return 'Valid'
}

/** Tamper-evident "last run" record: `{epochMs}.{hmac}` keyed to the product and device. */
export function encodeRunHistory(at: Date, product: string, machine: Fingerprint): string {
  const ms = String(at.getTime())
  return `${ms}.${historyMac(ms, product, machine)}`
}

export function decodeRunHistory(value: string | null | undefined, product: string, machine: Fingerprint): Date | null {
  const parts = value?.trim().split('.')
  if (!parts || parts.length !== 2 || !/^\d{1,15}$/.test(parts[0])) return null
  const expected = Buffer.from(historyMac(parts[0], product, machine))
  const actual = Buffer.from(parts[1])
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null
  return new Date(Number(parts[0]))
}

function historyMac(ms: string, product: string, machine: Fingerprint): string {
  const key = createHash('sha256').update(`codeo-run-history:${product}:${machine.machineId}:${machine.boardId}`).digest()
  return createHmac('sha256', key).update(ms).digest('hex').slice(0, 32).toUpperCase()
}
