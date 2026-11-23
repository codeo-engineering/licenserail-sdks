import { base64Decode, utf8Decode, utf8Encode } from './encoding.js'
import { parsePublicKey, verifyP256 } from './p256.js'

export interface Fingerprint {
  machineId: string
  diskId: string
  hostName: string
  boardId: string
  /** Operating system, or the host platform for installations (e.g. "youtrack"). */
  os?: string | null
}

/** The signed license token's payload (token-spec.md §2). Unknown future fields are kept. */
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
  /** A keyless trial: valid until `expiresAt`, never refreshed. */
  trial?: boolean
  /** Apps inside a host: the most users the host may have and what happens above it. */
  maxHostUsers?: number
  hostUserPolicy?: 'block' | 'warn' | 'report' | string
  /** The server saw more host users than allowed and the policy is "warn": show a warning. */
  hostUsersExceeded?: boolean
  [field: string]: unknown
}

interface Parts { signed: number[]; signature: number[]; payload: LicensePayload }

function split(token: string): Parts | null {
  if (!token || typeof token !== 'string') return null
  const parts = token.trim().split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null
  const signature = base64Decode(parts[1])
  const body = base64Decode(parts[0])
  if (!signature || signature.length !== 64 || !body) return null
  try {
    const payload = JSON.parse(utf8Decode(body)) as LicensePayload
    if (!payload || typeof payload !== 'object' || !payload.fingerprint) return null
    // The signature covers the ASCII bytes of the base64url payload as it appears in the token.
    return { signed: utf8Encode(parts[0]), signature, payload }
  } catch {
    return null
  }
}

/**
 * Verifies a token with the environment's public key (PEM) using the bundled P-256 code, synchronously.
 * Returns the payload, or null when the token is malformed or the signature doesn't match.
 */
export function verifyToken(token: string, publicKeyPem: string): LicensePayload | null {
  const parts = split(token)
  return parts && verifyP256(publicKeyPem, parts.signed, parts.signature) ? parts.payload : null
}

interface SubtleLike {
  importKey(format: 'spki', key: ArrayBuffer, algorithm: object, extractable: boolean, usages: string[]): Promise<unknown>
  verify(algorithm: object, key: unknown, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>
}

function subtle(): SubtleLike | null {
  const c = (globalThis as { crypto?: { subtle?: SubtleLike } }).crypto
  return c && c.subtle && typeof c.subtle.verify === 'function' ? c.subtle : null
}

/** Like {@link verifyToken}, but uses WebCrypto (`crypto.subtle`) when the host has it. */
export async function verifyTokenAsync(token: string, publicKeyPem: string): Promise<LicensePayload | null> {
  const s = subtle()
  if (!s || typeof Uint8Array === 'undefined') return verifyToken(token, publicKeyPem)
  const parts = split(token)
  const key = parsePublicKey(publicKeyPem)
  if (!parts || !key) return null
  try {
    const der = base64Decode(publicKeyPem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, ''))!
    const cryptoKey = await s.importKey('spki', new Uint8Array(der).buffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    const ok = await s.verify({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, new Uint8Array(parts.signature).buffer, new Uint8Array(parts.signed).buffer)
    return ok ? parts.payload : null
  } catch {
    return verifyToken(token, publicKeyPem)
  }
}

/** Reads a token's payload WITHOUT checking the signature (for display only; never trust it). */
export function decodeTokenUnverified(token: string): LicensePayload | null {
  return split(token)?.payload ?? null
}
