import { fingerprintMatches } from './fingerprint.js'
import type { Fingerprint, LicensePayload } from './token.js'

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

const CLOCK_TOLERANCE_MS = 10 * 60 * 1000
const ISSUED_AT_TOLERANCE_MS = 24 * 60 * 60 * 1000

/**
 * The offline check, identical in every SDK (shared test vectors). `lastSeen` is the last time the app ran with this license;
 * without one the license is Unverified until the next online check.
 */
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

/** What an app needs to show and gate features, read from a verified payload. */
export interface LicenseSummary {
  isTrial: boolean
  isTest: boolean
  expiresAt: Date | null
  entitlements: string[]
  metadata: Record<string, unknown>
  maxHostUsers: number | null
  hostUserPolicy: string | null
  /** True when the server flagged the host user limit (policy "warn"), or `hostUsers` is above the limit. */
  hostUsersOverLimit: boolean
}

export function summarize(payload: LicensePayload, hostUsers?: number | null): LicenseSummary {
  const max = typeof payload.maxHostUsers === 'number' ? payload.maxHostUsers : null
  return {
    isTrial: payload.trial === true || payload.kind === 'trial',
    isTest: payload.test === true,
    expiresAt: payload.expiresAt ? new Date(payload.expiresAt) : null,
    entitlements: payload.entitlements ?? [],
    metadata: payload.metadata ?? {},
    maxHostUsers: max,
    hostUserPolicy: max === null ? null : (payload.hostUserPolicy ?? 'block'),
    hostUsersOverLimit: payload.hostUsersExceeded === true || (max !== null && typeof hostUsers === 'number' && hostUsers > max),
  }
}

export const hasFeature = (payload: LicensePayload, code: string) => (payload.entitlements ?? []).indexOf(code) >= 0
