import { hex, utf8Encode } from './encoding.js'
import { sha256 } from './sha256.js'
import type { Fingerprint } from './token.js'

export const UNAVAILABLE = 'none'

/** Host platforms whose installations are licensed like devices (the server's list; extended as adapters ship). */
export const HOST_PLATFORMS: readonly string[] = ['youtrack']

export type ComponentPart = 'machine' | 'disk' | 'host' | 'board' | 'installation'

/**
 * lowercase_hex(SHA256(vendor:product:part:UPPER(TRIM(raw)))); missing or blank raw is "none". The vendor is the organization
 * id (ten_...), so the same device or installation hashes differently for every vendor and product.
 */
export function hashComponent(vendor: string, product: string, part: ComponentPart, raw: string | null | undefined): string {
  if (raw == null || raw.trim() === '') return UNAVAILABLE
  return hex(sha256(utf8Encode(`${vendor}:${product}:${part}:${raw.trim().toUpperCase()}`)))
}

/** The fingerprint of an installation inside a host platform (e.g. a YouTrack instance's uuid). */
export function installationFingerprint(vendor: string, product: string, platform: string, installationId: string): Fingerprint {
  return {
    machineId: hashComponent(vendor, product, 'installation', installationId),
    diskId: UNAVAILABLE, hostName: UNAVAILABLE, boardId: UNAVAILABLE,
    os: platform.toLowerCase(),
  }
}

export const isHostInstallation = (f: Fingerprint) => !!f.os && HOST_PLATFORMS.indexOf(f.os.toLowerCase()) >= 0

const available = (v: string | null | undefined): v is string => !!v && v !== UNAVAILABLE
const same = (a: string | null | undefined, b: string | null | undefined) => available(a) && a === b

/**
 * Whether `presented` is the device or installation `registered` was issued for (call on the registered fingerprint).
 * Installations: same platform and exactly the same id. Computers: board id + one other part, or two of three without a board id.
 */
export function fingerprintMatches(registered: Fingerprint, presented: Fingerprint): boolean {
  if (isHostInstallation(registered) || isHostInstallation(presented))
    return (registered.os ?? '').toLowerCase() === (presented.os ?? '').toLowerCase() && same(registered.machineId, presented.machineId)
  if (registered.os && presented.os && registered.os.toLowerCase() !== presented.os.toLowerCase()) return false
  let matches = 0
  if (same(registered.machineId, presented.machineId)) matches++
  if (same(registered.diskId, presented.diskId)) matches++
  if (same(registered.hostName, presented.hostName)) matches++
  return available(registered.boardId) ? same(registered.boardId, presented.boardId) && matches >= 1 : matches >= 2
}
