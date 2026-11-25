import type { Fingerprint, LicensePayload } from './token.js'

// Request descriptions and response reading for the client API (/api/client/v2). No I/O here: hosts send the requests
// with whatever they have (fetch, a synchronous call, or a fire-and-callback API such as YouTrack's postAsync).

export interface HttpRequestDescription {
  method: 'POST'
  url: string
  headers: Record<string, string>
  /** JSON text. */
  body: string
}

export interface Target {
  /** e.g. https://api.licenserail.com */
  apiUrl: string
  product: string
  fingerprint: Fingerprint
}

/** Header that makes the server rate-limit per installation instead of per IP (apps inside a host share its IPs). */
export const INSTALLATION_HEADER = 'LicenseRail-Installation'

function url(apiUrl: string, path: string) {
  return apiUrl.replace(/\/+$/, '') + '/api/client/v2' + path
}

function headers(fingerprint: Fingerprint): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  if (fingerprint.os) h[INSTALLATION_HEADER] = `${fingerprint.os}:${fingerprint.machineId}`.slice(0, 128)
  return h
}

function clean<T extends object>(o: T): T {
  const out = {} as T
  for (const k of Object.keys(o) as (keyof T)[]) if (o[k] !== undefined && o[k] !== null) out[k] = o[k]
  return out
}

export interface ActivateOptions extends Target {
  /**
   * The license key. Omit it when the host adds `Authorization: Bearer <key>` itself (YouTrack: the key is a secret setting
   * that only `connection.bearerAuth(ctx.settings.licenseKey)` can send).
   */
  licenseKey?: string
  /** Send the key as `Authorization: Bearer` instead of in the body (default true). */
  keyInHeader?: boolean
  machineName?: string
  appVersion?: string
  /** The host's current number of users (checked against the license's host user limit). */
  hostUsers?: number
  /** Floating license: check out a lease instead of activating. */
  floating?: boolean
}

export function activateRequest(o: ActivateOptions): HttpRequestDescription {
  const h = headers(o.fingerprint)
  const inHeader = o.keyInHeader !== false
  if (o.licenseKey && inHeader) h.Authorization = `Bearer ${o.licenseKey}`
  return {
    method: 'POST',
    url: url(o.apiUrl, o.floating ? '/floating/checkout' : '/activate'),
    headers: h,
    body: JSON.stringify(clean({
      product: o.product, fingerprint: o.fingerprint, licenseKey: inHeader ? undefined : o.licenseKey,
      machineName: o.machineName, appVersion: o.appVersion, hostUsers: o.hostUsers,
    })),
  }
}

export interface RefreshOptions extends Target {
  token: string
  appVersion?: string
  hostUsers?: number
  anomalies?: string[]
  floating?: boolean
}

export function refreshRequest(o: RefreshOptions): HttpRequestDescription {
  return {
    method: 'POST',
    url: url(o.apiUrl, o.floating ? '/floating/heartbeat' : '/refresh'),
    headers: headers(o.fingerprint),
    // appVersion is a required field of the refresh request (null allowed).
    body: JSON.stringify({ ...clean({ token: o.token, fingerprint: o.fingerprint, anomalies: o.anomalies, hostUsers: o.hostUsers }), appVersion: o.appVersion ?? null }),
  }
}

export function deactivateRequest(o: Target & { token: string; floating?: boolean }): HttpRequestDescription {
  return {
    method: 'POST',
    url: url(o.apiUrl, o.floating ? '/floating/release' : '/deactivate'),
    headers: headers(o.fingerprint),
    body: JSON.stringify({ token: o.token, fingerprint: o.fingerprint }),
  }
}

export interface TrialOptions extends Target {
  /** The environment's signing key id (public; shown with the public key in the dashboard). */
  keyId: string
  machineName?: string
  appVersion?: string
  hostUsers?: number
}

export function trialRequest(o: TrialOptions): HttpRequestDescription {
  return {
    method: 'POST',
    url: url(o.apiUrl, '/trial'),
    headers: headers(o.fingerprint),
    body: JSON.stringify(clean({ keyId: o.keyId, product: o.product, fingerprint: o.fingerprint, machineName: o.machineName, appVersion: o.appVersion, hostUsers: o.hostUsers })),
  }
}

/** Codes on which the local license must be removed; on all others (network errors, 402, 429, 5xx) the app keeps it. */
export const REVOKING_CODES: readonly string[] = [
  'license_not_found', 'license_suspended', 'license_expired', 'activation_revoked', 'wrong_machine', 'invalid_token', 'license_revoked',
]

export type ClientResponse =
  | { ok: true; token: string }
  | { ok: true; token: null }   // 204 (deactivate)
  | { ok: false; code: string; message: string; revokesLocalLicense: boolean; retryLater: boolean }

/** Reads a client API response. `status` 0 means the request failed before any response (network error, timeout). */
export function readResponse(status: number, bodyText: string | null | undefined): ClientResponse {
  let body: { token?: unknown; code?: unknown; message?: unknown } | null = null
  try { body = bodyText ? JSON.parse(bodyText) : null } catch { body = null }
  if (status >= 200 && status < 300) {
    if (status === 204) return { ok: true, token: null }
    // Anything else without a token isn't our server's answer (a captive portal, a proxy): an error, so nothing is removed.
    if (body && typeof body.token === 'string') return { ok: true, token: body.token }
  }
  const code = body && typeof body.code === 'string' ? body.code : status === 0 ? 'network_error' : `http_${status}`
  const message = body && typeof body.message === 'string' ? body.message : status === 0 ? 'The license server could not be reached.' : 'Unexpected response from the license server.'
  return {
    ok: false, code, message,
    revokesLocalLicense: REVOKING_CODES.indexOf(code) >= 0,
    retryLater: status === 0 || status === 429 || status === 402 || status >= 500,
  }
}

/** When the token wants to be refreshed (null for trials, which are never refreshed). */
export function refreshDueAt(payload: LicensePayload): Date | null {
  if (payload.trial === true) return null
  return new Date(payload.refreshAfter)
}
