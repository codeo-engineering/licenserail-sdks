import { evaluate, summarize, type LicenseStatus, type LicenseSummary } from './evaluate.js'
import { fingerprintMatches } from './fingerprint.js'
import { activateRequest, deactivateRequest, readResponse, refreshDueAt, refreshRequest, trialRequest, type HttpRequestDescription } from './protocol.js'
import { verifyTokenAsync, type Fingerprint, type LicensePayload } from './token.js'

// A ready client for hosts that can await HTTP calls (browser extensions, web apps, workers, Electron renderers).
// Hosts with callback-style I/O (YouTrack apps) use the functions in protocol.ts directly; see licenserail-youtrack.

/** Key-value storage for the token and the last-run time (e.g. chrome.storage, localStorage, a settings store). */
export interface LicenseStorage {
  get(key: string): Promise<string | null> | string | null
  set(key: string, value: string): Promise<void> | void
  remove(key: string): Promise<void> | void
}

/** Sends a request description; returns the status (0 on network failure) and the body text. */
export type Transport = (request: HttpRequestDescription) => Promise<{ status: number; body: string }>

export interface ClientOptions {
  apiUrl: string
  /** The environment's public key (PEM) from the dashboard. Not a secret. */
  publicKeyPem: string
  product: string
  /** The device or installation (see installationFingerprint). */
  fingerprint: Fingerprint
  storage: LicenseStorage
  transport?: Transport
  machineName?: string
  appVersion?: string
  /** The host's current number of users, if the license is priced per host user. */
  hostUsers?: () => number | undefined
  now?: () => Date
  /** Request timeout in milliseconds for the built-in transport (default 10 s). */
  timeoutMs?: number
  /** Storage key prefix (default "licenserail:"). */
  prefix?: string
}

export interface LicenseState {
  status: LicenseStatus
  payload: LicensePayload | null
  summary: LicenseSummary | null
}

export type ActionResult = { ok: true; state: LicenseState } | { ok: false; code: string; message: string; state: LicenseState }

type FetchLike = (url: string, init: object) => Promise<{ status: number; text(): Promise<string> }>

interface HostGlobals {
  fetch?: FetchLike
  AbortController?: new () => { signal: unknown; abort(): void }
  setTimeout?: (f: () => void, ms: number) => unknown
  clearTimeout?: (timer: unknown) => void
}

const fetchTransport = (timeoutMs: number): Transport => async (r) => {
  const host = globalThis as HostGlobals
  if (!host.fetch) return { status: 0, body: '' }
  // Hosts without timers or AbortController rely on their own request timeout.
  const controller = host.AbortController && host.setTimeout ? new host.AbortController() : null
  const timer = controller ? host.setTimeout!(() => controller.abort(), timeoutMs) : null
  try {
    const res = await host.fetch(r.url, { method: r.method, headers: r.headers, body: r.body, ...(controller ? { signal: controller.signal } : {}) })
    return { status: res.status, body: await res.text() }
  } catch {
    return { status: 0, body: '' }
  } finally {
    if (timer !== null) host.clearTimeout?.(timer)
  }
}

export function createLicenseClient(o: ClientOptions) {
  const send = o.transport ?? fetchTransport(o.timeoutMs ?? 10_000)
  const now = () => (o.now ? o.now() : new Date())
  const key = (k: string) => (o.prefix ?? 'licenserail:') + k
  const target = { apiUrl: o.apiUrl, product: o.product, fingerprint: o.fingerprint }

  async function load(): Promise<{ token: string | null; lastSeen: Date | null }> {
    const token = await o.storage.get(key('token'))
    const seen = await o.storage.get(key('lastSeen'))
    return { token, lastSeen: seen ? new Date(Number(seen)) : null }
  }

  async function state(): Promise<LicenseState> {
    const { token, lastSeen } = await load()
    if (!token) return { status: 'Missing', payload: null, summary: null }
    const payload = await verifyTokenAsync(token, o.publicKeyPem)
    const status = evaluate(payload, o.product, o.fingerprint, now(), lastSeen)
    if (status === 'Valid') await o.storage.set(key('lastSeen'), String(now().getTime()))
    return { status, payload, summary: payload ? summarize(payload, o.hostUsers?.()) : null }
  }

  /** Set when a license for this device or installation would never match it again: activating would only use up a seat. */
  async function unidentified(): Promise<ActionResult | null> {
    if (fingerprintMatches(o.fingerprint, o.fingerprint)) return null
    return { ok: false, code: 'device_not_identified', message: "This device can't be identified, so a license can't be activated on it.", state: await state() }
  }

  async function accept(response: { status: number; body: string }): Promise<ActionResult> {
    const r = readResponse(response.status, response.body)
    if (r.ok && r.token) {
      const payload = await verifyTokenAsync(r.token, o.publicKeyPem)
      if (!payload) return { ok: false, code: 'invalid_token', message: 'The license server returned a token that does not verify.', state: await state() }
      await o.storage.set(key('token'), r.token)
      await o.storage.set(key('lastSeen'), String(now().getTime()))
      return { ok: true, state: await state() }
    }
    if (!r.ok) {
      if (r.revokesLocalLicense) await o.storage.remove(key('token'))
      return { ok: false, code: r.code, message: r.message, state: await state() }
    }
    return { ok: true, state: await state() }
  }

  return {
    /** The current license, checked offline. */
    state,

    /** Activates a license key on this device or installation. */
    async activate(licenseKey: string, floating = false): Promise<ActionResult> {
      return (await unidentified()) ?? accept(await send(activateRequest({
        ...target, licenseKey, machineName: o.machineName, appVersion: o.appVersion, hostUsers: o.hostUsers?.(), floating,
      })))
    },

    /** Starts (or gets back) this device's or installation's keyless trial. */
    async startTrial(keyId: string): Promise<ActionResult> {
      return (await unidentified()) ?? accept(await send(trialRequest({ ...target, keyId, machineName: o.machineName, appVersion: o.appVersion, hostUsers: o.hostUsers?.() })))
    },

    /** Refreshes when the token asks for it (or always with force); keeps the token on network errors. */
    async refresh(force = false): Promise<ActionResult> {
      const { token } = await load()
      const current = await state()
      if (!token || !current.payload) return { ok: false, code: 'no_license', message: 'No license to refresh.', state: current }
      const due = refreshDueAt(current.payload)
      if (!force && (!due || due.getTime() > now().getTime())) return { ok: true, state: current }
      return accept(await send(refreshRequest({
        ...target, token, appVersion: o.appVersion, hostUsers: o.hostUsers?.(), floating: current.payload.floating === true,
      })))
    },

    /** Releases the license on this device or installation and removes it locally. */
    async deactivate(): Promise<ActionResult> {
      const { token } = await load()
      const current = await state()
      if (!token || !current.payload || current.payload.trial) {
        await o.storage.remove(key('token'))
        return { ok: true, state: await state() }
      }
      const res = await send(deactivateRequest({ ...target, token, floating: current.payload.floating === true }))
      const r = readResponse(res.status, res.body)
      if (r.ok || r.revokesLocalLicense) {
        await o.storage.remove(key('token'))
        return { ok: true, state: await state() }
      }
      return { ok: false, code: r.code, message: r.message, state: current }
    },
  }
}

export type LicenseClient = ReturnType<typeof createLicenseClient>
