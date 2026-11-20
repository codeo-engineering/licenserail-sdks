import type { KeyObject } from 'node:crypto'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, hostname, platform } from 'node:os'
import { join } from 'node:path'
import {
  decodeRunHistory,
  encodeRunHistory,
  evaluate,
  importPublicKey,
  REVOKING_CODES,
  verifyToken,
  type Fingerprint,
  type LicensePayload,
  type LicenseStatus,
} from './core.js'
import { collectFingerprint } from './fingerprint.js'

export interface LicenseClientOptions {
  /** Base URL of the licensing service, e.g. https://api.licenserail.com */
  serverUrl: string
  /** The product code from the dashboard. */
  product: string
  /** Your organization's slug from the dashboard (fixed for life; part of every device identity). */
  vendor: string
  /** The environment's public key (PEM); verifies license files offline. */
  publicKeyPem: string
  /** Where the license file and run history live; default: a per-user folder. */
  storageDir?: string
  appVersion?: string
  /** Refresh online on every check() (default false: only when the token says it is due). */
  refreshOnStartup?: boolean
  /** Request timeout in milliseconds (default 10 s). */
  timeoutMs?: number
  /** Overrides device fingerprinting (tests, custom hardware ids). */
  fingerprint?: () => Fingerprint
  /** Overrides the clock (tests). */
  now?: () => Date
  /** Overrides fetch (tests, proxies). */
  fetch?: typeof fetch
  machineName?: string
}

export interface ActivationResult {
  success: boolean
  errorCode?: string
  message: string
}

export interface CheckResult {
  status: LicenseStatus
  valid: boolean
  license: License | null
}

/** Read-only view of the current license. */
export class License {
  constructor(readonly payload: LicensePayload) {}
  get key() { return this.payload.licenseKey }
  get customer() { return this.payload.customer }
  get kind() { return this.payload.kind }
  get expiresAt(): Date | null { return this.payload.expiresAt ? new Date(this.payload.expiresAt) : null }
  get offlineUntil(): Date { return new Date(this.payload.offlineUntil) }
  get isTest() { return this.payload.test === true }
  get isFloating() { return this.payload.floating === true }
  get features(): string[] { return this.payload.entitlements ?? [] }
  get metadata(): Record<string, unknown> { return this.payload.metadata ?? {} }
  hasFeature(code: string): boolean { return this.features.includes(code) }
}

const messages: Record<LicenseStatus, string> = {
  Valid: 'The license is valid.',
  Missing: 'No license is activated on this device.',
  InvalidSignature: 'The license file is invalid. Activate it again.',
  WrongProduct: 'The license is for another product.',
  WrongMachine: 'The license belongs to another device.',
  Expired: 'The license has expired.',
  OfflineTooLong: 'Connect to the internet to verify the license.',
  ClockTampered: "The device's clock looks wrong. Correct it and connect to the internet.",
  Unverified: 'Connect to the internet to verify the license.',
  Suspended: 'The license has been suspended.',
}

/**
 * The licensing client for a vendor's app: offline verification on every start, online refresh when due, activation,
 * deactivation and floating leases. Never put an API key in client code; this class needs only the public key.
 */
export class LicenseClient {
  private readonly options: Required<Pick<LicenseClientOptions, 'serverUrl' | 'vendor' | 'product' | 'timeoutMs'>> & LicenseClientOptions
  private readonly key: KeyObject
  private readonly dir: string
  private fp: Fingerprint | null = null
  private heartbeat: ReturnType<typeof setInterval> | null = null
  private warnedTest = false
  /** The last message from the server (e.g. why a license was removed). */
  lastServerMessage: string | null = null

  constructor(options: LicenseClientOptions) {
    if (!options.serverUrl || !options.vendor || !options.product || !options.publicKeyPem)
      throw new Error('serverUrl, vendor, product and publicKeyPem are required.')
    this.options = { timeoutMs: 10_000, ...options, serverUrl: options.serverUrl.replace(/\/+$/, '') }
    this.key = importPublicKey(options.publicKeyPem)
    this.dir = options.storageDir ?? defaultStorageDir(options.product)
  }

  private now(): Date { return this.options.now?.() ?? new Date() }
  private fingerprint(): Fingerprint { return (this.fp ??= this.options.fingerprint?.() ?? collectFingerprint(this.options.vendor, this.options.product)) }
  private get tokenPath() { return join(this.dir, 'license.lic') }
  private get historyPath() { return join(this.dir, 'license.seen') }

  /** The current license after the last check, or null. */
  get license(): License | null {
    const p = this.readPayload()
    return p ? new License(p) : null
  }

  /** Offline evaluation only (no network). */
  evaluateLocal(): CheckResult {
    const token = this.read(this.tokenPath)
    if (!token) return { status: 'Missing', valid: false, license: null }
    const payload = verifyToken(token, this.key)
    const lastSeen = decodeRunHistory(this.read(this.historyPath), this.options.vendor, this.options.product, this.fingerprint())
    const now = this.now()
    const status = evaluate(payload, this.options.product, this.fingerprint(), now, lastSeen)
    if ((status === 'Valid' || status === 'Expired' || status === 'OfflineTooLong') && (!lastSeen || now > lastSeen))
      this.write(this.historyPath, encodeRunHistory(now, this.options.vendor, this.options.product, this.fingerprint()))
    if (payload?.test && !this.warnedTest) {
      this.warnedTest = true
      console.warn('[licenserail] Test license: not for production use.')
    }
    return { status, valid: status === 'Valid', license: payload ? new License(payload) : null }
  }

  /** Call on startup: evaluates offline and refreshes online when due or when only the server can clear the state. */
  async check(): Promise<CheckResult> {
    let result = this.evaluateLocal()
    const due = result.valid && (this.options.refreshOnStartup || this.now() >= new Date(result.license!.payload.refreshAfter))
    if (due || ['Expired', 'Suspended', 'OfflineTooLong', 'ClockTampered', 'Unverified'].includes(result.status)) {
      try {
        await this.refresh(result.status === 'ClockTampered' ? ['clock_rollback'] : result.status === 'Unverified' ? ['history_missing'] : undefined)
      } catch {
        // offline: the local result stands until offlineUntil
      }
      result = this.evaluateLocal()
    }
    return result
  }

  /** Activates `licenseKey` on this device (or checks out a floating lease if the license is floating). */
  async activate(licenseKey: string, machineName?: string): Promise<ActivationResult> {
    if (!licenseKey?.trim()) return { success: false, errorCode: 'bad_request', message: 'Enter the license key.' }
    const body = {
      licenseKey: licenseKey.trim(), product: this.options.product, fingerprint: this.fingerprint(),
      machineName: machineName ?? this.options.machineName ?? hostname(), appVersion: this.options.appVersion ?? null,
    }
    let r = await this.post('/api/client/v2/activate', body).catch(() => null)
    if (r && !r.ok && r.error?.code === 'bad_request' && /floating/i.test(r.error.message)) r = await this.post('/api/client/v2/floating/checkout', body).catch(() => null)
    if (!r) return { success: false, errorCode: 'network', message: 'Could not connect to the license server.' }
    if (!r.ok) return { success: false, errorCode: r.error?.code, message: r.error?.message ?? `Server error (${r.status}).` }
    if (!this.saveIfValid(r.token!)) return { success: false, errorCode: 'invalid_token', message: 'The server returned an invalid license.' }
    const result = this.evaluateLocal()
    if (result.license?.isFloating) this.startHeartbeat()
    return result.valid ? { success: true, message: 'The license has been activated.' } : { success: false, errorCode: result.status, message: messages[result.status] }
  }

  /** Checks out a floating seat and keeps it alive with heartbeats until release(). */
  async checkout(licenseKey: string): Promise<ActivationResult> {
    const body = { licenseKey: licenseKey.trim(), product: this.options.product, fingerprint: this.fingerprint(), machineName: this.options.machineName ?? hostname(), appVersion: this.options.appVersion ?? null }
    const r = await this.post('/api/client/v2/floating/checkout', body).catch(() => null)
    if (!r) return { success: false, errorCode: 'network', message: 'Could not connect to the license server.' }
    if (!r.ok) return { success: false, errorCode: r.error?.code, message: r.error?.message ?? `Server error (${r.status}).` }
    this.saveIfValid(r.token!)
    this.startHeartbeat()
    return { success: true, message: 'Floating license checked out.' }
  }

  /** Releases a floating seat. */
  async release(): Promise<ActivationResult> {
    this.stopHeartbeat()
    return this.deactivate()
  }

  /** Removes the license from this device and frees its seat on the server. */
  async deactivate(): Promise<ActivationResult> {
    this.stopHeartbeat()
    const token = this.read(this.tokenPath)
    if (!token) return { success: true, message: 'There is no license on this device.' }
    const floating = verifyToken(token, this.key)?.floating === true
    const r = await this.post(floating ? '/api/client/v2/floating/release' : '/api/client/v2/deactivate', { token, fingerprint: this.fingerprint() }).catch(() => null)
    if (!r) return { success: false, errorCode: 'network', message: 'Removing the license needs an internet connection.' }
    if (!r.ok && !(r.error && REVOKING_CODES.has(r.error.code)))
      return { success: false, errorCode: r.error?.code, message: r.error?.message ?? `Server error (${r.status}).` }
    this.clear()
    return r.ok || r.error?.code !== 'wrong_machine'
      ? { success: true, message: 'The license has been removed from this device.' }
      : { success: false, errorCode: 'wrong_machine', message: r.error!.message }
  }

  /** Asks the server for a fresh token now (floating licenses: a heartbeat). */
  async refresh(anomalies?: string[]): Promise<void> {
    const token = this.read(this.tokenPath)
    if (!token) return
    const floating = verifyToken(token, this.key)?.floating === true
    const r = await this.post(floating ? '/api/client/v2/floating/heartbeat' : '/api/client/v2/refresh',
      { token, fingerprint: this.fingerprint(), appVersion: this.options.appVersion ?? null, anomalies: anomalies ?? null })
    if (r.ok) this.saveIfValid(r.token!)
    else if (r.error && REVOKING_CODES.has(r.error.code)) {
      this.clear()
      this.lastServerMessage = r.error.message
    } else if (r.error?.code === 'lease_expired') {
      this.clear()
      this.lastServerMessage = r.error.message
    }
  }

  /** A user-facing sentence for a status. */
  message(status: LicenseStatus): string {
    return status === 'Missing' && this.lastServerMessage ? this.lastServerMessage : messages[status]
  }

  private startHeartbeat() {
    this.stopHeartbeat()
    const payload = this.readPayload()
    if (!payload?.floating) return
    const half = Math.max(30_000, (Date.parse(payload.offlineUntil) - Date.parse(payload.issuedAt)) / 2)
    this.heartbeat = setInterval(() => void this.refresh().catch(() => undefined), half)
    this.heartbeat.unref?.()
  }

  private stopHeartbeat() {
    if (this.heartbeat) clearInterval(this.heartbeat)
    this.heartbeat = null
  }

  private async post(path: string, body: unknown): Promise<{ ok: boolean; status: number; token?: string; error?: { code: string; message: string } }> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs)
    try {
      const res = await (this.options.fetch ?? fetch)(this.options.serverUrl + path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: controller.signal,
      })
      const text = await res.text()
      const json = text ? JSON.parse(text) : {}
      return res.ok ? { ok: true, status: res.status, token: json.token } : { ok: false, status: res.status, error: json.code ? json : undefined }
    } finally {
      clearTimeout(timer)
    }
  }

  private saveIfValid(token: string): boolean {
    const payload = verifyToken(token, this.key)
    if (!payload || payload.product.toLowerCase() !== this.options.product.toLowerCase()) return false
    this.write(this.tokenPath, token)
    this.write(this.historyPath, encodeRunHistory(this.now(), this.options.vendor, this.options.product, this.fingerprint()))
    return true
  }

  private readPayload(): LicensePayload | null {
    const token = this.read(this.tokenPath)
    return token ? verifyToken(token, this.key) : null
  }

  private clear() {
    for (const p of [this.tokenPath]) rmSync(p, { force: true })
  }

  private read(path: string): string | null {
    try { return readFileSync(path, 'utf8').trim() || null } catch { return null }
  }

  private write(path: string, value: string) {
    mkdirSync(this.dir, { recursive: true })
    writeFileSync(path, value, 'utf8')
  }
}

function defaultStorageDir(product: string): string {
  const base = platform() === 'win32'
    ? process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local')
    : platform() === 'darwin'
      ? join(homedir(), 'Library', 'Application Support')
      : process.env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share')
  return join(base, 'licenserail', product)
}
