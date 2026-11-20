/**
 * Server-side client for the management API (/api/v2). Needs a secret API key: never ship it in an app.
 * Every operation of /openapi.json is reachable through `request`; the common ones have typed helpers.
 */
export interface ManagementOptions {
  apiKey: string
  baseUrl?: string
  /** For access tokens (not API keys): "test" (default) or "live". */
  environment?: 'test' | 'live'
  fetch?: typeof fetch
}

export class ApiRequestError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly body: unknown) {
    super(message)
  }
}

export class ManagementClient {
  private readonly base: string

  constructor(private readonly options: ManagementOptions) {
    this.base = (options.baseUrl ?? 'https://api.licenserail.com').replace(/\/+$/, '')
  }

  async request<T = any>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const h: Record<string, string> = { Authorization: `Bearer ${this.options.apiKey}`, ...headers }
    if (this.options.environment) h['X-Environment'] = this.options.environment
    if (body !== undefined) h['Content-Type'] = 'application/json'
    if (method !== 'GET' && !h['Idempotency-Key']) h['Idempotency-Key'] = crypto.randomUUID()
    const res = await (this.options.fetch ?? fetch)(`${this.base}/api/v2${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) })
    const text = await res.text()
    const json = text ? JSON.parse(text) : undefined
    if (!res.ok) throw new ApiRequestError(res.status, json?.error?.code ?? 'error', json?.error?.message ?? `HTTP ${res.status}`, json)
    return json as T
  }

  createProduct = (body: { code: string; name: string; offlineGraceDays?: number; metadata?: Record<string, unknown> }) => this.request('POST', '/products', body)
  listProducts = () => this.request('GET', '/products')
  createCustomer = (body: { name: string; email?: string; contactName?: string; metadata?: Record<string, unknown> }) => this.request('POST', '/customers', body)
  createLicenses = (body: {
    productId: string; customerId: string; kind?: 'full' | 'trial'; expiresAt?: string | null; maxActivations?: number; isFloating?: boolean
    leaseMinutes?: number; features?: string[]; metadata?: Record<string, unknown>; quantity?: number; licensee?: string; notes?: string
  }) => this.request('POST', '/licenses', body)
  getLicense = (id: string) => this.request('GET', `/licenses/${id}`)
  updateLicense = (id: string, patch: Record<string, unknown>) => this.request('PATCH', `/licenses/${id}`, patch)
  suspendLicense = (id: string) => this.request('POST', `/licenses/${id}/suspend`)
  resumeLicense = (id: string) => this.request('POST', `/licenses/${id}/resume`)
  revokeLicense = (id: string, approvalId?: string) => this.request('POST', `/licenses/${id}/revoke`, undefined, approvalId ? { 'Approval-Id': approvalId } : {})
  listEvents = (type?: string) => this.request('GET', `/events${type ? `?type=${encodeURIComponent(type)}` : ''}`)
}

/** Verifies a Standard Webhooks signature (webhook-id, webhook-timestamp, webhook-signature) with the endpoint secret. */
export async function verifyWebhook(secret: string, headers: Record<string, string | undefined>, body: string, toleranceSeconds = 300): Promise<boolean> {
  const { createHmac, timingSafeEqual } = await import('node:crypto')
  const id = headers['webhook-id'], ts = headers['webhook-timestamp'], sig = headers['webhook-signature']
  if (!id || !ts || !sig) return false
  if (Math.abs(Date.now() / 1000 - Number(ts)) > toleranceSeconds) return false
  const key = Buffer.from(secret.startsWith('whsec_') ? secret.slice(6) : secret, 'base64')
  const expected = Buffer.from(createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64'))
  return sig.split(' ').some((s) => {
    const v = Buffer.from(s.startsWith('v1,') ? s.slice(3) : '')
    return v.length === expected.length && timingSafeEqual(v, expected)
  })
}
