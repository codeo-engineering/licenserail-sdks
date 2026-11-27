// LicenseRail License page (administration menu). Talks to the app's own "licenserail-license" handler; the license key
// itself is entered in the app's settings (a secret setting the page can't read).

const host = await YTApp.register()
const $ = (id) => document.getElementById(id)
const HANDLER = 'licenserail-license'

let installationId = null
try {
  installationId = (await host.fetchYouTrack('config?fields=uuid', { method: 'GET' })).uuid ?? null
} catch {
  installationId = null
}

/** Where this YouTrack is reached, as the browser sees it (the page runs inside it); LicenseRail checks the instance there. */
function baseUrls() {
  const seen = []
  const add = (value) => {
    try {
      const origin = new URL(value).origin
      if (/^https?:/.test(origin) && !seen.includes(origin)) seen.push(origin)
    } catch { /* not a URL */ }
  }
  if (window.location.ancestorOrigins?.length) add(window.location.ancestorOrigins[window.location.ancestorOrigins.length - 1])
  if (document.referrer) add(document.referrer)
  add(window.location.href)
  return seen.slice(0, 3)
}

async function call(path, method = 'GET') {
  return host.fetchApp(`${HANDLER}/${path}`, method === 'GET' ? { method } : { method, body: { installationId, baseUrls: baseUrls() } })
}

const LABELS = {
  Valid: 'Licensed',
  Missing: 'Not activated',
  Expired: 'Expired',
  OfflineTooLong: 'Not verified for too long',
  WrongMachine: 'Activated for another YouTrack instance',
  Suspended: 'Suspended',
  ClockTampered: 'The server clock looks wrong',
  Unverified: 'Waiting for the first check',
  InvalidSignature: 'Invalid license data',
  WrongProduct: 'The license is for another app',
}

function render(s) {
  const lines = []
  const label = s.valid && s.isTrial ? 'Trial' : (LABELS[s.status] ?? s.status)
  lines.push(`<p class="state ${s.valid ? 'ok' : 'bad'}">${label}${s.isTest ? ' (test)' : ''}</p>`)
  if (s.expiresAt) lines.push(`<p>${s.valid ? 'Valid until' : 'Ended'} ${new Date(s.expiresAt).toLocaleDateString()}</p>`)
  if (s.maxHostUsers !== null) {
    lines.push(`<p${s.hostUsersOverLimit ? ' class="warn"' : ''}>Users: ${s.hostUsers ?? '?'} of ${s.maxHostUsers} allowed</p>`)
  }
  if (s.pending) lines.push('<p class="muted">Contacting the license server…</p>')
  if (s.lastError) lines.push(`<p class="bad">${escapeHtml(s.lastError.message)}</p>`)
  $('status').innerHTML = lines.join('')
  $('key-hint').textContent = s.keyConfigured
    ? 'A license key is set in this app\'s settings.'
    : 'Enter the license key in this app\'s settings (Administration → Apps → this app → Settings), then activate.'
  $('activate').disabled = !s.keyConfigured || !installationId || !!s.pending
  $('refresh').disabled = s.status === 'Missing' || s.isTrial || !!s.pending
  $('deactivate').disabled = s.status === 'Missing' || !!s.pending
  $('trial-card').hidden = (s.valid && !s.isTrial) || s.isTrial
  $('trial').disabled = !installationId || !!s.pending
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

async function load() {
  try {
    const s = await call('status')
    render(s)
    return s
  } catch (e) {
    $('status').textContent = 'The license status could not be loaded.'
    return null
  }
}

async function act(path, done) {
  $('message').textContent = ''
  try {
    render(await call(path, 'POST'))
  } catch (e) {
    $('message').textContent = e?.message ?? 'The request failed.'
    return
  }
  // The license server answers asynchronously: poll until the pending request is finished (up to 30 s).
  for (let i = 0; i < 15; i++) {
    await new Promise((r) => setTimeout(r, 2000))
    const s = await load()
    if (s && !s.pending) {
      $('message').textContent = s.lastError ? '' : done
      return
    }
  }
}

$('activate').onclick = () => act('activate', 'The license is active.')
$('trial').onclick = () => act('trial', 'The trial has started.')
$('refresh').onclick = () => act('refresh', 'The license was checked.')
$('deactivate').onclick = () => act('deactivate', 'This instance no longer uses the license.')

if (!installationId) $('message').textContent = 'This YouTrack instance\'s id could not be read; activation is unavailable.'
await load()
