import { base64Decode, type Bytes } from './encoding.js'
import { sha256 } from './sha256.js'

// ECDSA P-256 / SHA-256 signature verification with BigInt (ES2020), for hosts without crypto.subtle.
// Verify-only: no secret data is involved, so constant-time arithmetic is not needed. Checked against the Wycheproof
// ecdsa_secp256r1_sha256_p1363 vectors (test/wycheproof.test.mjs).

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn

interface Point { x: bigint; y: bigint; z: bigint }   // Jacobian coordinates; z = 0 is the point at infinity

const G: Point = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  z: 1n,
}
const INFINITY: Point = { x: 0n, y: 1n, z: 0n }

function toInt(bytes: ArrayLike<number>): bigint {
  let r = 0n
  for (let i = 0; i < bytes.length; i++) r = (r << 8n) | BigInt(bytes[i])
  return r
}

function mod(a: bigint, m: bigint): bigint {
  const r = a % m
  return r < 0n ? r + m : r
}

function pow(a: bigint, e: bigint, m: bigint): bigint {
  let r = 1n
  a = mod(a, m)
  while (e > 0n) {
    if (e & 1n) r = (r * a) % m
    a = (a * a) % m
    e >>= 1n
  }
  return r
}

const invert = (a: bigint, m: bigint) => pow(a, m - 2n, m)   // m is prime

// Curve a = -3.
function double(p: Point): Point {
  if (p.z === 0n || p.y === 0n) return INFINITY
  const delta = (p.z * p.z) % P, gamma = (p.y * p.y) % P, beta = (p.x * gamma) % P
  const alpha = (3n * mod(p.x - delta, P) * (p.x + delta)) % P
  const x = mod(alpha * alpha - 8n * beta, P)
  const z = mod((p.y + p.z) * (p.y + p.z) - gamma - delta, P)
  const y = mod(alpha * (4n * beta - x) - 8n * gamma * gamma, P)
  return { x, y, z }
}

function add(p: Point, q: Point): Point {
  if (p.z === 0n) return q
  if (q.z === 0n) return p
  const z1z1 = (p.z * p.z) % P, z2z2 = (q.z * q.z) % P
  const u1 = (p.x * z2z2) % P, u2 = (q.x * z1z1) % P
  const s1 = (((p.y * q.z) % P) * z2z2) % P, s2 = (((q.y * p.z) % P) * z1z1) % P
  const h = mod(u2 - u1, P), r = mod(s2 - s1, P)
  if (h === 0n) return r === 0n ? double(p) : INFINITY
  const hh = (h * h) % P, hhh = (hh * h) % P, v = (u1 * hh) % P
  const x = mod(r * r - hhh - 2n * v, P)
  const y = mod(r * (v - x) - s1 * hhh, P)
  return { x, y, z: (((p.z * q.z) % P) * h) % P }
}

/** u1·G + u2·Q in one pass (Shamir's trick). */
function mulAdd(u1: bigint, u2: bigint, q: Point): Point {
  const gq = add(G, q)
  let r = INFINITY
  for (let i = 255; i >= 0; i--) {
    r = double(r)
    const b1 = (u1 >> BigInt(i)) & 1n, b2 = (u2 >> BigInt(i)) & 1n
    if (b1 && b2) r = add(r, gq)
    else if (b1) r = add(r, G)
    else if (b2) r = add(r, q)
  }
  return r
}

// An uncompressed P-256 SubjectPublicKeyInfo is always 91 bytes: this fixed header, 0x04, X (32), Y (32).
const SPKI_HEADER = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0x03, 0x42, 0x00]

/** The public point of a PEM (SPKI) P-256 key, or null if it is anything else. */
export function parsePublicKey(pem: string): { x: Bytes; y: Bytes } | null {
  const der = base64Decode(pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, ''))
  if (!der || der.length !== 91 || der[26] !== 0x04) return null
  for (let i = 0; i < SPKI_HEADER.length; i++) if (der[i] !== SPKI_HEADER[i]) return null
  return { x: der.slice(27, 59), y: der.slice(59, 91) }
}

/** Verifies an IEEE P1363 (r || s, 64 bytes) ECDSA P-256 SHA-256 signature over `data`. */
export function verifyP256(publicKeyPem: string, data: ArrayLike<number>, signature: ArrayLike<number>): boolean {
  const key = parsePublicKey(publicKeyPem)
  if (!key || signature.length !== 64) return false
  const qx = toInt(key.x), qy = toInt(key.y)
  if (qx >= P || qy >= P || mod(qy * qy - (qx * qx * qx - 3n * qx + B), P) !== 0n) return false   // on the curve
  const sig = Array.prototype.slice.call(signature) as number[]
  const r = toInt(sig.slice(0, 32)), s = toInt(sig.slice(32, 64))
  if (r < 1n || r >= N || s < 1n || s >= N) return false
  const e = toInt(sha256(data))   // a 256-bit hash needs no truncation for P-256
  const w = invert(s, N)
  const point = mulAdd((e * w) % N, (r * w) % N, { x: qx, y: qy, z: 1n })
  if (point.z === 0n) return false
  const zi = invert(point.z, P)
  const x = (((point.x * zi) % P) * zi) % P
  return x % N === r
}
