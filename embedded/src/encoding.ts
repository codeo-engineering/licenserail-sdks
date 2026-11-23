// Byte helpers that work without TextEncoder, TextDecoder, atob or Buffer (sandboxed hosts such as YouTrack apps lack them).

export type Bytes = number[]

/** UTF-8 bytes of a string (surrogate pairs combined). */
export function utf8Encode(text: string): Bytes {
  const out: Bytes = []
  for (let i = 0; i < text.length; i++) {
    let c = text.charCodeAt(i)
    if (c >= 0xd800 && c < 0xdc00 && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1)
      if (d >= 0xdc00 && d < 0xe000) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++ }
    }
    if (c < 0x80) out.push(c)
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
  }
  return out
}

/** Decodes UTF-8; invalid sequences become U+FFFD. */
export function utf8Decode(bytes: ArrayLike<number>): string {
  let out = ''
  for (let i = 0; i < bytes.length;) {
    const b = bytes[i]
    let cp = 0xfffd, len = 1
    if (b < 0x80) { cp = b }
    else if (b >= 0xc2 && b < 0xe0 && cont(bytes, i + 1)) { cp = ((b & 31) << 6) | (bytes[i + 1] & 63); len = 2 }
    else if (b >= 0xe0 && b < 0xf0 && cont(bytes, i + 1) && cont(bytes, i + 2)) {
      const v = ((b & 15) << 12) | ((bytes[i + 1] & 63) << 6) | (bytes[i + 2] & 63)
      if (v >= 0x800 && (v < 0xd800 || v > 0xdfff)) { cp = v; len = 3 }
    } else if (b >= 0xf0 && b < 0xf5 && cont(bytes, i + 1) && cont(bytes, i + 2) && cont(bytes, i + 3)) {
      const v = ((b & 7) << 18) | ((bytes[i + 1] & 63) << 12) | ((bytes[i + 2] & 63) << 6) | (bytes[i + 3] & 63)
      if (v >= 0x10000 && v <= 0x10ffff) { cp = v; len = 4 }
    }
    if (cp > 0xffff) { cp -= 0x10000; out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 1023)) }
    else out += String.fromCharCode(cp)
    i += len
  }
  return out
}

function cont(bytes: ArrayLike<number>, i: number): boolean {
  return i < bytes.length && (bytes[i] & 0xc0) === 0x80
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** Decodes base64 or base64url (padding and whitespace ignored). Returns null on any other character. */
export function base64Decode(text: string): Bytes | null {
  const s = text.replace(/[\s=]/g, '').replace(/-/g, '+').replace(/_/g, '/')
  const out: Bytes = []
  let acc = 0, bits = 0
  for (let i = 0; i < s.length; i++) {
    const v = B64.indexOf(s.charAt(i))
    if (v < 0) return null
    acc = ((acc << 6) | v) & 0xffffff
    bits += 6
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255) }
  }
  return out
}

export function hex(bytes: ArrayLike<number>): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16)
  return out
}
