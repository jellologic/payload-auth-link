import { createHmac } from 'node:crypto'

/**
 * RFC 6238 TOTP (SHA-1, 30s step, 6 digits) for a base32 secret, as
 * authenticator apps compute it. `stepOffset` shifts the time step
 * (e.g. -1 / +1 for the neighbors a verifier's skew window accepts).
 * Dynamic truncation (RFC 4226 §5.3) masks ONLY the first byte with
 * 0x7f; the other three are taken whole.
 */
export function totp(base32Secret: string, stepOffset = 0): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of base32Secret.replaceAll('=', '').toUpperCase()) {
    const value = alphabet.indexOf(char)
    if (value < 0) {
      throw new Error(`not a base32 secret (bad character '${char}')`)
    }
    bits += value.toString(2).padStart(5, '0')
  }
  const keyBytes: number[] = []
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    keyBytes.push(Number.parseInt(bits.slice(index, index + 8), 2))
  }
  const counterBuffer = Buffer.alloc(8)
  counterBuffer.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30) + stepOffset))
  const digest = createHmac('sha1', Buffer.from(keyBytes)).update(counterBuffer).digest()
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f
  const binary =
    ((digest[offset] ?? 0) & 0x7f) * 2 ** 24 +
    (digest[offset + 1] ?? 0) * 2 ** 16 +
    (digest[offset + 2] ?? 0) * 2 ** 8 +
    (digest[offset + 3] ?? 0)
  return String(binary % 1_000_000).padStart(6, '0')
}

/**
 * A six-digit code no skew-tolerant verifier accepts right now: it
 * differs from the codes of the previous, current, and next steps.
 */
export function wrongTotp(base32Secret: string): string {
  const valid = new Set([-1, 0, 1].map((step) => totp(base32Secret, step)))
  let candidate = Number(totp(base32Secret))
  do {
    candidate = (candidate + 1) % 1_000_000
  } while (valid.has(String(candidate).padStart(6, '0')))
  return String(candidate).padStart(6, '0')
}
