/**
 * Property tests for the identity normalisation smart constructors
 * (issue #86): `parseEmail` (the one place raw input becomes an
 * `Email`), `parseRole` (the one canonical `Role`), and the SSO
 * domain policy built on top of them. Email identity is the linking
 * key, so a normalisation that is not idempotent or not
 * case-insensitive would let two spellings of one address resolve
 * to different users.
 */
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { emailDomainAllowed, emailDomainOf } from '../policies.js'
import { parseEmail } from '../email.js'
import { parseRole } from '../roles.js'

const runs = { numRuns: 200 } as const

/** Mixed-case ASCII emails the boundary schema accepts. */
const asciiLabel = fc.stringMatching(/^[A-Za-z0-9]([A-Za-z0-9-]{0,10}[A-Za-z0-9])?$/)
const emailArb = fc
  .tuple(
    fc.stringMatching(/^[A-Za-z0-9]([A-Za-z0-9._+-]{0,14}[A-Za-z0-9])?$/),
    fc.array(asciiLabel, { minLength: 1, maxLength: 3 }),
    fc.stringMatching(/^[A-Za-z]{2,6}$/)
  )
  .filter(([local]) => !local.includes('..'))
  .map(([local, labels, tld]) => `${local}@${[...labels, tld].join('.')}`)

/** Flip the case of a random subset of characters. */
const recase = (value: string, mask: readonly boolean[]): string =>
  [...value]
    .map((char, index) => (mask[index % mask.length] === true ? char.toUpperCase() : char))
    .join('')

describe('parseEmail (property)', () => {
  it('accepts generated well-formed addresses and lowercases them', () => {
    fc.assert(
      fc.property(emailArb, (raw) => {
        const parsed = parseEmail(raw)
        expect(parsed.isOk()).toBe(true)
        if (parsed.isOk()) {
          expect(parsed.value).toBe(raw.toLowerCase())
        }
      }),
      runs
    )
  })

  it('is idempotent: parse(parse(x)) === parse(x)', () => {
    fc.assert(
      fc.property(emailArb, (raw) => {
        const once = parseEmail(raw)
        if (once.isErr()) {
          return
        }
        const twice = parseEmail(once.value)
        expect(twice.isOk() && twice.value).toBe(once.value)
      }),
      runs
    )
  })

  it('is case-insensitive: every recasing normalises to the same Email', () => {
    fc.assert(
      fc.property(emailArb, fc.array(fc.boolean(), { minLength: 1 }), (raw, mask) => {
        const left = parseEmail(raw)
        const right = parseEmail(recase(raw, mask))
        expect(left.isOk()).toBe(right.isOk())
        if (left.isOk() && right.isOk()) {
          expect(right.value).toBe(left.value)
        }
      }),
      runs
    )
  })

  it('never throws on arbitrary input: invalid values are Err', () => {
    fc.assert(
      fc.property(fc.anything(), (value) => {
        const parsed = parseEmail(value)
        if (parsed.isOk()) {
          // Anything accepted is already canonical.
          expect(typeof parsed.value).toBe('string')
          expect(parsed.value).toBe(parsed.value.toLowerCase())
          expect(parsed.value.length).toBeLessThanOrEqual(320)
        }
      }),
      runs
    )
  })

  it('rejects addresses carrying surrounding whitespace (no silent trim)', () => {
    fc.assert(
      fc.property(emailArb, fc.constantFrom(' ', '\t', '\n'), (raw, space) => {
        expect(parseEmail(`${space}${raw}`).isErr()).toBe(true)
        expect(parseEmail(`${raw}${space}`).isErr()).toBe(true)
      }),
      runs
    )
  })

  it('emailDomainOf agrees with the normalised domain, whatever the casing', () => {
    fc.assert(
      fc.property(emailArb, fc.array(fc.boolean(), { minLength: 1 }), (raw, mask) => {
        const parsed = parseEmail(raw)
        if (parsed.isErr()) {
          return
        }
        const domain = parsed.value.slice(parsed.value.lastIndexOf('@') + 1)
        expect(emailDomainOf(recase(raw, mask))).toBe(domain)
        expect(emailDomainAllowed(recase(raw, mask), [domain.toUpperCase()])).toBe(true)
        // Subdomains never inherit trust; a parent-domain list admits
        // nothing beyond an exact match.
        expect(emailDomainAllowed(`x@mail.${domain}`, [domain])).toBe(false)
        expect(emailDomainAllowed(raw, [])).toBe(false)
      }),
      runs
    )
  })
})

/** Canonical role slugs. */
const roleArb = fc.stringMatching(/^[a-z0-9][a-z0-9_-]{0,63}$/)

describe('parseRole (property)', () => {
  it('accepts every canonical slug unchanged (round-trip)', () => {
    fc.assert(
      fc.property(roleArb, (raw) => {
        const parsed = parseRole(raw)
        expect(parsed.isOk() && parsed.value).toBe(raw)
        // Idempotent.
        if (parsed.isOk()) {
          const again = parseRole(parsed.value)
          expect(again.isOk() && again.value).toBe(raw)
        }
      }),
      runs
    )
  })

  it('never silently normalises: any uppercase letter is refused, not lowercased', () => {
    fc.assert(
      fc.property(
        roleArb.filter((role) => /[a-z]/.test(role)),
        fc.array(fc.boolean(), { minLength: 1 }),
        (raw, mask) => {
          const recased = recase(raw, mask)
          const parsed = parseRole(recased)
          expect(parsed.isOk()).toBe(recased === raw)
        }
      ),
      runs
    )
  })

  it('never throws on arbitrary input; whatever it accepts is a canonical slug', () => {
    fc.assert(
      fc.property(fc.anything(), (value) => {
        const parsed = parseRole(value)
        if (parsed.isOk()) {
          expect(parsed.value).toMatch(/^[a-z0-9][a-z0-9_-]{0,63}$/)
        }
      }),
      runs
    )
  })

  it('refuses padded, empty, and over-long roles', () => {
    fc.assert(
      fc.property(roleArb, (raw) => {
        expect(parseRole(` ${raw}`).isErr()).toBe(true)
        expect(parseRole(`${raw} `).isErr()).toBe(true)
        expect(parseRole(raw.padEnd(65, 'a')).isErr()).toBe(true)
      }),
      runs
    )
    expect(parseRole('').isErr()).toBe(true)
  })
})
