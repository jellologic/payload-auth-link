/**
 * LOCAL EXAMPLE ONLY: the dev mailbox. Provider mail hooks (magic
 * link / email OTP senders) write here instead of sending real email,
 * and the `/api/dev-mailbox` route (404 in production) reads them back
 * so the passwordless flows — and their e2e tests — run with no mail
 * server. Production builders pass real senders and never ship this.
 *
 * Stored on `globalThis` so Next's module reloading in dev does not
 * fork the mailbox between the engine module and the route module.
 */
export type DevMailEntry = {
  readonly kind: 'magic-link' | 'email-otp'
  readonly email: string
  /** Full magic-link URL when kind is `magic-link`. */
  readonly url?: string | undefined
  /** 6-digit code when kind is `email-otp`. */
  readonly code?: string | undefined
  readonly at: number
}

type MailboxGlobal = typeof globalThis & { __devMailbox?: DevMailEntry[] }

function mailbox(): DevMailEntry[] {
  const holder = globalThis as MailboxGlobal
  holder.__devMailbox ??= []
  return holder.__devMailbox
}

/** Record one captured message (newest last, capped like a real inbox view). */
export function recordDevMail(entry: Omit<DevMailEntry, 'at'>): void {
  const entries = mailbox()
  entries.push({ ...entry, at: Date.now() })
  if (entries.length > 200) {
    entries.splice(0, entries.length - 200)
  }
}

/** Messages for one address (or all), newest first. */
export function readDevMailbox(email?: string): DevMailEntry[] {
  const entries = email === undefined ? mailbox() : mailbox().filter((e) => e.email === email)
  return [...entries].reverse()
}

/** Empty the mailbox (e2e isolation). */
export function clearDevMailbox(): void {
  mailbox().length = 0
}
