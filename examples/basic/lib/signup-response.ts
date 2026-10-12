import { InvalidEmailError, UserExistsError } from '@payload-auth-link/core'
import { WeakPasswordError } from '@payload-auth-link/provider-authjs'

/**
 * Map a registration result to the signup HTTP response without an
 * email-enumeration oracle: a new address and an already-registered one
 * get the SAME status and body, so the response never reveals whether an
 * account exists. The duplicate case goes out-of-band instead, through
 * `notifyExisting` (production: email the owner "someone tried to
 * register with your address"; this local example has no email
 * delivery, so its routes pass a documented no-op). Input errors (weak
 * password, malformed email) reveal nothing about existence and stay
 * 400s; storage failures are a generic 500 (the cause may carry database
 * internals).
 */
export function signupResponse(
  /** The registration error, or `null` when the user was created. */
  error: unknown,
  email: string,
  notifyExisting: (email: string) => void
): Response {
  if (error === null) {
    return Response.json({ ok: true })
  }
  if (error instanceof UserExistsError) {
    notifyExisting(email)
    return Response.json({ ok: true })
  }
  if (error instanceof WeakPasswordError || error instanceof InvalidEmailError) {
    return Response.json({ error: error.message }, { status: 400 })
  }
  return Response.json({ error: 'registration failed, try again later' }, { status: 500 })
}
