/**
 * Test-only `PayloadRequest` factories that work on BOTH Payload majors
 * in the supported band (`^3.83.0 || 4.0.0-beta.0`). Payload v4 renamed
 * the request builders, and reused one of the names with a different
 * signature:
 *
 * | purpose                      | v3                                   | v4                                              |
 * | ---------------------------- | ------------------------------------ | ----------------------------------------------- |
 * | Local-API req (no transport) | `createLocalReq(options, payload)`   | `createPayloadRequest({ payload, req })`        |
 * | req from a web `Request`     | `createPayloadRequest({ config, request, canSetHeaders })` | `createPayloadRequestFromWebRequest({ ...same })` |
 *
 * Neither name can be imported statically on both majors (the compiler
 * rejects the missing export), so the builders are looked up on the
 * module namespace at runtime and typed by the signatures above. The
 * lookup throws instead of guessing when neither shape is present.
 */
import * as payloadExports from 'payload'
import type { Payload, PayloadRequest, SanitizedConfig } from 'payload'

type LocalReqV3 = (
  options: { req?: Partial<PayloadRequest> },
  payload: Payload
) => Promise<PayloadRequest>
type LocalReqV4 = (args: {
  payload: Payload
  req?: Partial<PayloadRequest>
}) => Promise<PayloadRequest>
type WebReq = (args: {
  canSetHeaders?: boolean
  config: Promise<SanitizedConfig> | SanitizedConfig
  request: Request
}) => Promise<PayloadRequest>

const exportsByName: Readonly<Record<string, unknown>> = payloadExports

function exported<T>(name: string): T | undefined {
  const value = exportsByName[name]
  // The signature is pinned by the per-major table above; a runtime
  // `typeof` is the only check a function value admits.
  return typeof value === 'function' ? (value as T) : undefined
}

/** True when the installed `payload` is the v3 line (`createLocalReq` exists). */
export const isPayloadV3 = exported<LocalReqV3>('createLocalReq') !== undefined

/** A Local-API `PayloadRequest` (v3 `createLocalReq`, v4 `createPayloadRequest`). */
export async function createLocalRequest(
  payload: Payload,
  req: Partial<PayloadRequest>
): Promise<PayloadRequest> {
  const v3 = exported<LocalReqV3>('createLocalReq')
  if (v3 !== undefined) {
    return v3({ req }, payload)
  }
  const v4 = exported<LocalReqV4>('createPayloadRequest')
  if (v4 === undefined) {
    throw new Error('payload exports no Local-API request builder')
  }
  return v4({ payload, req })
}

/**
 * An authenticated `PayloadRequest` built from a web `Request` the way
 * the framework route handlers do (v3 `createPayloadRequest`, v4
 * `createPayloadRequestFromWebRequest`).
 */
export async function createWebRequest(args: {
  canSetHeaders?: boolean
  config: SanitizedConfig
  request: Request
}): Promise<PayloadRequest> {
  const builder = isPayloadV3
    ? exported<WebReq>('createPayloadRequest')
    : exported<WebReq>('createPayloadRequestFromWebRequest')
  if (builder === undefined) {
    throw new Error('payload exports no web-request builder')
  }
  return builder(args)
}
