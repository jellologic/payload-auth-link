/**
 * The step-up guard's per-user serializer (GHSA-xgx5-2cj5-x548):
 * attempt reservations for one user run strictly one after another,
 * a failing task never blocks the queue, and distinct users never
 * wait on each other. The real-engine burst tests in
 * `mfa-step-up-engine.test.ts` pin what this buys end to end.
 */
import { describe, expect, it } from 'vitest'
import { createSerializer, outcomeOf } from '../step-up.js'

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve = (): void => undefined
  const promise = new Promise<void>((settle) => {
    resolve = settle
  })
  return { promise, resolve }
}

describe('createSerializer', () => {
  it('runs tasks for one key strictly in order, never overlapping', async () => {
    const serialize = createSerializer()
    const log: string[] = []
    const gate = deferred()
    const first = serialize('u-1', async () => {
      log.push('first:start')
      await gate.promise
      log.push('first:end')
      return 1
    })
    const second = serialize('u-1', () => {
      log.push('second')
      return Promise.resolve(2)
    })
    // Queued behind `first`, which has not finished.
    await Promise.resolve()
    expect(log).toEqual(['first:start'])
    gate.resolve()
    await expect(Promise.all([first, second])).resolves.toEqual([1, 2])
    expect(log).toEqual(['first:start', 'first:end', 'second'])
  })

  it('a failing task rejects its own caller and does not block the queue', async () => {
    const serialize = createSerializer()
    const failed = serialize('u-1', () => Promise.reject(new Error('boom')))
    const next = serialize('u-1', () => Promise.resolve('ran'))
    await expect(failed).rejects.toThrow('boom')
    await expect(next).resolves.toBe('ran')
  })

  it('distinct keys do not wait on each other', async () => {
    const serialize = createSerializer()
    const gate = deferred()
    const blocked = serialize('u-1', () => gate.promise)
    await expect(serialize('u-2', () => Promise.resolve('free'))).resolves.toBe('free')
    gate.resolve()
    await blocked
  })
})

describe('outcomeOf', () => {
  it('classifies a 200 Response as success and any other Response as failed', () => {
    expect(outcomeOf(new Response('{}', { status: 200 }))).toBe('success')
    expect(outcomeOf(new Response('{}', { status: 401 }))).toBe('failed')
    expect(outcomeOf({ token: 'x' })).toBe('success')
    expect(outcomeOf(undefined)).toBe('failed')
  })
})
