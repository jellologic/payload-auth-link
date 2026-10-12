import type { ClockPort, IdPort, LoggerPort, LogFields, TracerPort } from './ports.js'

/**
 * Safe leaf defaults for composition roots and tests. These are honest
 * implementations of leaf behavior (system time, random ids, silent logs),
 * not stubs hiding missing functionality — adapters replace them freely.
 */
export function systemClock(): ClockPort {
  return {
    now: () => new Date(),
  }
}

/** Random UUID ids via `crypto.randomUUID`. */
export function randomIds(): IdPort {
  return {
    newId: () => crypto.randomUUID(),
  }
}

/** Silent logger; `child` returns itself. */
export function nullLogger(): LoggerPort {
  const logger: LoggerPort = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    child: () => logger,
  }
  return logger
}

/** No-op tracer; `withSpan` runs the function directly. */
export function nullTracer(): TracerPort {
  return {
    withSpan: <T>(_name: string, _attributes: LogFields, fn: () => Promise<T>): Promise<T> => fn(),
  }
}
