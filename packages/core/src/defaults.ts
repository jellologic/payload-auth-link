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

const silentLoggers = new WeakSet<object>()

/** Silent logger; `child` returns itself. */
export function nullLogger(): LoggerPort {
  const logger: LoggerPort = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    child: () => logger,
  }
  silentLoggers.add(logger)
  return logger
}

/** Was this logger produced by {@link nullLogger}? Lets wiring warn
 * through a different channel when the configured logger would eat a
 * message. */
export function isSilentLogger(logger: LoggerPort): boolean {
  return silentLoggers.has(logger)
}

/**
 * Console-backed logger: the plugin's default so refusals and audit
 * events are visible without configuration. Warn/error go to the
 * matching console level, info to `console.info`; fields render as a
 * compact JSON suffix. `debug` stays silent — call sites that need
 * trace noise should pass a real logger. Messages carry only what
 * call sites pass: never tokens or secrets.
 */
export function consoleLogger(): LoggerPort {
  /* eslint-disable no-console -- the LoggerPort's console sink: the one place logs reach the console */
  const format = (message: string, fields?: LogFields): string =>
    fields === undefined || Object.keys(fields).length === 0
      ? message
      : `${message} ${JSON.stringify(fields)}`
  const logger: LoggerPort = {
    debug: () => undefined,
    info: (message, fields) => {
      console.info(format(message, fields))
    },
    warn: (message, fields) => {
      console.warn(format(message, fields))
    },
    error: (message, fields) => {
      console.error(format(message, fields))
    },
    child: () => logger,
  }
  /* eslint-enable no-console */
  return logger
}

/** No-op tracer; `withSpan` runs the function directly. */
export function nullTracer(): TracerPort {
  return {
    withSpan: <T>(_name: string, _attributes: LogFields, fn: () => Promise<T>): Promise<T> => fn(),
  }
}
