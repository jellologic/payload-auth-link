#!/usr/bin/env bun
/**
 * The `@payload-auth-link/migrate` CLI (issues #49–#59). Today: the
 * read-only `doctor` (#52). The importer and exporters ride the same
 * entrypoint as they land (#50, #58).
 *
 * Exit codes: 0 clean, 1 blockers, 2 warnings only, 3 usage errors.
 * Never logs credential material — connection strings print only in
 * the `--json` echo of what the caller passed, and secrets inside them
 * are the caller's own input.
 */
import { runDoctor } from './doctor/run-doctor.js'
import type { DoctorReport } from './doctor/types.js'

type ParsedArgs = {
  readonly command: string | null
  readonly flags: ReadonlyMap<string, string | boolean>
}

function parseArgs(argv: readonly string[]): ParsedArgs {
  const positional: string[] = []
  const flags = new Map<string, string | boolean>()
  for (let index = 0; index < argv.length; index += 1) {
    const arg: string | undefined = argv[index]
    if (arg === undefined) {
      continue
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=')
      if (eq > 0) {
        flags.set(arg.slice(2, eq), arg.slice(eq + 1))
      } else {
        const name = arg.slice(2)
        const next: string | undefined = argv[index + 1]
        if (next !== undefined && !next.startsWith('--')) {
          flags.set(name, next)
          index += 1
        } else {
          flags.set(name, true)
        }
      }
    } else {
      positional.push(arg)
    }
  }
  return { command: positional[0] ?? null, flags }
}

function usage(): string {
  return `@payload-auth-link/migrate — the payload-auth → payload-auth-link migration kit

Commands:
  doctor --config ./src/payload.config.ts [--src ./src] [--json] [--database-url URL]
  doctor is read-only: it loads the config, inspects the users
  collection and Better Auth plugins, scans sources for call sites
  that must migrate, and (with a database URL) reports row counts,
  unverified users, and orphans.

Exit codes: 0 clean, 1 blockers/mismatch, 2 warnings only, 3 usage errors.
`
}

function formatReport(report: DoctorReport): string {
  const lines: string[] = []
  lines.push('== versions ==')
  for (const finding of report.versions) {
    lines.push(
      `${finding.status === 'ok' ? ' ok ' : finding.status === 'unknown' ? ' ?  ' : ' !! '} ${finding.name}: ${finding.installed ?? 'unresolved'} (band ${finding.band})`
    )
  }
  lines.push('')
  lines.push('== Better Auth plugins ==')
  if (report.plugins.length === 0) {
    lines.push('     none declared')
  }
  for (const finding of report.plugins) {
    lines.push(`  -  ${finding.id}: ${finding.status} — ${finding.detail}`)
  }
  lines.push('')
  lines.push('== users collection ==')
  if (report.users === null) {
    lines.push('     not found')
  } else {
    lines.push(`  slug: ${report.users.slug}`)
    const role = report.users.roleField
    if (role !== null) {
      lines.push(
        `  role field '${role.name}': ${role.type}${role.hasMany ? ' (hasMany)' : ''} values [${role.values.join(', ')}]${role.nonCanonical.length > 0 ? ` — NON-CANONICAL: ${role.nonCanonical.join(', ')}` : ''}`
      )
    } else {
      lines.push('  role field: none found')
    }
    lines.push(`  local strategy: ${report.users.localStrategy ? 'ON' : 'off'}`)
    if (report.users.collisions.length > 0) {
      lines.push(`  collisions with injected fields: ${report.users.collisions.join(', ')}`)
    }
    for (const note of report.users.notes) {
      lines.push(`  note: ${note}`)
    }
  }
  lines.push('')
  lines.push('== source scan ==')
  if (report.source.length === 0) {
    lines.push('     no migration call sites found')
  }
  for (const finding of report.source) {
    lines.push(
      `  -  ${finding.kind}: ${finding.files.length} file(s)${finding.fields.length > 0 ? ` (fields: ${finding.fields.join(', ')})` : ''}`
    )
    for (const file of finding.files.slice(0, 8)) {
      lines.push(`        ${file}`)
    }
  }
  lines.push('')
  lines.push('== database ==')
  if (report.database === null) {
    lines.push('     not inspected')
  } else {
    for (const table of report.database.tables) {
      lines.push(`  ${table.name}: ${table.rows}`)
    }
    if (report.database.unverifiedUsers !== null) {
      lines.push(`  unverified users: ${report.database.unverifiedUsers}`)
    }
    for (const orphan of report.database.orphans) {
      lines.push(`  ORPHANS ${orphan.kind}: ${orphan.count}`)
    }
  }
  lines.push('')
  lines.push('== behaviour changes that will bite (0.7.0) ==')
  for (const change of report.behaviourChanges) {
    lines.push(`  * ${change.title}: ${change.detail}`)
  }
  lines.push('')
  lines.push('== blockers ==')
  if (report.blockers.length === 0) {
    lines.push('     none')
  }
  for (const issue of report.blockers) {
    lines.push(`  [${issue.code}] ${issue.detail}`)
  }
  lines.push('')
  lines.push('== warnings ==')
  if (report.warnings.length === 0) {
    lines.push('     none')
  }
  for (const issue of report.warnings) {
    lines.push(`  [${issue.code}] ${issue.detail}`)
  }
  return lines.join('\n')
}

type StdSink = {
  readonly write: (chunk: string) => void
}

async function main(
  argv: readonly string[],
  out: StdSink = process.stdout,
  err: StdSink = process.stderr
): Promise<number> {
  const { command, flags } = parseArgs(argv)
  if (command === null || command === 'help' || flags.get('help') === true) {
    out.write(usage())
    return command === null && argv.length === 0 ? 3 : 0
  }
  if (command !== 'doctor') {
    err.write(`unknown command '${command}'\n\n${usage()}`)
    return 3
  }
  const configPath = flags.get('config')
  if (typeof configPath !== 'string' || configPath === '') {
    err.write('doctor requires --config <path to payload.config.ts>\n')
    return 3
  }
  const resolvedConfig = new URL(configPath, `file://${process.cwd()}/`).pathname
  const srcFlag = flags.get('src')
  const dbFlag = flags.get('database-url')
  const report = await runDoctor({
    configPath: resolvedConfig,
    ...(typeof srcFlag === 'string'
      ? { srcDir: new URL(srcFlag, `file://${process.cwd()}/`).pathname }
      : {}),
    ...(typeof dbFlag === 'string' ? { databaseUrl: dbFlag } : {}),
  })
  if (flags.get('json') === true) {
    out.write(`${JSON.stringify(report, null, 2)}\n`)
  } else {
    out.write(`${formatReport(report)}\n`)
  }
  if (report.blockers.length > 0) {
    return 1
  }
  if (report.warnings.length > 0) {
    return 2
  }
  return 0
}

const invokedDirectly =
  process.argv[1]?.endsWith('cli.js') === true || process.argv[1]?.endsWith('cli.ts') === true
if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code
    })
    .catch((error: unknown) => {
      process.stderr.write(
        `doctor failed: ${error instanceof Error ? error.message : String(error)}\n`
      )
      process.exitCode = 1
    })
}

export { main as cliMain }
