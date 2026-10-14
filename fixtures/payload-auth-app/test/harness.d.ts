import { Client } from 'pg'
export declare const dumpPath: string
export type PostgresTarget = {
  readonly host: string
  readonly port: number
  readonly user: string
  readonly password: string
  readonly database: string
}
export declare function targetFromEnv(database: string): PostgresTarget
export declare function fixtureClient(database: string): Client
/**
 * Create a fresh database and load the committed dump. `--clean
 * --if-exists` statements no-op on an empty database, so the same file
 * loads anywhere. Returns the database name.
 */
export declare function loadFixtureDump(prefix: string): Promise<string>
export declare function dropDatabase(database: string): Promise<void>
/** The committed dump's own sanity contract, shared by every consumer. */
export declare const expectedCounts: Readonly<Record<string, number>>
//# sourceMappingURL=harness.d.ts.map
