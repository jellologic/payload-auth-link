/**
 * Consumer fixture for `@payload-auth-link/migrate` (issue #85): its
 * shipped `.d.ts` must typecheck under `skipLibCheck: false` with only
 * its declared peers present — no `@types/pg`, no `typescript`.
 */
import {
  openSource,
  readSourceUsers,
  runDoctor,
  type DoctorReport,
  type SourceClient,
  type SourceUser,
} from '@payload-auth-link/migrate'

export async function users(url: string): Promise<readonly SourceUser[]> {
  const client: SourceClient = await openSource(url)
  try {
    return await readSourceUsers(client)
  } finally {
    await client.end()
  }
}

export type Report = DoctorReport
export const doctor: typeof runDoctor = runDoctor
