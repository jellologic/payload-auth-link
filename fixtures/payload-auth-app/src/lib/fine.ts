// Scan target (never executed): call sites that need NO migration —
// the doctor must not report them.
import { getPayload } from 'payload'

export async function pages(request: Request): Promise<unknown> {
  const payload = await getPayload({ config: (await import('../payload.config.ts')).default })
  const projection = request.user
  return payload.find({ collection: 'pages', depth: 0 })
}
