/**
 * Fixture generator: a real payload-auth 1.9.4 database, produced by
 * running payload-auth (Better Auth 1.6.30) itself — never hand-written
 * rows. Run with DATABASE_URL pointing at a FRESH database:
 *
 *   DATABASE_URL=postgres://postgres:payload@localhost:5433/pal_fixture bun scripts/seed.ts
 *
 * Then dump:
 *   docker exec pal-pg pg_dump -U postgres --no-owner --no-privileges \
 *     --clean --if-exists pal_fixture > ../dumps/payload-auth-1.9.4.sql
 */
import { getPayload } from 'payload'
import config from '../payload.config.ts'

type AnyRec = Record<string, any>

const PASSWORD = 'FixturePassw0rd!'
let STEP = 'boot'
const step = (label: string): void => {
  STEP = label
}

const payload: AnyRec = await getPayload({ config })
const api: AnyRec = payload.betterAuth.api
const ctx: AnyRec = await payload.betterAuth.$context
const internal: AnyRec = ctx.internalAdapter

function cookiesFrom(headers: Headers): string {
  const raw: string[] = (headers as AnyRec).getSetCookie?.() ?? []
  return raw.map((c) => c.split(';')[0]).join('; ')
}

async function signInHeaders(email: string): Promise<Headers> {
  const r: AnyRec = await api.signInEmail({
    body: { email, password: PASSWORD },
    returnHeaders: true,
  })
  return new Headers({ cookie: cookiesFrom(r.headers as Headers) })
}

async function signUp(name: string, email: string): Promise<AnyRec> {
  const r: AnyRec = await api.signUpEmail({ body: { name, email, password: PASSWORD } })
  return r.user as AnyRec
}

try {
  // --- users -------------------------------------------------------------
  // alice: verified admin. bob: unverified, camelCase role. carol:
  // verified member. dave: unverified member (never links — the doctor's
  // "won't JIT-link" case).
  step('signups')
  const alice = await signUp('Alice Admin', 'alice@example.com')
  const bob = await signUp('Bob Unverified', 'bob@example.com')
  const carol = await signUp('Carol Member', 'carol@example.com')
  const dave = await signUp('Dave Unverified', 'dave@example.com')
  step('verify-users')
  await internal.updateUser(alice.id, { emailVerified: true })
  await internal.updateUser(carol.id, { emailVerified: true })
  step('roles')
  await payload.update({ collection: 'users', id: Number(alice.id), data: { role: ['admin'] } })
  await payload.update({
    collection: 'users',
    id: Number(bob.id),
    data: { role: ['frontPlugin', 'user'], department: 'frontend' },
  })
  await payload.update({ collection: 'users', id: Number(carol.id), data: { department: 'ops' } })

  // --- OAuth accounts (payload-auth adapter writes) -----------------------
  step('oauth-accounts')
  await internal.createAccount({
    userId: String(alice.id),
    accountId: 'google-407',
    providerId: 'google',
    accessToken: 'at_google_fixture',
    refreshToken: 'rt_google_fixture',
    idToken: 'eyJ fixture id token',
    scope: 'openid email profile',
    accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    refreshTokenExpiresAt: new Date(Date.now() + 30 * 86_400_000),
  })
  await internal.createAccount({
    userId: String(carol.id),
    accountId: 'carol@partner.example',
    providerId: 'generic-oauth',
    accessToken: 'at_generic_fixture',
    scope: 'read',
  })

  // --- magic-link verification -------------------------------------------
  step('magic-link')
  const carolHeaders = await signInHeaders('carol@example.com')
  await api.signInMagicLink({
    body: { email: 'carol@example.com', callbackURL: '/verify' },
    headers: carolHeaders,
  })

  // --- organizations (Better Auth organization plugin) --------------------
  step('orgs')
  const aliceHeaders = await signInHeaders('alice@example.com')
  const acme: AnyRec = await api.createOrganization({
    body: { name: 'Acme Inc', slug: 'acme' },
    headers: aliceHeaders,
  })
  // payload-auth 1.9.4 quirk on Postgres: BA 1.6 sends the creator's
  // member role as an array, which payload-auth stringifies into the
  // single-select column ('["owner"]'). BA's own permission checks then
  // fail to parse it. Normalize the encoding so the invitation flow —
  // payload-auth's own code — runs as designed.
  const ownerRows: AnyRec[] = (
    await payload.find({
      collection: 'members',
      where: { organization: { equals: Number(acme.id) } },
      depth: 0,
    })
  ).docs
  for (const m of ownerRows) {
    if (m.user === Number(alice.id) && m.role !== 'owner') {
      await payload.update({ collection: 'members', id: m.id, data: { role: 'owner' } })
    }
  }
  step('invite-bob')
  const bobInvite: AnyRec = await api.createInvitation({
    body: { email: 'bob@example.com', role: 'member', organizationId: acme.id },
    headers: aliceHeaders,
  })
  // acceptInvitation hits BA 1.6's `adapter.incrementOne`, which
  // payload-auth's adapter does not implement (BA 1.7 made it optional
  // with a fallback). Add bob as a member directly — the same rows the
  // accept flow would have written.
  step('add-member')
  const added: AnyRec = await api.addMember({
    body: { userId: String(bob.id), role: 'member', organizationId: acme.id },
    headers: aliceHeaders,
  })
  step('member-role')
  await api.updateMemberRole({
    body: { memberId: added.member?.id ?? added.id, role: 'admin', organizationId: acme.id },
    headers: aliceHeaders,
  })
  // carol: invited, never joins — the pending invitation row.
  step('invite-carol')
  await api.createInvitation({
    body: { email: 'carol@example.com', role: 'member', organizationId: acme.id },
    headers: aliceHeaders,
  })
  // Host-added fields survive: an app-side write through Payload's own API.
  step('org-host-fields')
  await payload.update({
    collection: 'organizations',
    id: Number(acme.id),
    data: {
      billing: { plan: 'pro', seats: 12 },
      tags: [{ label: 'launch' }, { label: 'beta' }],
      owner: Number(alice.id),
    },
  })
  // A second org, owned by carol, untouched by hosts.
  step('org-globex')
  const globex: AnyRec = await api.createOrganization({
    body: { name: 'Globex', slug: 'globex' },
    headers: carolHeaders,
  })

  // --- API keys with metadata --------------------------------------------
  step('api-keys')
  const aliceKey: AnyRec = await api.createApiKey({
    body: {
      name: 'ci-key',
      metadata: { env: 'ci', scopes: ['pages.read', 'pages.write'] },
      rateLimitEnabled: true,
      rateLimitMax: 100,
      rateLimitTimeWindow: 60_000,
      remaining: 97,
      userId: String(alice.id),
    },
  })
  const carolKey: AnyRec = await api.createApiKey({
    body: {
      name: 'read-only',
      metadata: { env: 'prod', scopes: ['pages.read'] },
      enabled: true,
      userId: String(carol.id),
    },
  })

  // --- jwks (jwt plugin mints its signing key on first token) -------------
  step('jwks')
  await api.getToken({ headers: aliceHeaders })

  // --- manifest -----------------------------------------------------------
  step('manifest')
  const counts: AnyRec = {}
  for (const slug of [
    'users',
    'accounts',
    'sessions',
    'verifications',
    'apiKeys',
    'organizations',
    'members',
    'invitations',
    'jwks',
    'admin-invitations',
  ]) {
    counts[slug] = (await payload.count({ collection: slug })).totalDocs
  }
  const users: AnyRec[] = (
    await payload.find({ collection: 'users', limit: 20, sort: 'id', depth: 0 })
  ).docs
  const manifest = {
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      emailVerified: u.emailVerified,
      role: u.role,
      department: u.department ?? null,
    })),
    acmeHostFields: (await payload.findByID({ collection: 'organizations', id: Number(acme.id) }))
      .billing,
    globexId: globex.id,
    apiKeyStarts: [aliceKey.start, carolKey.start],
    counts,
  }
  console.log('FIXTURE MANIFEST ' + JSON.stringify(manifest, null, 2))
} catch (e) {
  const err: AnyRec = e as AnyRec
  console.log('FAILED AT', STEP, err?.message, err?.stack?.split('\n').slice(1, 4).join(' | '))
  process.exit(1)
}
process.exit(0)
