/**
 * The `req.context` key the ENGINE stamps on the Local API creates it
 * performs for Better Auth users (issue #132). The plugin's users
 * collection hook reads it to tell an engine-created row (whose id IS
 * the provider user id in adopt mode, and whose identities row can be
 * written at creation) apart from an operator-created document, which
 * must never gain a synthetic identity.
 */
export const engineCreateMarker = 'payload-auth-link:engine-create'
