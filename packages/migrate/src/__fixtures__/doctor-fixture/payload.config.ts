/**
 * A minimal config fixture the doctor can LOAD in-process: no
 * payload-auth plugin (so the report is warnings-only), a users
 * collection with a non-canonical role value.
 */
const config = {
  collections: [
    {
      slug: 'users',
      auth: true,
      fields: [
        { name: 'email', type: 'email' },
        { name: 'role', type: 'select', hasMany: true, options: ['user', 'frontPlugin'] },
      ],
    },
  ],
}
export default config
