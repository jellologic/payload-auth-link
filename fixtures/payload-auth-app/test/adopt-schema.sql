-- Additive schema for adopt mode (issue #49): the columns and child
-- tables payload-auth-link injects on the users collection. Applied
-- before boot; `push` stays OFF because drizzle's push prompts
-- interactively when it meets the payload-auth layout's enums.
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone varchar;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_until timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspend_reason varchar;
ALTER TABLE users ADD COLUMN IF NOT EXISTS linkable boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS linkable_email varchar;

CREATE TABLE IF NOT EXISTS users_identities (
  _order integer NOT NULL,
  _parent_id integer NOT NULL,
  id varchar NOT NULL,
  provider_id varchar NOT NULL,
  provider_user_id varchar NOT NULL,
  email varchar NOT NULL,
  linked_at timestamptz NOT NULL,
  CONSTRAINT users_identities_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS users_identities_order_idx ON users_identities (_order);
CREATE INDEX IF NOT EXISTS users_identities_parent_id_idx ON users_identities (_parent_id);

-- Payload's auth collections carry a `sessions` array (session-based
-- local auth); payload-auth's dump predates the table materializing.
CREATE TABLE IF NOT EXISTS users_sessions (
  _order integer NOT NULL,
  _parent_id integer NOT NULL,
  id varchar NOT NULL,
  created_at timestamptz,
  expires_at timestamptz,
  CONSTRAINT users_sessions_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS users_sessions_order_idx ON users_sessions (_order);
CREATE INDEX IF NOT EXISTS users_sessions_parent_id_idx ON users_sessions (_parent_id);

-- Payload's local-strategy bookkeeping columns (auth collections carry
-- them even when the local strategy is dormant).
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_token varchar;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_expiration timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_requested_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS lock_until timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS salt varchar;
ALTER TABLE users ADD COLUMN IF NOT EXISTS hash varchar;

-- The migration kit's own record store (issue #139): the plugin
-- declares the payload-auth-link-migrations collection, so the app's
-- migrations create it. The kit records its database identity, runs,
-- and finalize marker here — in the database they describe.
CREATE TABLE IF NOT EXISTS payload_auth_link_migrations (
  id serial PRIMARY KEY,
  key varchar NOT NULL UNIQUE,
  data jsonb NOT NULL
);
