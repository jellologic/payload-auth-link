--
-- PostgreSQL database dump
--

\restrict ypcjhu0fhucKJgysf2UIhCjabW28k7BcgW8nxkOX2t4t7AJlAjS9Z2IvummiJQc

-- Dumped from database version 16.15 (Debian 16.15-1.pgdg13+2)
-- Dumped by pg_dump version 16.15 (Debian 16.15-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

ALTER TABLE IF EXISTS ONLY public.users_role DROP CONSTRAINT IF EXISTS users_role_parent_fk;
ALTER TABLE IF EXISTS ONLY public.sessions DROP CONSTRAINT IF EXISTS sessions_user_id_users_id_fk;
ALTER TABLE IF EXISTS ONLY public.sessions DROP CONSTRAINT IF EXISTS sessions_active_organization_id_organizations_id_fk;
ALTER TABLE IF EXISTS ONLY public.payload_preferences_rels DROP CONSTRAINT IF EXISTS payload_preferences_rels_users_fk;
ALTER TABLE IF EXISTS ONLY public.payload_preferences_rels DROP CONSTRAINT IF EXISTS payload_preferences_rels_parent_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_verifications_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_users_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_sessions_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_parent_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_organizations_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_members_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_jwks_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_invitations_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_api_keys_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_admin_invitations_fk;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_accounts_fk;
ALTER TABLE IF EXISTS ONLY public.organizations_tags DROP CONSTRAINT IF EXISTS organizations_tags_parent_id_fk;
ALTER TABLE IF EXISTS ONLY public.organizations DROP CONSTRAINT IF EXISTS organizations_owner_id_users_id_fk;
ALTER TABLE IF EXISTS ONLY public.members DROP CONSTRAINT IF EXISTS members_user_id_users_id_fk;
ALTER TABLE IF EXISTS ONLY public.members DROP CONSTRAINT IF EXISTS members_organization_id_organizations_id_fk;
ALTER TABLE IF EXISTS ONLY public.invitations DROP CONSTRAINT IF EXISTS invitations_organization_id_organizations_id_fk;
ALTER TABLE IF EXISTS ONLY public.invitations DROP CONSTRAINT IF EXISTS invitations_inviter_id_users_id_fk;
ALTER TABLE IF EXISTS ONLY public.accounts DROP CONSTRAINT IF EXISTS accounts_user_id_users_id_fk;
DROP INDEX IF EXISTS public.verifications_updated_at_idx;
DROP INDEX IF EXISTS public.verifications_identifier_idx;
DROP INDEX IF EXISTS public.verifications_created_at_idx;
DROP INDEX IF EXISTS public.users_updated_at_idx;
DROP INDEX IF EXISTS public.users_role_parent_idx;
DROP INDEX IF EXISTS public.users_role_order_idx;
DROP INDEX IF EXISTS public.users_email_idx;
DROP INDEX IF EXISTS public.users_created_at_idx;
DROP INDEX IF EXISTS public.sessions_user_idx;
DROP INDEX IF EXISTS public.sessions_updated_at_idx;
DROP INDEX IF EXISTS public.sessions_token_idx;
DROP INDEX IF EXISTS public.sessions_created_at_idx;
DROP INDEX IF EXISTS public.sessions_active_organization_idx;
DROP INDEX IF EXISTS public.payload_preferences_updated_at_idx;
DROP INDEX IF EXISTS public.payload_preferences_rels_users_id_idx;
DROP INDEX IF EXISTS public.payload_preferences_rels_path_idx;
DROP INDEX IF EXISTS public.payload_preferences_rels_parent_idx;
DROP INDEX IF EXISTS public.payload_preferences_rels_order_idx;
DROP INDEX IF EXISTS public.payload_preferences_key_idx;
DROP INDEX IF EXISTS public.payload_preferences_created_at_idx;
DROP INDEX IF EXISTS public.payload_migrations_updated_at_idx;
DROP INDEX IF EXISTS public.payload_migrations_created_at_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_updated_at_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_verifications_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_users_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_sessions_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_path_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_parent_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_organizations_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_order_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_members_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_jwks_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_invitations_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_api_keys_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_admin_invitations_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_rels_accounts_id_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_global_slug_idx;
DROP INDEX IF EXISTS public.payload_locked_documents_created_at_idx;
DROP INDEX IF EXISTS public.payload_kv_key_idx;
DROP INDEX IF EXISTS public.organizations_updated_at_idx;
DROP INDEX IF EXISTS public.organizations_tags_parent_id_idx;
DROP INDEX IF EXISTS public.organizations_tags_order_idx;
DROP INDEX IF EXISTS public.organizations_slug_idx;
DROP INDEX IF EXISTS public.organizations_owner_idx;
DROP INDEX IF EXISTS public.members_user_idx;
DROP INDEX IF EXISTS public.members_updated_at_idx;
DROP INDEX IF EXISTS public.members_organization_idx;
DROP INDEX IF EXISTS public.jwks_updated_at_idx;
DROP INDEX IF EXISTS public.jwks_public_key_idx;
DROP INDEX IF EXISTS public.invitations_updated_at_idx;
DROP INDEX IF EXISTS public.invitations_organization_idx;
DROP INDEX IF EXISTS public.invitations_inviter_idx;
DROP INDEX IF EXISTS public.invitations_email_idx;
DROP INDEX IF EXISTS public.api_keys_updated_at_idx;
DROP INDEX IF EXISTS public.api_keys_created_at_idx;
DROP INDEX IF EXISTS public.admin_invitations_updated_at_idx;
DROP INDEX IF EXISTS public.admin_invitations_token_idx;
DROP INDEX IF EXISTS public.admin_invitations_created_at_idx;
DROP INDEX IF EXISTS public.accounts_user_idx;
DROP INDEX IF EXISTS public.accounts_updated_at_idx;
DROP INDEX IF EXISTS public.accounts_created_at_idx;
DROP INDEX IF EXISTS public.accounts_account_id_idx;
ALTER TABLE IF EXISTS ONLY public.verifications DROP CONSTRAINT IF EXISTS verifications_pkey;
ALTER TABLE IF EXISTS ONLY public.users_role DROP CONSTRAINT IF EXISTS users_role_pkey;
ALTER TABLE IF EXISTS ONLY public.users DROP CONSTRAINT IF EXISTS users_pkey;
ALTER TABLE IF EXISTS ONLY public.sessions DROP CONSTRAINT IF EXISTS sessions_pkey;
ALTER TABLE IF EXISTS ONLY public.payload_preferences_rels DROP CONSTRAINT IF EXISTS payload_preferences_rels_pkey;
ALTER TABLE IF EXISTS ONLY public.payload_preferences DROP CONSTRAINT IF EXISTS payload_preferences_pkey;
ALTER TABLE IF EXISTS ONLY public.payload_migrations DROP CONSTRAINT IF EXISTS payload_migrations_pkey;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents_rels DROP CONSTRAINT IF EXISTS payload_locked_documents_rels_pkey;
ALTER TABLE IF EXISTS ONLY public.payload_locked_documents DROP CONSTRAINT IF EXISTS payload_locked_documents_pkey;
ALTER TABLE IF EXISTS ONLY public.payload_kv DROP CONSTRAINT IF EXISTS payload_kv_pkey;
ALTER TABLE IF EXISTS ONLY public.organizations_tags DROP CONSTRAINT IF EXISTS organizations_tags_pkey;
ALTER TABLE IF EXISTS ONLY public.organizations DROP CONSTRAINT IF EXISTS organizations_pkey;
ALTER TABLE IF EXISTS ONLY public.members DROP CONSTRAINT IF EXISTS members_pkey;
ALTER TABLE IF EXISTS ONLY public.jwks DROP CONSTRAINT IF EXISTS jwks_pkey;
ALTER TABLE IF EXISTS ONLY public.invitations DROP CONSTRAINT IF EXISTS invitations_pkey;
ALTER TABLE IF EXISTS ONLY public.api_keys DROP CONSTRAINT IF EXISTS api_keys_pkey;
ALTER TABLE IF EXISTS ONLY public.admin_invitations DROP CONSTRAINT IF EXISTS admin_invitations_pkey;
ALTER TABLE IF EXISTS ONLY public.accounts DROP CONSTRAINT IF EXISTS accounts_pkey;
ALTER TABLE IF EXISTS public.verifications ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.users_role ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.users ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.sessions ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.payload_preferences_rels ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.payload_preferences ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.payload_migrations ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.payload_locked_documents_rels ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.payload_locked_documents ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.payload_kv ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.organizations ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.members ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.jwks ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.invitations ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.api_keys ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.admin_invitations ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS public.accounts ALTER COLUMN id DROP DEFAULT;
DROP SEQUENCE IF EXISTS public.verifications_id_seq;
DROP TABLE IF EXISTS public.verifications;
DROP SEQUENCE IF EXISTS public.users_role_id_seq;
DROP TABLE IF EXISTS public.users_role;
DROP SEQUENCE IF EXISTS public.users_id_seq;
DROP TABLE IF EXISTS public.users;
DROP SEQUENCE IF EXISTS public.sessions_id_seq;
DROP TABLE IF EXISTS public.sessions;
DROP SEQUENCE IF EXISTS public.payload_preferences_rels_id_seq;
DROP TABLE IF EXISTS public.payload_preferences_rels;
DROP SEQUENCE IF EXISTS public.payload_preferences_id_seq;
DROP TABLE IF EXISTS public.payload_preferences;
DROP SEQUENCE IF EXISTS public.payload_migrations_id_seq;
DROP TABLE IF EXISTS public.payload_migrations;
DROP SEQUENCE IF EXISTS public.payload_locked_documents_rels_id_seq;
DROP TABLE IF EXISTS public.payload_locked_documents_rels;
DROP SEQUENCE IF EXISTS public.payload_locked_documents_id_seq;
DROP TABLE IF EXISTS public.payload_locked_documents;
DROP SEQUENCE IF EXISTS public.payload_kv_id_seq;
DROP TABLE IF EXISTS public.payload_kv;
DROP TABLE IF EXISTS public.organizations_tags;
DROP SEQUENCE IF EXISTS public.organizations_id_seq;
DROP TABLE IF EXISTS public.organizations;
DROP SEQUENCE IF EXISTS public.members_id_seq;
DROP TABLE IF EXISTS public.members;
DROP SEQUENCE IF EXISTS public.jwks_id_seq;
DROP TABLE IF EXISTS public.jwks;
DROP SEQUENCE IF EXISTS public.invitations_id_seq;
DROP TABLE IF EXISTS public.invitations;
DROP SEQUENCE IF EXISTS public.api_keys_id_seq;
DROP TABLE IF EXISTS public.api_keys;
DROP SEQUENCE IF EXISTS public.admin_invitations_id_seq;
DROP TABLE IF EXISTS public.admin_invitations;
DROP SEQUENCE IF EXISTS public.accounts_id_seq;
DROP TABLE IF EXISTS public.accounts;
DROP TYPE IF EXISTS public.enum_users_role;
DROP TYPE IF EXISTS public.enum_admin_invitations_role;
--
-- Name: enum_admin_invitations_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.enum_admin_invitations_role AS ENUM (
    'admin',
    'user',
    'staff',
    'frontPlugin'
);


--
-- Name: enum_users_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.enum_users_role AS ENUM (
    'admin',
    'user',
    'staff',
    'frontPlugin'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.accounts (
    id integer NOT NULL,
    account_id character varying NOT NULL,
    provider_id character varying NOT NULL,
    user_id integer NOT NULL,
    access_token character varying,
    refresh_token character varying,
    id_token character varying,
    access_token_expires_at timestamp(3) with time zone,
    refresh_token_expires_at timestamp(3) with time zone,
    scope character varying,
    password character varying,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.accounts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.accounts_id_seq OWNED BY public.accounts.id;


--
-- Name: admin_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_invitations (
    id integer NOT NULL,
    role public.enum_admin_invitations_role DEFAULT 'admin'::public.enum_admin_invitations_role NOT NULL,
    token character varying NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: admin_invitations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_invitations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_invitations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_invitations_id_seq OWNED BY public.admin_invitations.id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id integer NOT NULL,
    config_id character varying NOT NULL,
    name character varying,
    start character varying,
    reference_id character varying NOT NULL,
    prefix character varying,
    key character varying NOT NULL,
    refill_interval numeric,
    refill_amount numeric,
    last_refill_at timestamp(3) with time zone,
    enabled boolean DEFAULT true,
    rate_limit_enabled boolean DEFAULT true,
    rate_limit_time_window numeric,
    rate_limit_max numeric,
    request_count numeric,
    remaining numeric,
    last_request timestamp(3) with time zone,
    expires_at timestamp(3) with time zone,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    permissions character varying,
    metadata character varying
);


--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.api_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.api_keys_id_seq OWNED BY public.api_keys.id;


--
-- Name: invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invitations (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    email character varying NOT NULL,
    role character varying,
    status character varying DEFAULT 'pending'::character varying NOT NULL,
    expires_at timestamp(3) with time zone NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    inviter_id integer NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: invitations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.invitations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: invitations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.invitations_id_seq OWNED BY public.invitations.id;


--
-- Name: jwks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jwks (
    id integer NOT NULL,
    public_key character varying NOT NULL,
    private_key character varying NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    expires_at timestamp(3) with time zone,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: jwks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.jwks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: jwks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.jwks_id_seq OWNED BY public.jwks.id;


--
-- Name: members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.members (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    user_id integer NOT NULL,
    role character varying DEFAULT 'member'::character varying NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: members_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.members_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: members_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.members_id_seq OWNED BY public.members.id;


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id integer NOT NULL,
    name character varying NOT NULL,
    slug character varying NOT NULL,
    logo character varying,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    metadata character varying,
    billing_plan character varying DEFAULT 'free'::character varying,
    billing_seats numeric DEFAULT 5,
    owner_id integer,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: organizations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.organizations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: organizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.organizations_id_seq OWNED BY public.organizations.id;


--
-- Name: organizations_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations_tags (
    _order integer NOT NULL,
    _parent_id integer NOT NULL,
    id character varying NOT NULL,
    label character varying
);


--
-- Name: payload_kv; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_kv (
    id integer NOT NULL,
    key character varying NOT NULL,
    data jsonb NOT NULL
);


--
-- Name: payload_kv_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payload_kv_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payload_kv_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payload_kv_id_seq OWNED BY public.payload_kv.id;


--
-- Name: payload_locked_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_locked_documents (
    id integer NOT NULL,
    global_slug character varying,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: payload_locked_documents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payload_locked_documents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payload_locked_documents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payload_locked_documents_id_seq OWNED BY public.payload_locked_documents.id;


--
-- Name: payload_locked_documents_rels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_locked_documents_rels (
    id integer NOT NULL,
    "order" integer,
    parent_id integer NOT NULL,
    path character varying NOT NULL,
    users_id integer,
    sessions_id integer,
    accounts_id integer,
    verifications_id integer,
    organizations_id integer,
    members_id integer,
    invitations_id integer,
    api_keys_id integer,
    jwks_id integer,
    admin_invitations_id integer
);


--
-- Name: payload_locked_documents_rels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payload_locked_documents_rels_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payload_locked_documents_rels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payload_locked_documents_rels_id_seq OWNED BY public.payload_locked_documents_rels.id;


--
-- Name: payload_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_migrations (
    id integer NOT NULL,
    name character varying,
    batch numeric,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: payload_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payload_migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payload_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payload_migrations_id_seq OWNED BY public.payload_migrations.id;


--
-- Name: payload_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_preferences (
    id integer NOT NULL,
    key character varying,
    value jsonb,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: payload_preferences_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payload_preferences_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payload_preferences_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payload_preferences_id_seq OWNED BY public.payload_preferences.id;


--
-- Name: payload_preferences_rels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_preferences_rels (
    id integer NOT NULL,
    "order" integer,
    parent_id integer NOT NULL,
    path character varying NOT NULL,
    users_id integer
);


--
-- Name: payload_preferences_rels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payload_preferences_rels_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payload_preferences_rels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payload_preferences_rels_id_seq OWNED BY public.payload_preferences_rels.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id integer NOT NULL,
    expires_at timestamp(3) with time zone NOT NULL,
    token character varying NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    ip_address character varying,
    user_agent character varying,
    user_id integer NOT NULL,
    active_organization_id integer
);


--
-- Name: sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sessions_id_seq OWNED BY public.sessions.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    name character varying NOT NULL,
    email character varying NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    image character varying,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    department character varying
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: users_role; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users_role (
    "order" integer NOT NULL,
    parent_id integer NOT NULL,
    value public.enum_users_role,
    id integer NOT NULL
);


--
-- Name: users_role_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_role_id_seq OWNED BY public.users_role.id;


--
-- Name: verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verifications (
    id integer NOT NULL,
    identifier character varying NOT NULL,
    value character varying NOT NULL,
    expires_at timestamp(3) with time zone NOT NULL,
    created_at timestamp(3) with time zone DEFAULT now() NOT NULL,
    updated_at timestamp(3) with time zone DEFAULT now() NOT NULL
);


--
-- Name: verifications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.verifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: verifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.verifications_id_seq OWNED BY public.verifications.id;


--
-- Name: accounts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts ALTER COLUMN id SET DEFAULT nextval('public.accounts_id_seq'::regclass);


--
-- Name: admin_invitations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_invitations ALTER COLUMN id SET DEFAULT nextval('public.admin_invitations_id_seq'::regclass);


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys ALTER COLUMN id SET DEFAULT nextval('public.api_keys_id_seq'::regclass);


--
-- Name: invitations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations ALTER COLUMN id SET DEFAULT nextval('public.invitations_id_seq'::regclass);


--
-- Name: jwks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jwks ALTER COLUMN id SET DEFAULT nextval('public.jwks_id_seq'::regclass);


--
-- Name: members id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.members ALTER COLUMN id SET DEFAULT nextval('public.members_id_seq'::regclass);


--
-- Name: organizations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations ALTER COLUMN id SET DEFAULT nextval('public.organizations_id_seq'::regclass);


--
-- Name: payload_kv id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_kv ALTER COLUMN id SET DEFAULT nextval('public.payload_kv_id_seq'::regclass);


--
-- Name: payload_locked_documents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents ALTER COLUMN id SET DEFAULT nextval('public.payload_locked_documents_id_seq'::regclass);


--
-- Name: payload_locked_documents_rels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels ALTER COLUMN id SET DEFAULT nextval('public.payload_locked_documents_rels_id_seq'::regclass);


--
-- Name: payload_migrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_migrations ALTER COLUMN id SET DEFAULT nextval('public.payload_migrations_id_seq'::regclass);


--
-- Name: payload_preferences id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_preferences ALTER COLUMN id SET DEFAULT nextval('public.payload_preferences_id_seq'::regclass);


--
-- Name: payload_preferences_rels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_preferences_rels ALTER COLUMN id SET DEFAULT nextval('public.payload_preferences_rels_id_seq'::regclass);


--
-- Name: sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions ALTER COLUMN id SET DEFAULT nextval('public.sessions_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: users_role id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_role ALTER COLUMN id SET DEFAULT nextval('public.users_role_id_seq'::regclass);


--
-- Name: verifications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verifications ALTER COLUMN id SET DEFAULT nextval('public.verifications_id_seq'::regclass);


--
-- Data for Name: accounts; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.accounts VALUES (1, '1', 'credential', 1, NULL, NULL, NULL, NULL, NULL, NULL, 'b526c99288cdeb9e90d3b2925dfac624:9fa28f896afc4cc359b62b2d11f8c1946a49c3a030bece5a7527e9b3ece9fdb162bb58632cf30ff2185cc424c2df75b6a53cc9e4cc18697cdf014fe34ee1ec75', '2026-10-14 19:44:24.659+00', '2026-10-14 19:44:24.659+00');
INSERT INTO public.accounts VALUES (2, '2', 'credential', 2, NULL, NULL, NULL, NULL, NULL, NULL, '9dd9d23213ef90810d406adbea280dd3:727d3a3395440d7bb5d9b5daac9b253019863211da8d4ebe78da1418fab5547f84e7f2b68faa1dcc835b2c81a6df19aa3e04c7117613ec99dc963ab7d9208b91', '2026-10-14 19:44:24.714+00', '2026-10-14 19:44:24.714+00');
INSERT INTO public.accounts VALUES (3, '3', 'credential', 3, NULL, NULL, NULL, NULL, NULL, NULL, '1c437e7d3c20600a968922aaae207b62:5249a682ebb0882c6a0e3db5b057f629f66f25bb99ff93cbc01ae26450f40582dbbc20034811e5f2f3001c3e93ac2288597677b5414ada91f2a86f111716bec4', '2026-10-14 19:44:24.771+00', '2026-10-14 19:44:24.771+00');
INSERT INTO public.accounts VALUES (4, '4', 'credential', 4, NULL, NULL, NULL, NULL, NULL, NULL, '697d3c974104d46194bbe68bea84a57d:c3029af0da1334bcafba98bc32fc41e5856945cca04a5639407378ffd273db763f019d6d03656bb9b0da4f0bc8a29c4fd7df0402deba25a20dd127e41176144b', '2026-10-14 19:44:24.834+00', '2026-10-14 19:44:24.834+00');
INSERT INTO public.accounts VALUES (5, 'google-407', 'google', 1, 'at_google_fixture', 'rt_google_fixture', 'eyJ fixture id token', '2026-10-14 20:44:24.891+00', '2026-11-13 19:44:24.891+00', 'openid email profile', NULL, '2026-10-14 19:44:24.892+00', '2026-10-14 19:44:24.892+00');
INSERT INTO public.accounts VALUES (6, 'carol@partner.example', 'generic-oauth', 3, 'at_generic_fixture', NULL, NULL, NULL, NULL, 'read', NULL, '2026-10-14 19:44:24.895+00', '2026-10-14 19:44:24.895+00');


--
-- Data for Name: admin_invitations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: api_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.api_keys VALUES (1, 'default', 'ci-key', 'gndWvi', '1', NULL, 'vf_pCPNDHseduIVOCvesmMjq6kAXe3M1dUiadklchjU', NULL, NULL, NULL, true, true, 60000, 100, 0, 97, NULL, NULL, '2026-10-14 19:44:25.116+00', '2026-10-14 19:44:25.116+00', NULL, '{"env":"ci","scopes":["pages.read","pages.write"]}');
INSERT INTO public.api_keys VALUES (2, 'default', 'read-only', 'Ctzrnd', '3', NULL, 'pL2G-YX_FGAmuSfNA-ht-OKQJJtByrVtnsSjxzK_lj4', NULL, NULL, NULL, true, true, 86400000, 10, 0, NULL, NULL, NULL, '2026-10-14 19:44:25.126+00', '2026-10-14 19:44:25.126+00', NULL, '{"env":"prod","scopes":["pages.read"]}');


--
-- Data for Name: invitations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.invitations VALUES (1, 1, 'bob@example.com', '["member"]', 'pending', '2026-10-16 19:44:25.048+00', '2026-10-14 19:44:25.048+00', 1, '2026-10-14 19:44:25.049+00');
INSERT INTO public.invitations VALUES (2, 1, 'carol@example.com', '["member"]', 'pending', '2026-10-16 19:44:25.092+00', '2026-10-14 19:44:25.092+00', 1, '2026-10-14 19:44:25.092+00');


--
-- Data for Name: jwks; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.jwks VALUES (1, '{"crv":"Ed25519","kty":"OKP","x":"-ln9xxpdIiI_mRn2E_EGSj6AlvQrEEEk3rI7tUusiqo"}', '"4ed3cdd4b251aad7d2c49a395501149f7295be21d4896327505f0d8ab20d7a437e59685fe3ef4b488001c7d249a02a3f82dbb7630ccad4b05869a5e02c4218d513fe07f1590477c8ef2a7f5749d670947b4dbd024e17c0224a5e72570b1ed4764808f1427c040faf90b7bfe5780b8bbba385d6e52ef9172a8be0f1f60e542529d9cdbb5e86484c2334404a1abc723366b20c59e16a02d10fa1d9b49d34652792c160575a3a4e4ec584"', '2026-10-14 19:44:25.136+00', NULL, '2026-10-14 19:44:25.137+00');


--
-- Data for Name: members; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.members VALUES (1, 1, 1, 'owner', '2026-10-14 19:44:25.019+00', '2026-10-14 19:44:25.031+00');
INSERT INTO public.members VALUES (2, 1, 2, '["admin"]', '2026-10-14 19:44:25.062+00', '2026-10-14 19:44:25.081+00');
INSERT INTO public.members VALUES (3, 2, 3, '["owner"]', '2026-10-14 19:44:25.108+00', '2026-10-14 19:44:25.109+00');


--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.organizations VALUES (1, 'Acme Inc', 'acme', NULL, '2026-10-14 19:44:25.014+00', NULL, 'pro', 12, 1, '2026-10-14 19:44:25.096+00');
INSERT INTO public.organizations VALUES (2, 'Globex', 'globex', NULL, '2026-10-14 19:44:25.105+00', NULL, 'free', 5, NULL, '2026-10-14 19:44:25.106+00');


--
-- Data for Name: organizations_tags; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.organizations_tags VALUES (1, 1, '6acfdb992289b253c3288de4', 'launch');
INSERT INTO public.organizations_tags VALUES (2, 1, '6acfdb992289b253c3288de5', 'beta');


--
-- Data for Name: payload_kv; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: payload_locked_documents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: payload_locked_documents_rels; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: payload_migrations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.payload_migrations VALUES (1, 'dev', -1, '2026-10-14 19:44:24.582+00', '2026-10-14 19:44:24.582+00');


--
-- Data for Name: payload_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: payload_preferences_rels; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.sessions VALUES (1, '2026-10-21 19:44:24.663+00', 'LkTFDDg6bYamxAoa2EKyQ1izUniMjJP5', '2026-10-14 19:44:24.663+00', '2026-10-14 19:44:24.663+00', '', '', 1, NULL);
INSERT INTO public.sessions VALUES (2, '2026-10-21 19:44:24.717+00', '4ehotbjD5MjNs9cxaXY2HCzw92K7k2k1', '2026-10-14 19:44:24.717+00', '2026-10-14 19:44:24.717+00', '', '', 2, NULL);
INSERT INTO public.sessions VALUES (3, '2026-10-21 19:44:24.776+00', 'z47V8zg4Jl5RL9z7yLeIj2rS8bf888lQ', '2026-10-14 19:44:24.776+00', '2026-10-14 19:44:24.776+00', '', '', 3, NULL);
INSERT INTO public.sessions VALUES (4, '2026-10-21 19:44:24.838+00', 'U2tQVpsn69Zdk2TYcvTkXhS9X022SqJW', '2026-10-14 19:44:24.838+00', '2026-10-14 19:44:24.838+00', '', '', 4, NULL);
INSERT INTO public.sessions VALUES (6, '2026-10-21 19:44:24.995+00', 'tZcAlZscidoEfiUA3Xox1imFah8neBqt', '2026-10-14 19:44:24.995+00', '2026-10-14 19:44:25.026+00', '', '', 1, 1);
INSERT INTO public.sessions VALUES (5, '2026-10-21 19:44:24.943+00', 'R8qdwiuNZQraPserkoySaavaK6HfpTyv', '2026-10-14 19:44:24.943+00', '2026-10-14 19:44:25.112+00', '', '', 3, 2);


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.users VALUES (4, 'Dave Unverified', 'dave@example.com', false, NULL, '2026-10-14 19:44:24.828+00', '2026-10-14 19:44:24.828+00', NULL);
INSERT INTO public.users VALUES (1, 'Alice Admin', 'alice@example.com', true, NULL, '2026-10-14 19:44:24.644+00', '2026-10-14 19:44:24.874+00', NULL);
INSERT INTO public.users VALUES (2, 'Bob Unverified', 'bob@example.com', false, NULL, '2026-10-14 19:44:24.71+00', '2026-10-14 19:44:24.882+00', 'frontend');
INSERT INTO public.users VALUES (3, 'Carol Member', 'carol@example.com', true, NULL, '2026-10-14 19:44:24.763+00', '2026-10-14 19:44:24.889+00', 'ops');


--
-- Data for Name: users_role; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.users_role VALUES (1, 4, 'user', 4);
INSERT INTO public.users_role VALUES (1, 1, 'admin', 7);
INSERT INTO public.users_role VALUES (1, 2, 'frontPlugin', 8);
INSERT INTO public.users_role VALUES (2, 2, 'user', 9);
INSERT INTO public.users_role VALUES (1, 3, 'user', 10);


--
-- Data for Name: verifications; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.verifications VALUES (1, 'QjYsOglAPSUlZMvmSaGOCJVowkJIwQCs', '{"email":"carol@example.com"}', '2026-10-14 19:49:24.948+00', '2026-10-14 19:44:24.948+00', '2026-10-14 19:44:24.948+00');


--
-- Name: accounts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.accounts_id_seq', 6, true);


--
-- Name: admin_invitations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.admin_invitations_id_seq', 1, false);


--
-- Name: api_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.api_keys_id_seq', 2, true);


--
-- Name: invitations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.invitations_id_seq', 2, true);


--
-- Name: jwks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.jwks_id_seq', 1, true);


--
-- Name: members_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.members_id_seq', 3, true);


--
-- Name: organizations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.organizations_id_seq', 2, true);


--
-- Name: payload_kv_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.payload_kv_id_seq', 1, false);


--
-- Name: payload_locked_documents_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.payload_locked_documents_id_seq', 1, false);


--
-- Name: payload_locked_documents_rels_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.payload_locked_documents_rels_id_seq', 1, false);


--
-- Name: payload_migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.payload_migrations_id_seq', 1, true);


--
-- Name: payload_preferences_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.payload_preferences_id_seq', 1, false);


--
-- Name: payload_preferences_rels_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.payload_preferences_rels_id_seq', 1, false);


--
-- Name: sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sessions_id_seq', 6, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_id_seq', 4, true);


--
-- Name: users_role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.users_role_id_seq', 10, true);


--
-- Name: verifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.verifications_id_seq', 1, true);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: admin_invitations admin_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_invitations
    ADD CONSTRAINT admin_invitations_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


--
-- Name: jwks jwks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jwks
    ADD CONSTRAINT jwks_pkey PRIMARY KEY (id);


--
-- Name: members members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.members
    ADD CONSTRAINT members_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: organizations_tags organizations_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations_tags
    ADD CONSTRAINT organizations_tags_pkey PRIMARY KEY (id);


--
-- Name: payload_kv payload_kv_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_kv
    ADD CONSTRAINT payload_kv_pkey PRIMARY KEY (id);


--
-- Name: payload_locked_documents payload_locked_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents
    ADD CONSTRAINT payload_locked_documents_pkey PRIMARY KEY (id);


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_pkey PRIMARY KEY (id);


--
-- Name: payload_migrations payload_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_migrations
    ADD CONSTRAINT payload_migrations_pkey PRIMARY KEY (id);


--
-- Name: payload_preferences payload_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_preferences
    ADD CONSTRAINT payload_preferences_pkey PRIMARY KEY (id);


--
-- Name: payload_preferences_rels payload_preferences_rels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_preferences_rels
    ADD CONSTRAINT payload_preferences_rels_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users_role users_role_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_role
    ADD CONSTRAINT users_role_pkey PRIMARY KEY (id);


--
-- Name: verifications verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verifications
    ADD CONSTRAINT verifications_pkey PRIMARY KEY (id);


--
-- Name: accounts_account_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX accounts_account_id_idx ON public.accounts USING btree (account_id);


--
-- Name: accounts_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX accounts_created_at_idx ON public.accounts USING btree (created_at);


--
-- Name: accounts_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX accounts_updated_at_idx ON public.accounts USING btree (updated_at);


--
-- Name: accounts_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX accounts_user_idx ON public.accounts USING btree (user_id);


--
-- Name: admin_invitations_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_invitations_created_at_idx ON public.admin_invitations USING btree (created_at);


--
-- Name: admin_invitations_token_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_invitations_token_idx ON public.admin_invitations USING btree (token);


--
-- Name: admin_invitations_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_invitations_updated_at_idx ON public.admin_invitations USING btree (updated_at);


--
-- Name: api_keys_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_keys_created_at_idx ON public.api_keys USING btree (created_at);


--
-- Name: api_keys_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_keys_updated_at_idx ON public.api_keys USING btree (updated_at);


--
-- Name: invitations_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_email_idx ON public.invitations USING btree (email);


--
-- Name: invitations_inviter_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_inviter_idx ON public.invitations USING btree (inviter_id);


--
-- Name: invitations_organization_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_organization_idx ON public.invitations USING btree (organization_id);


--
-- Name: invitations_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_updated_at_idx ON public.invitations USING btree (updated_at);


--
-- Name: jwks_public_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX jwks_public_key_idx ON public.jwks USING btree (public_key);


--
-- Name: jwks_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX jwks_updated_at_idx ON public.jwks USING btree (updated_at);


--
-- Name: members_organization_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX members_organization_idx ON public.members USING btree (organization_id);


--
-- Name: members_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX members_updated_at_idx ON public.members USING btree (updated_at);


--
-- Name: members_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX members_user_idx ON public.members USING btree (user_id);


--
-- Name: organizations_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_owner_idx ON public.organizations USING btree (owner_id);


--
-- Name: organizations_slug_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organizations_slug_idx ON public.organizations USING btree (slug);


--
-- Name: organizations_tags_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_tags_order_idx ON public.organizations_tags USING btree (_order);


--
-- Name: organizations_tags_parent_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_tags_parent_id_idx ON public.organizations_tags USING btree (_parent_id);


--
-- Name: organizations_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_updated_at_idx ON public.organizations USING btree (updated_at);


--
-- Name: payload_kv_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX payload_kv_key_idx ON public.payload_kv USING btree (key);


--
-- Name: payload_locked_documents_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_created_at_idx ON public.payload_locked_documents USING btree (created_at);


--
-- Name: payload_locked_documents_global_slug_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_global_slug_idx ON public.payload_locked_documents USING btree (global_slug);


--
-- Name: payload_locked_documents_rels_accounts_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_accounts_id_idx ON public.payload_locked_documents_rels USING btree (accounts_id);


--
-- Name: payload_locked_documents_rels_admin_invitations_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_admin_invitations_id_idx ON public.payload_locked_documents_rels USING btree (admin_invitations_id);


--
-- Name: payload_locked_documents_rels_api_keys_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_api_keys_id_idx ON public.payload_locked_documents_rels USING btree (api_keys_id);


--
-- Name: payload_locked_documents_rels_invitations_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_invitations_id_idx ON public.payload_locked_documents_rels USING btree (invitations_id);


--
-- Name: payload_locked_documents_rels_jwks_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_jwks_id_idx ON public.payload_locked_documents_rels USING btree (jwks_id);


--
-- Name: payload_locked_documents_rels_members_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_members_id_idx ON public.payload_locked_documents_rels USING btree (members_id);


--
-- Name: payload_locked_documents_rels_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_order_idx ON public.payload_locked_documents_rels USING btree ("order");


--
-- Name: payload_locked_documents_rels_organizations_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_organizations_id_idx ON public.payload_locked_documents_rels USING btree (organizations_id);


--
-- Name: payload_locked_documents_rels_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_parent_idx ON public.payload_locked_documents_rels USING btree (parent_id);


--
-- Name: payload_locked_documents_rels_path_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_path_idx ON public.payload_locked_documents_rels USING btree (path);


--
-- Name: payload_locked_documents_rels_sessions_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_sessions_id_idx ON public.payload_locked_documents_rels USING btree (sessions_id);


--
-- Name: payload_locked_documents_rels_users_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_users_id_idx ON public.payload_locked_documents_rels USING btree (users_id);


--
-- Name: payload_locked_documents_rels_verifications_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_rels_verifications_id_idx ON public.payload_locked_documents_rels USING btree (verifications_id);


--
-- Name: payload_locked_documents_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_locked_documents_updated_at_idx ON public.payload_locked_documents USING btree (updated_at);


--
-- Name: payload_migrations_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_migrations_created_at_idx ON public.payload_migrations USING btree (created_at);


--
-- Name: payload_migrations_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_migrations_updated_at_idx ON public.payload_migrations USING btree (updated_at);


--
-- Name: payload_preferences_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_created_at_idx ON public.payload_preferences USING btree (created_at);


--
-- Name: payload_preferences_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_key_idx ON public.payload_preferences USING btree (key);


--
-- Name: payload_preferences_rels_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_rels_order_idx ON public.payload_preferences_rels USING btree ("order");


--
-- Name: payload_preferences_rels_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_rels_parent_idx ON public.payload_preferences_rels USING btree (parent_id);


--
-- Name: payload_preferences_rels_path_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_rels_path_idx ON public.payload_preferences_rels USING btree (path);


--
-- Name: payload_preferences_rels_users_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_rels_users_id_idx ON public.payload_preferences_rels USING btree (users_id);


--
-- Name: payload_preferences_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_preferences_updated_at_idx ON public.payload_preferences USING btree (updated_at);


--
-- Name: sessions_active_organization_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_active_organization_idx ON public.sessions USING btree (active_organization_id);


--
-- Name: sessions_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_created_at_idx ON public.sessions USING btree (created_at);


--
-- Name: sessions_token_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sessions_token_idx ON public.sessions USING btree (token);


--
-- Name: sessions_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_updated_at_idx ON public.sessions USING btree (updated_at);


--
-- Name: sessions_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_idx ON public.sessions USING btree (user_id);


--
-- Name: users_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_created_at_idx ON public.users USING btree (created_at);


--
-- Name: users_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_email_idx ON public.users USING btree (email);


--
-- Name: users_role_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_role_order_idx ON public.users_role USING btree ("order");


--
-- Name: users_role_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_role_parent_idx ON public.users_role USING btree (parent_id);


--
-- Name: users_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_updated_at_idx ON public.users USING btree (updated_at);


--
-- Name: verifications_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX verifications_created_at_idx ON public.verifications USING btree (created_at);


--
-- Name: verifications_identifier_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX verifications_identifier_idx ON public.verifications USING btree (identifier);


--
-- Name: verifications_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX verifications_updated_at_idx ON public.verifications USING btree (updated_at);


--
-- Name: accounts accounts_user_id_users_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: invitations invitations_inviter_id_users_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_inviter_id_users_id_fk FOREIGN KEY (inviter_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: invitations invitations_organization_id_organizations_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_organization_id_organizations_id_fk FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- Name: members members_organization_id_organizations_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.members
    ADD CONSTRAINT members_organization_id_organizations_id_fk FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- Name: members members_user_id_users_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.members
    ADD CONSTRAINT members_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: organizations organizations_owner_id_users_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_owner_id_users_id_fk FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: organizations_tags organizations_tags_parent_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations_tags
    ADD CONSTRAINT organizations_tags_parent_id_fk FOREIGN KEY (_parent_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_accounts_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_accounts_fk FOREIGN KEY (accounts_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_admin_invitations_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_admin_invitations_fk FOREIGN KEY (admin_invitations_id) REFERENCES public.admin_invitations(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_api_keys_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_api_keys_fk FOREIGN KEY (api_keys_id) REFERENCES public.api_keys(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_invitations_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_invitations_fk FOREIGN KEY (invitations_id) REFERENCES public.invitations(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_jwks_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_jwks_fk FOREIGN KEY (jwks_id) REFERENCES public.jwks(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_members_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_members_fk FOREIGN KEY (members_id) REFERENCES public.members(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_organizations_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_organizations_fk FOREIGN KEY (organizations_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_parent_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_parent_fk FOREIGN KEY (parent_id) REFERENCES public.payload_locked_documents(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_sessions_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_sessions_fk FOREIGN KEY (sessions_id) REFERENCES public.sessions(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_users_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_users_fk FOREIGN KEY (users_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: payload_locked_documents_rels payload_locked_documents_rels_verifications_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_locked_documents_rels
    ADD CONSTRAINT payload_locked_documents_rels_verifications_fk FOREIGN KEY (verifications_id) REFERENCES public.verifications(id) ON DELETE CASCADE;


--
-- Name: payload_preferences_rels payload_preferences_rels_parent_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_preferences_rels
    ADD CONSTRAINT payload_preferences_rels_parent_fk FOREIGN KEY (parent_id) REFERENCES public.payload_preferences(id) ON DELETE CASCADE;


--
-- Name: payload_preferences_rels payload_preferences_rels_users_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_preferences_rels
    ADD CONSTRAINT payload_preferences_rels_users_fk FOREIGN KEY (users_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_active_organization_id_organizations_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_active_organization_id_organizations_id_fk FOREIGN KEY (active_organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- Name: sessions sessions_user_id_users_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: users_role users_role_parent_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_role
    ADD CONSTRAINT users_role_parent_fk FOREIGN KEY (parent_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict ypcjhu0fhucKJgysf2UIhCjabW28k7BcgW8nxkOX2t4t7AJlAjS9Z2IvummiJQc

