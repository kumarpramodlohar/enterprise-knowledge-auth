-- ISOLATED TEST CANDIDATE ONLY. Requires an instance created for testing.
-- Does not provision production identities, migration privileges or secrets.
CREATE ROLE eka_auth_candidate_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE eka_auth_candidate_schema LOGIN PASSWORD 'synthetic-only'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT eka_auth_candidate_owner TO eka_auth_candidate_schema;
GRANT TRIGGER ON public.collections, public.app_users, public.collection_grants TO eka_auth_candidate_owner;
GRANT REFERENCES (id) ON public.collections TO eka_auth_candidate_owner;
