-- ISOLATED TEST CANDIDATE ONLY. Not a migration or a production role setup.
-- It does not implement manifest-controlled migration or deployment roles.
-- The caller must provide an empty disposable database and synthetic public
-- collections, app_users and collection_grants.
CREATE SCHEMA eka_auth;
REVOKE ALL ON SCHEMA eka_auth FROM PUBLIC;

CREATE TABLE eka_auth.control (
    singleton boolean PRIMARY KEY CHECK (singleton),
    frozen boolean NOT NULL,
    epoch uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 0)
);
INSERT INTO eka_auth.control VALUES (true, false, gen_random_uuid(), 0);

CREATE TABLE eka_auth.identities (
    identity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL,
    issuer text COLLATE "C",
    subject text COLLATE "C",
    local_namespace text COLLATE "C",
    username text COLLATE "C",
    role text NOT NULL CHECK (role IN ('ADMIN', 'MEMBER')),
    CHECK (
        (kind = 'OIDC' AND issuer IS NOT NULL AND issuer <> '' AND subject IS NOT NULL AND subject <> ''
         AND local_namespace IS NULL AND username IS NULL)
        OR
        (kind = 'LOCAL' AND local_namespace IS NOT NULL AND local_namespace <> ''
         AND username IS NOT NULL AND username <> '' AND issuer IS NULL AND subject IS NULL)
    )
);
CREATE UNIQUE INDEX identities_oidc ON eka_auth.identities (issuer, subject) WHERE kind = 'OIDC';
CREATE UNIQUE INDEX identities_local ON eka_auth.identities (local_namespace, username) WHERE kind = 'LOCAL';

CREATE TABLE eka_auth.grants (
    identity_id uuid NOT NULL REFERENCES eka_auth.identities ON DELETE CASCADE,
    collection_id uuid NOT NULL REFERENCES public.collections ON DELETE CASCADE,
    permission text NOT NULL CHECK (permission IN ('READ', 'MANAGE')),
    PRIMARY KEY (identity_id, collection_id)
);
CREATE INDEX grants_collection ON eka_auth.grants (collection_id);

-- The test-only advisory key is not allocated for a real deployment.
CREATE FUNCTION eka_auth.guard_policy_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE is_frozen boolean;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(19201, 13001);
    SELECT c.frozen INTO STRICT is_frozen FROM eka_auth.control AS c
    WHERE c.singleton = true FOR UPDATE;
    IF is_frozen THEN
        RAISE EXCEPTION 'policy writes frozen' USING ERRCODE = '55000';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION eka_auth.bump_policy_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    UPDATE eka_auth.control SET revision = revision + 1
    WHERE singleton = true AND revision < 9223372036854775807;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'policy revision unavailable' USING ERRCODE = '55000';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION eka_auth.test_set_freeze(p_frozen boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF p_frozen IS NULL THEN
        RAISE EXCEPTION 'invalid freeze state' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(19201, 13001);
    UPDATE eka_auth.control SET frozen = p_frozen WHERE singleton = true;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'freeze control unavailable' USING ERRCODE = '55000';
    END IF;
END $$;

-- A fresh epoch must come from outside the restored snapshot. This test helper
-- neither generates nor verifies freshness against previously issued epochs.
CREATE FUNCTION eka_auth.test_restore_epoch(p_epoch uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE is_frozen boolean; old_epoch uuid;
BEGIN
    IF p_epoch IS NULL OR p_epoch = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'invalid restore epoch' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(19201, 13001);
    SELECT c.frozen, c.epoch INTO STRICT is_frozen, old_epoch
    FROM eka_auth.control AS c WHERE c.singleton = true FOR UPDATE;
    IF NOT is_frozen OR p_epoch = old_epoch THEN
        RAISE EXCEPTION 'restore requires frozen policy and a fresh epoch' USING ERRCODE = '55000';
    END IF;
    UPDATE eka_auth.control SET epoch = p_epoch, revision = 0 WHERE singleton = true;
END $$;

CREATE FUNCTION eka_auth.resolve_oidc(p_issuer text, p_subject text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE is_frozen boolean;
BEGIN
    IF p_issuer IS NULL OR p_issuer = '' OR p_subject IS NULL OR p_subject = '' THEN
        RAISE EXCEPTION 'invalid identity' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(19201, 13001);
    SELECT c.frozen INTO STRICT is_frozen FROM eka_auth.control AS c
    WHERE c.singleton = true FOR UPDATE;
    IF EXISTS (SELECT 1 FROM eka_auth.identities
               WHERE kind = 'OIDC' AND issuer = p_issuer AND subject = p_subject) THEN
        RETURN 'EXISTING';
    END IF;
    IF is_frozen THEN
        RAISE EXCEPTION 'policy writes frozen' USING ERRCODE = '55000';
    END IF;
    INSERT INTO eka_auth.identities (kind, issuer, subject, role)
    VALUES ('OIDC', p_issuer, p_subject, 'MEMBER');
    RETURN 'CREATED';
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA eka_auth FROM PUBLIC;
REVOKE ALL ON FUNCTION eka_auth.guard_policy_write() FROM PUBLIC;
REVOKE ALL ON FUNCTION eka_auth.bump_policy_revision() FROM PUBLIC;
REVOKE ALL ON FUNCTION eka_auth.test_set_freeze(boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION eka_auth.test_restore_epoch(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION eka_auth.resolve_oidc(text, text) FROM PUBLIC;

CREATE TRIGGER test_guard_identities BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON eka_auth.identities FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.guard_policy_write();
CREATE TRIGGER test_revision_identities AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE
ON eka_auth.identities FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.bump_policy_revision();
CREATE TRIGGER test_guard_grants BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON eka_auth.grants FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.guard_policy_write();
CREATE TRIGGER test_revision_grants AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE
ON eka_auth.grants FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.bump_policy_revision();
CREATE TRIGGER test_guard_collections BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON public.collections FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.guard_policy_write();
CREATE TRIGGER test_revision_collections AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE
ON public.collections FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.bump_policy_revision();
CREATE TRIGGER test_guard_legacy_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON public.app_users FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.guard_policy_write();
CREATE TRIGGER test_revision_legacy_users AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE
ON public.app_users FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.bump_policy_revision();
CREATE TRIGGER test_guard_legacy_grants BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON public.collection_grants FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.guard_policy_write();
CREATE TRIGGER test_revision_legacy_grants AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE
ON public.collection_grants FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.bump_policy_revision();
