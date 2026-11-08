package postgres

import (
	"context"
	"errors"
	"fmt"
)

var guardedRelations = []string{
	"eka_auth.identities",
	"eka_auth.grants",
	"public.collections",
	"public.app_users",
	"public.collection_grants",
}

// VerifySchema confirms that the connected database role is read-only except
// for guarded provisioning and that every policy table has active guard and
// revision triggers. It is a startup check, not proof that privileged owners
// or superusers cannot bypass database controls.
func (s *Store) VerifySchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("missing PostgreSQL store")
	}
	var superuser, bypassRLS, createDatabase, createRole, replication, databaseCreate, schemaCreate, ownerMember bool
	err := s.pool.QueryRow(ctx, `
		SELECT r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, r.rolreplication,
			pg_catalog.has_database_privilege(current_user, current_database(), 'CREATE'),
			EXISTS (
				SELECT 1 FROM pg_catalog.pg_namespace n
				WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
				  AND n.nspname NOT LIKE 'pg_toast%'
				  AND pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE')
			),
			EXISTS (
				SELECT 1 FROM pg_catalog.pg_proc p
				JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
				WHERE n.nspname = 'eka_auth'
				  AND p.proname IN ('resolve_oidc', 'guard_policy_write', 'bump_policy_revision')
				  AND pg_catalog.pg_has_role(current_user, p.proowner, 'MEMBER')
			)
		FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`,
	).Scan(&superuser, &bypassRLS, &createDatabase, &createRole, &replication, &databaseCreate, &schemaCreate, &ownerMember)
	if err != nil {
		return fmt.Errorf("verify policy database role: %w", err)
	}
	if superuser || bypassRLS || createDatabase || createRole || replication || databaseCreate || schemaCreate || ownerMember {
		return fmt.Errorf("database runtime role is privileged (superuser=%t bypassRLS=%t createDatabase=%t createRole=%t replication=%t databaseCreate=%t schemaCreate=%t ownerMembership=%t)",
			superuser, bypassRLS, createDatabase, createRole, replication, databaseCreate, schemaCreate, ownerMember)
	}
	var schemaUsage, controlSelect, identitySelect, grantSelect, collectionIDSelect bool
	var controlWrite, identityWrite, grantWrite, collectionWrite bool
	err = s.pool.QueryRow(ctx, `
		SELECT
			pg_catalog.has_schema_privilege(current_user, 'eka_auth', 'USAGE'),
			pg_catalog.has_table_privilege(current_user, 'eka_auth.control', 'SELECT'),
			pg_catalog.has_table_privilege(current_user, 'eka_auth.identities', 'SELECT'),
			pg_catalog.has_table_privilege(current_user, 'eka_auth.grants', 'SELECT'),
			pg_catalog.has_column_privilege(current_user, 'public.collections', 'id', 'SELECT'),
			pg_catalog.has_table_privilege(current_user, 'eka_auth.control', 'INSERT')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.control', 'UPDATE')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.control', 'DELETE')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.control', 'TRUNCATE'),
			pg_catalog.has_table_privilege(current_user, 'eka_auth.identities', 'INSERT')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.identities', 'UPDATE')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.identities', 'DELETE')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.identities', 'TRUNCATE')
				OR pg_catalog.has_any_column_privilege(current_user, 'eka_auth.identities', 'INSERT')
				OR pg_catalog.has_any_column_privilege(current_user, 'eka_auth.identities', 'UPDATE'),
			pg_catalog.has_table_privilege(current_user, 'eka_auth.grants', 'INSERT')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.grants', 'UPDATE')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.grants', 'DELETE')
				OR pg_catalog.has_table_privilege(current_user, 'eka_auth.grants', 'TRUNCATE')
				OR pg_catalog.has_any_column_privilege(current_user, 'eka_auth.grants', 'INSERT')
				OR pg_catalog.has_any_column_privilege(current_user, 'eka_auth.grants', 'UPDATE'),
			pg_catalog.has_table_privilege(current_user, 'public.collections', 'INSERT')
				OR pg_catalog.has_table_privilege(current_user, 'public.collections', 'UPDATE')
				OR pg_catalog.has_table_privilege(current_user, 'public.collections', 'DELETE')
				OR pg_catalog.has_table_privilege(current_user, 'public.collections', 'TRUNCATE')
				OR pg_catalog.has_table_privilege(current_user, 'public.collections', 'TRIGGER')
				OR pg_catalog.has_any_column_privilege(current_user, 'public.collections', 'INSERT')
				OR pg_catalog.has_any_column_privilege(current_user, 'public.collections', 'UPDATE')
				OR pg_catalog.has_any_column_privilege(current_user, 'public.collections', 'REFERENCES')`).Scan(
		&schemaUsage, &controlSelect, &identitySelect, &grantSelect, &collectionIDSelect,
		&controlWrite, &identityWrite, &grantWrite, &collectionWrite)
	if err != nil {
		return fmt.Errorf("verify policy read and write privileges: %w", err)
	}
	if !schemaUsage || !controlSelect || !identitySelect || !grantSelect || !collectionIDSelect ||
		controlWrite || identityWrite || grantWrite || collectionWrite {
		return errors.New("database runtime grants are unsafe")
	}
	var procedureOK bool
	err = s.pool.QueryRow(ctx, `
		SELECT pg_catalog.has_function_privilege(current_user, 'eka_auth.resolve_oidc(text,text)', 'EXECUTE')
			AND NOT EXISTS (
				SELECT 1 FROM pg_catalog.pg_roles privileged
				WHERE (privileged.rolsuper OR privileged.rolbypassrls OR privileged.rolcreatedb
					OR privileged.rolcreaterole OR privileged.rolreplication)
				  AND pg_catalog.pg_has_role(current_user, privileged.oid, 'MEMBER')
			)
			AND NOT EXISTS (
				SELECT 1 FROM pg_catalog.pg_proc p
				JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
				CROSS JOIN LATERAL pg_catalog.aclexplode(
					coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
				WHERE n.nspname = 'eka_auth' AND p.proname = 'resolve_oidc'
				  AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'
			)
			AND (SELECT p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']
					AND NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
					FROM pg_catalog.pg_proc p
					JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
					JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = p.proowner
					WHERE n.nspname = 'eka_auth' AND p.proname = 'resolve_oidc'
					  AND p.oid = 'eka_auth.resolve_oidc(text,text)'::regprocedure)`).Scan(&procedureOK)
	if err != nil {
		return fmt.Errorf("verify OIDC provisioning procedure: %w", err)
	}
	if !procedureOK {
		return errors.New("OIDC provisioning procedure is missing or unsafe")
	}
	var controlOK bool
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) = 1 AND bool_and(epoch <> '00000000-0000-0000-0000-000000000000'::uuid AND revision >= 0)
		FROM eka_auth.control WHERE singleton = true`).Scan(&controlOK)
	if err != nil {
		return fmt.Errorf("verify policy revision control: %w", err)
	}
	if !controlOK {
		return errors.New("policy revision control is missing or invalid")
	}
	for _, relation := range guardedRelations {
		var beforeGuard, afterRevision bool
		err := s.pool.QueryRow(ctx, `
			SELECT
				(SELECT count(*) = 1 FROM pg_catalog.pg_trigger t
					JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
					JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
					JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = p.proowner
					WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgenabled = 'O'
					  AND (t.tgtype & 1) = 0 AND (t.tgtype & 2) = 2 AND (t.tgtype & 60) = 60
					  AND n.nspname = 'eka_auth' AND p.proname = 'guard_policy_write'
					  AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']
					  AND NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
					  AND NOT EXISTS (
						SELECT 1 FROM pg_catalog.aclexplode(
							coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
						WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')),
				(SELECT count(*) = 1 FROM pg_catalog.pg_trigger t
					JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
					JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
					JOIN pg_catalog.pg_roles owner_role ON owner_role.oid = p.proowner
					WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgenabled = 'O'
					  AND (t.tgtype & 1) = 0 AND (t.tgtype & 2) = 0 AND (t.tgtype & 60) = 60
					  AND n.nspname = 'eka_auth' AND p.proname = 'bump_policy_revision'
					  AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']
					  AND NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
					  AND NOT EXISTS (
						SELECT 1 FROM pg_catalog.aclexplode(
							coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
						WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))`, relation).Scan(&beforeGuard, &afterRevision)
		if err != nil {
			return fmt.Errorf("verify policy guards on %s: %w", relation, err)
		}
		if !beforeGuard || !afterRevision {
			return fmt.Errorf("policy guard or revision trigger missing on %s", relation)
		}
	}
	var collectionFieldsOK bool
	err = s.pool.QueryRow(ctx, `
		SELECT NOT pg_catalog.has_table_privilege(current_user, 'public.collections', 'SELECT')
			AND NOT EXISTS (
				SELECT 1 FROM pg_catalog.pg_attribute a
				WHERE a.attrelid = 'public.collections'::regclass
				  AND a.attnum > 0 AND NOT a.attisdropped AND a.attname <> 'id'
				  AND pg_catalog.has_column_privilege(current_user, a.attrelid, a.attnum, 'SELECT')
			)`).Scan(&collectionFieldsOK)
	if err != nil {
		return fmt.Errorf("verify collection-column privileges: %w", err)
	}
	if !collectionFieldsOK {
		return errors.New("policy runtime can read collection fields beyond the collection ID")
	}
	var hasWritePrivileges bool
	err = s.pool.QueryRow(ctx, `
		SELECT pg_catalog.has_any_column_privilege(current_user, 'public.app_users', 'INSERT')
			OR pg_catalog.has_any_column_privilege(current_user, 'public.app_users', 'UPDATE')
			OR pg_catalog.has_any_column_privilege(current_user, 'public.app_users', 'REFERENCES')
			OR pg_catalog.has_table_privilege(current_user, 'public.app_users', 'DELETE')
			OR pg_catalog.has_table_privilege(current_user, 'public.app_users', 'TRUNCATE')
			OR pg_catalog.has_table_privilege(current_user, 'public.app_users', 'TRIGGER')
			OR pg_catalog.has_any_column_privilege(current_user, 'public.collection_grants', 'INSERT')
			OR pg_catalog.has_any_column_privilege(current_user, 'public.collection_grants', 'UPDATE')
			OR pg_catalog.has_any_column_privilege(current_user, 'public.collection_grants', 'REFERENCES')
			OR pg_catalog.has_table_privilege(current_user, 'public.collection_grants', 'DELETE')
			OR pg_catalog.has_table_privilege(current_user, 'public.collection_grants', 'TRUNCATE')
			OR pg_catalog.has_table_privilege(current_user, 'public.collection_grants', 'TRIGGER')`).Scan(&hasWritePrivileges)
	if err != nil {
		return fmt.Errorf("verify legacy and collection privileges: %w", err)
	}
	if hasWritePrivileges {
		return errors.New("policy runtime has legacy-policy or collection write privileges")
	}
	return nil
}
