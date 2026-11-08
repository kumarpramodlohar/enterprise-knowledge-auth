package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/compatibility"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
)

func TestPostgresStoreIntegration(t *testing.T) {
	dsn := os.Getenv("EKA_SYNTHETIC_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("EKA_REQUIRE_POSTGRES_TEST") == "1" {
			t.Fatal("PostgreSQL integration test is required but its DSN is not configured")
		}
		t.Skip("EKA_SYNTHETIC_POSTGRES_DSN is not configured for a disposable database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var db string
	var empty bool
	if err := pool.QueryRow(ctx, `SELECT current_database(), NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eka_auth') AND to_regclass('public.collections') IS NULL AND to_regclass('public.app_users') IS NULL AND to_regclass('public.collection_grants') IS NULL`).Scan(&db, &empty); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(db, "eka_auth_test_") || !empty {
		t.Fatal("integration tests require a new, empty synthetic database named eka_auth_test_*")
	}
	fixture, err := os.ReadFile("testdata/guarded_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE public.collections (id uuid PRIMARY KEY, private_test_field text);
		CREATE TABLE public.app_users (
			subject text PRIMARY KEY, display_name text, role text NOT NULL CHECK (role IN ('ADMIN', 'MEMBER')),
			created_at timestamptz NOT NULL DEFAULT now());
		CREATE TABLE public.collection_grants (
			subject text NOT NULL REFERENCES public.app_users(subject) ON DELETE CASCADE,
			collection_id uuid NOT NULL REFERENCES public.collections(id) ON DELETE CASCADE,
			permission text NOT NULL CHECK (permission IN ('READ', 'MANAGE')),
			PRIMARY KEY(subject, collection_id))`); err != nil {
		t.Fatal(err)
	}
	ownership, err := os.ReadFile("testdata/guarded_ownership.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(ownership)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `REASSIGN OWNED BY eka_auth_candidate_owner TO CURRENT_USER; DROP OWNED BY eka_auth_candidate_owner; DROP OWNED BY eka_auth_candidate_schema; DROP ROLE eka_auth_candidate_schema; DROP ROLE eka_auth_candidate_owner`); err != nil {
			t.Errorf("remove test owner role: %v", err)
		}
	}()
	if _, err := pool.Exec(ctx, `GRANT CREATE ON DATABASE `+pgx.Identifier{db}.Sanitize()+` TO eka_auth_candidate_owner`); err != nil {
		t.Fatal(err)
	}
	cfg := pool.Config().ConnConfig
	cfg.User, cfg.Password = "eka_auth_candidate_schema", "synthetic-only"
	installer, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot connect as synthetic schema installer")
	}
	defer func() {
		if err := installer.Close(context.Background()); err != nil {
			t.Errorf("close synthetic schema installer: %v", err)
		}
	}()
	var installerIsRestricted bool
	if err := installer.QueryRow(ctx, `SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&installerIsRestricted); err != nil || !installerIsRestricted {
		t.Fatalf("invalid synthetic schema installer: %v", err)
	}
	if _, err := installer.Exec(ctx, `SET ROLE eka_auth_candidate_owner`); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Exec(ctx, string(fixture)); err != nil {
		t.Fatalf("restricted schema installation failed: %v", err)
	}
	if _, err := installer.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `REVOKE TRIGGER ON public.collections, public.app_users, public.collection_grants FROM eka_auth_candidate_owner;
		REVOKE REFERENCES (id) ON public.collections FROM eka_auth_candidate_owner;
		REVOKE CREATE ON DATABASE `+pgx.Identifier{db}.Sanitize()+` FROM eka_auth_candidate_owner;
		REVOKE eka_auth_candidate_owner FROM eka_auth_candidate_schema`); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Exec(ctx, `SET ROLE eka_auth_candidate_owner`); err == nil {
		t.Fatal("schema installer retained owner role after membership revocation")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("unexpected installer role rejection: %v", err)
		}
	}
	verifyCandidateOwner(t, ctx, pool)
	if result, err := compatibility.Check(ctx, pool, compatibility.Config{Kind: "OIDC", Issuer: "issuer"}); err != nil || result.Total != 0 {
		t.Fatalf("empty legacy compatibility scan: %+v %v", result, err)
	}
	if _, err := compatibility.Check(ctx, pool, compatibility.Config{Kind: "OIDC", Issuer: strings.Repeat("x", contract.MaxFieldSize+1)}); err == nil {
		t.Fatal("oversized issuer accepted for compatibility scan")
	}
	store, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	oidc := contract.Identity{Kind: "OIDC", Issuer: "issuer", Subject: "alice"}
	local := contract.Identity{Kind: "LOCAL", Namespace: "dev", Username: "alice"}
	status, err := store.Resolve(ctx, local)
	if err != nil || status != service.NotFound {
		t.Fatalf("unknown local: %s %v", status, err)
	}
	role, grant, err := store.Check(ctx, local, [16]byte{})
	if err != nil || role != policy.None || grant != nil {
		t.Fatalf("unknown local check: %s %v %v", role, grant, err)
	}
	if _, _, err := store.Check(ctx, oidc, [16]byte{}); !errors.Is(err, errMissingOIDC) {
		t.Fatalf("missing OIDC: %v", err)
	}

	const parallel = 8
	results := make(chan service.ResolveStatus, parallel)
	errorsFound := make(chan error, parallel)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := store.Resolve(ctx, oidc)
			results <- result
			errorsFound <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent resolve: %v", err)
		}
	}
	created := 0
	for result := range results {
		if result == service.Created {
			created++
		} else if result != service.Existing {
			t.Fatalf("invalid resolve result: %s", result)
		}
	}
	if created != 1 {
		t.Fatalf("created %d identities, want 1", created)
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(true)`); err != nil {
		t.Fatal(err)
	}
	if status, err := store.Resolve(ctx, oidc); err != nil || status != service.Existing {
		t.Fatalf("existing during freeze: %s %v", status, err)
	}
	if _, err := store.Resolve(ctx, contract.Identity{Kind: "OIDC", Issuer: "issuer", Subject: "new"}); err == nil {
		t.Fatal("new identity accepted during synthetic freeze")
	}
	for _, statement := range []string{
		`INSERT INTO eka_auth.identities(kind, local_namespace, username, role) VALUES ('LOCAL', 'dev', 'blocked', 'MEMBER')`,
		`UPDATE eka_auth.identities SET role = 'ADMIN'`,
		`DELETE FROM eka_auth.grants`,
		`TRUNCATE eka_auth.grants`,
		`INSERT INTO public.collections(id) VALUES ('00000000-0000-0000-0000-000000000002')`,
		`DELETE FROM public.collections`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("frozen policy write succeeded: %s", statement)
		}
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(false)`); err != nil {
		t.Fatal(err)
	}
	verifyFreezeDrain(t, ctx, pool)
	verifyRestrictedRuntime(t, ctx, pool)
	verifyLegacyFreeze(t, ctx, pool)
	if _, err := pool.Exec(ctx, `
		INSERT INTO eka_auth.identities(kind, local_namespace, username, role) VALUES ('LOCAL', 'dev', 'alice', 'ADMIN');
		INSERT INTO public.collections(id) SELECT md5(i::text)::uuid FROM generate_series(1,10001) i;
		INSERT INTO eka_auth.grants(identity_id, collection_id, permission)
		SELECT i.identity_id, c.id, 'MANAGE' FROM eka_auth.identities i
		CROSS JOIN (SELECT id FROM public.collections ORDER BY id LIMIT 2) c
		WHERE i.kind = 'OIDC' AND i.issuer = 'issuer' AND i.subject = 'alice'`); err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(ctx, oidc, nil, 1, 10000)
	if err != nil || page.Role != policy.Member || page.Total != 2 || len(page.Entries) != 2 {
		t.Fatalf("member first page: %+v %v", page, err)
	}
	role, grant, err = store.Check(ctx, oidc, page.Entries[0].CollectionID)
	if err != nil || role != policy.Member || grant == nil || *grant != policy.Manage {
		t.Fatalf("member grant: %s %v %v", role, grant, err)
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM public.collections WHERE id = $1`, page.Entries[0].CollectionID); err == nil {
		t.Fatal("frozen cascade succeeded")
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(false)`); err != nil {
		t.Fatal(err)
	}
	if role, grant, err := store.Check(ctx, oidc, page.Entries[0].CollectionID); err != nil || role != policy.Member || grant == nil || *grant != policy.Manage {
		t.Fatalf("frozen cascade changed grant: %s %v %v", role, grant, err)
	}
	next, err := store.Page(ctx, oidc, &page.Entries[0].CollectionID, 1, 10000)
	if err != nil || len(next.Entries) != 1 || next.Entries[0] != page.Entries[1] || next.Revision != page.Revision {
		t.Fatalf("member next page: %+v %v", next, err)
	}
	admin, err := store.Page(ctx, local, nil, 500, 10000)
	if err != nil || admin.Total != 10001 || len(admin.Entries) != 0 {
		t.Fatalf("over limit: %+v %v", admin, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM public.collections WHERE id = (SELECT id FROM public.collections ORDER BY id DESC LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	admin, err = store.Page(ctx, local, nil, 500, 10000)
	if err != nil || admin.Total != 10000 || len(admin.Entries) != 501 || admin.Entries[0].Permission != policy.Manage || admin.Revision == page.Revision {
		t.Fatalf("at limit: total=%d entries=%d err=%v", admin.Total, len(admin.Entries), err)
	}
	verifyConcurrentSnapshot(t, ctx, pool, store, local, admin.Revision)
	codec, err := cursor.New("test", map[string]cursor.KeyPair{"test": {Signing: bytes.Repeat([]byte{1}, 32), Binding: bytes.Repeat([]byte{2}, 32)}}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(store, codec, 500, 10000)
	if err != nil {
		t.Fatal(err)
	}
	verifyRevisionChanges(t, ctx, pool, svc, oidc)
	first, err := svc.Page(ctx, oidc, "spiffe://test/backend", 1, "")
	if err != nil || len(first.Entries) != 1 || first.NextCursor == nil {
		t.Fatalf("service first page: %+v %v", first, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM public.collections WHERE id = $1`, first.Entries[0].CollectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Page(ctx, oidc, "spiffe://test/backend", 1, *first.NextCursor); !errors.Is(err, service.ErrRevisionChanged) {
		t.Fatalf("collection cascade must invalidate cursor: %v", err)
	}
	decision, err := svc.Check(ctx, oidc, first.Entries[0].CollectionID, policy.Read)
	if err != nil || decision != policy.Deny {
		t.Fatalf("cascaded grant must be revoked: %s %v", decision, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.control SET revision = 9223372036854775807 WHERE singleton = true`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.collections(id) VALUES ('00000000-0000-0000-0000-000000000003')`); err == nil {
		t.Fatal("collection write succeeded at revision overflow")
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.collections WHERE id = '00000000-0000-0000-0000-000000000003')`).Scan(&exists); err != nil || exists {
		t.Fatalf("overflow write was not rolled back: exists=%v err=%v", exists, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM eka_auth.control`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Page(ctx, local, nil, 100, 10000); err == nil {
		t.Fatal("page accepted missing control")
	}
	if _, _, err := store.Check(ctx, local, [16]byte{}); err == nil {
		t.Fatal("check accepted missing control")
	}
	if _, err := store.Resolve(ctx, oidc); err == nil {
		t.Fatal("resolve accepted missing control")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM public.collections`); err == nil {
		t.Fatal("policy write accepted missing control")
	}
	t.Log(fmt.Sprintf("synthetic PostgreSQL store checks passed for %d concurrent resolves and 10000/10001 scopes", parallel))
}

// verifyCandidateOwner checks the isolated fixture's function owner and security
// attributes; it does not inspect deployment role memberships or privileges.
func verifyCandidateOwner(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var valid bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_catalog.pg_roles
			WHERE rolname = 'eka_auth_candidate_owner'
			  AND NOT (rolsuper OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
		)
		AND (SELECT count(*) = 5 FROM pg_catalog.pg_proc p
			JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
			JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
			WHERE n.nspname = 'eka_auth' AND r.rolname = 'eka_auth_candidate_owner'
			  AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog'])
		AND NOT EXISTS (
			SELECT 1 FROM pg_catalog.pg_proc p
			JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
			CROSS JOIN LATERAL pg_catalog.aclexplode(
				coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
			WHERE n.nspname = 'eka_auth' AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'
		)
		AND (SELECT r.rolname = 'eka_auth_candidate_owner'
			FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
			WHERE n.nspname = 'eka_auth')
		AND (SELECT count(*) = 3 FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
			WHERE n.nspname = 'eka_auth' AND c.relname IN ('control', 'identities', 'grants')
			  AND r.rolname = 'eka_auth_candidate_owner')
		AND NOT pg_catalog.has_table_privilege('eka_auth_candidate_owner', 'public.app_users', 'INSERT')
		AND NOT pg_catalog.has_table_privilege('eka_auth_candidate_owner', 'public.collection_grants', 'UPDATE')
		AND NOT pg_catalog.has_table_privilege('eka_auth_candidate_owner', 'public.collections', 'DELETE')
		AND NOT pg_catalog.has_table_privilege('eka_auth_candidate_owner', 'public.collections', 'TRIGGER')
		AND NOT pg_catalog.has_column_privilege('eka_auth_candidate_owner', 'public.collections', 'id', 'REFERENCES')
		AND NOT pg_catalog.has_database_privilege('eka_auth_candidate_owner', current_database(), 'CREATE')`).Scan(&valid)
	if err != nil || !valid {
		t.Fatalf("invalid isolated owner attributes or function privileges: valid=%v error=%v", valid, err)
	}
}

// verifyFreezeDrain shows that freeze waits for an admitted writer, then blocks new writes.
func verifyFreezeDrain(t *testing.T, parent context.Context, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("release writer: %v", err)
		}
	}()
	if _, err := writer.Exec(ctx, `INSERT INTO eka_auth.identities(kind, issuer, subject, role) VALUES ('OIDC', 'issuer', 'drain-test', 'MEMBER')`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(ctx, `INSERT INTO public.app_users(subject, role) VALUES ('drain-legacy', 'MEMBER')`); err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	pid := conn.Conn().PgConn().PID()
	result := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, `SELECT eka_auth.test_set_freeze(true)`)
		result <- err
	}()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("freeze finished before writer committed: %v", err)
		case <-ctx.Done():
			t.Fatal("freeze did not wait for writer")
		case <-time.After(10 * time.Millisecond):
		}
	}
	lateConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lateConn.Release()
	latePID := lateConn.Conn().PgConn().PID()
	lateResult := make(chan error, 1)
	go func() {
		_, err := lateConn.Exec(ctx, `INSERT INTO public.collections(id) VALUES ('00000000-0000-0000-0000-000000000005')`)
		lateResult <- err
	}()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')`, latePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-lateResult:
			t.Fatalf("new writer finished while freeze was draining: %v", err)
		case <-ctx.Done():
			t.Fatal("new writer did not wait for freeze")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("freeze failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("freeze did not complete after writer")
	}
	select {
	case err := <-lateResult:
		if err == nil {
			t.Fatal("queued writer bypassed freeze")
		}
	case <-ctx.Done():
		t.Fatal("queued writer did not finish")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.collections(id) VALUES ('00000000-0000-0000-0000-000000000004')`); err == nil {
		t.Fatal("new write succeeded after freeze")
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(false)`); err != nil {
		t.Fatal(err)
	}
}

// verifyLegacyFreeze exercises statement guards through a separate legacy login.
// The no-op insert demonstrates why the Java provisioning filter needs A06.
func verifyLegacyFreeze(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		CREATE ROLE eka_auth_candidate_legacy LOGIN PASSWORD 'synthetic-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
		GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON public.app_users, public.collection_grants, public.collections TO eka_auth_candidate_legacy`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DROP OWNED BY eka_auth_candidate_legacy; DROP ROLE eka_auth_candidate_legacy`); err != nil {
			t.Errorf("remove legacy test role: %v", err)
		}
	}()
	cfg := pool.Config()
	cfg.ConnConfig.User = "eka_auth_candidate_legacy"
	cfg.ConnConfig.Password = "synthetic-only"
	legacy, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot configure legacy test connection")
	}
	defer legacy.Close()
	if empty, err := compatibility.Check(ctx, legacy, compatibility.Config{Kind: "OIDC", Issuer: "issuer"}); err != nil || empty.Total != 1 || empty.Incompatible != 0 {
		t.Fatalf("initial legacy compatibility scan: %+v %v", empty, err)
	}
	if _, err := legacy.Exec(ctx, `
		INSERT INTO public.app_users(subject, role) VALUES ('legacy-test', 'MEMBER');
		INSERT INTO public.app_users(subject, role) VALUES ('', 'MEMBER'), (repeat('é', 513), 'MEMBER');
		INSERT INTO public.collections(id) VALUES ('00000000-0000-0000-0000-000000000006');
		INSERT INTO public.collection_grants(subject, collection_id, permission)
		VALUES ('legacy-test', '00000000-0000-0000-0000-000000000006', 'READ')`); err != nil {
		t.Fatalf("seed legacy policy: %v", err)
	}
	for _, config := range []compatibility.Config{{Kind: "OIDC", Issuer: "issuer"}, {Kind: "LOCAL", Namespace: "dev"}} {
		result, err := compatibility.Check(ctx, legacy, config)
		if err != nil || result.Total != 4 || result.Incompatible != 2 {
			t.Fatalf("legacy compatibility scan: %+v %v", result, err)
		}
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE public.app_users ENABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := compatibility.Check(ctx, legacy, compatibility.Config{Kind: "OIDC", Issuer: "issuer"}); err == nil {
		t.Fatal("compatibility scan accepted row-level filtered data")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE public.app_users DISABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(true)`); err != nil {
		t.Fatal(err)
	}
	var role, permission string
	if err := legacy.QueryRow(ctx, `SELECT u.role, g.permission FROM public.app_users u JOIN public.collection_grants g ON g.subject = u.subject WHERE u.subject = 'legacy-test'`).Scan(&role, &permission); err != nil || role != "MEMBER" || permission != "READ" {
		t.Fatalf("legacy read during freeze: %v", err)
	}
	for _, statement := range []string{
		`INSERT INTO public.app_users(subject, role) VALUES ('legacy-test', 'MEMBER') ON CONFLICT DO NOTHING`,
		`INSERT INTO public.app_users(subject, role) VALUES ('blocked', 'MEMBER')`,
		`UPDATE public.app_users SET role = 'ADMIN' WHERE subject = 'legacy-test'`,
		`DELETE FROM public.app_users WHERE subject = 'legacy-test'`,
		`UPDATE public.collection_grants SET permission = 'MANAGE' WHERE subject = 'legacy-test'`,
		`DELETE FROM public.collection_grants WHERE subject = 'legacy-test'`,
		`DELETE FROM public.collections WHERE id = '00000000-0000-0000-0000-000000000006'`,
		`TRUNCATE public.collection_grants`,
	} {
		_, err := legacy.Exec(ctx, statement)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
			t.Fatalf("legacy write was not blocked by freeze: %v", err)
		}
		for _, statement := range []string{
			`SET ROLE eka_auth_candidate_owner`,
			`SELECT eka_auth.test_set_freeze(false)`,
			`SELECT eka_auth.resolve_oidc('issuer', 'bypass')`,
		} {
			_, err := legacy.Exec(ctx, statement)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("legacy runtime bypass permitted or failed unexpectedly: %v", err)
			}
		}
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(ctx, `DELETE FROM public.collections WHERE id = '00000000-0000-0000-0000-000000000006'`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := legacy.QueryRow(ctx, `SELECT count(*) FROM public.collection_grants WHERE subject = 'legacy-test'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy cascade failed: count=%d error=%v", count, err)
	}
}

// verifyRestrictedRuntime tests candidate privileges through a separate login.
// It removes the test role and grants before the disposable database is closed.
func verifyRestrictedRuntime(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback role test: %v", err)
		}
	}()
	if _, err := tx.Exec(ctx, `
		CREATE ROLE eka_auth_candidate_runtime LOGIN PASSWORD 'synthetic-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
		GRANT USAGE ON SCHEMA eka_auth TO eka_auth_candidate_runtime;
		GRANT SELECT ON eka_auth.control, eka_auth.identities, eka_auth.grants TO eka_auth_candidate_runtime;
		GRANT SELECT (id) ON public.collections TO eka_auth_candidate_runtime;
		GRANT EXECUTE ON FUNCTION eka_auth.resolve_oidc(text, text) TO eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DROP OWNED BY eka_auth_candidate_runtime; DROP ROLE eka_auth_candidate_runtime`); err != nil {
			t.Errorf("remove test role: %v", err)
		}
	}()
	cfg := pool.Config()
	cfg.ConnConfig.User = "eka_auth_candidate_runtime"
	cfg.ConnConfig.Password = "synthetic-only"
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot configure restricted test connection")
	}
	defer runtime.Close()
	var currentUser, sessionUser string
	if err := runtime.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&currentUser, &sessionUser); err != nil || currentUser != "eka_auth_candidate_runtime" || sessionUser != currentUser {
		t.Fatalf("restricted login failed: %v", err)
	}
	store, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("valid candidate schema rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE eka_auth.grants DISABLE TRIGGER test_revision_grants`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err == nil {
		t.Fatal("disabled revision trigger accepted")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE eka_auth.grants ENABLE TRIGGER test_revision_grants`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT UPDATE ON eka_auth.control TO eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err == nil {
		t.Fatal("runtime control-table write privilege accepted")
	}
	if _, err := pool.Exec(ctx, `REVOKE UPDATE ON eka_auth.control FROM eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("restored candidate schema rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT (private_test_field) ON public.collections TO eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err == nil {
		t.Fatal("runtime access to non-ID collection fields accepted")
	}
	if _, err := pool.Exec(ctx, `REVOKE SELECT (private_test_field) ON public.collections FROM eka_auth_candidate_runtime;
		GRANT CREATE ON SCHEMA public TO eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err == nil {
		t.Fatal("runtime schema creation privilege accepted")
	}
	if _, err := pool.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM eka_auth_candidate_runtime;
		GRANT eka_auth_candidate_owner TO eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err == nil {
		t.Fatal("runtime owner-role membership accepted")
	}
	if _, err := pool.Exec(ctx, `REVOKE eka_auth_candidate_owner FROM eka_auth_candidate_runtime`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("runtime role rejected after unsafe grants revoked: %v", err)
	}
	id := contract.Identity{Kind: "OIDC", Issuer: "issuer", Subject: "runtime-test"}
	if status, err := store.Resolve(ctx, id); err != nil || status != service.Created {
		t.Fatalf("restricted provisioning: %s %v", status, err)
	}
	if role, grant, err := store.Check(ctx, id, [16]byte{}); err != nil || role != policy.Member || grant != nil {
		t.Fatalf("restricted permission check: %s %v %v", role, grant, err)
	}
	if page, err := store.Page(ctx, id, nil, 100, 10000); err != nil || page.Role != policy.Member || page.Total != 0 {
		t.Fatalf("restricted scope read: %+v %v", page, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.identities SET role = 'ADMIN' WHERE kind = 'OIDC' AND issuer = 'issuer' AND subject = 'runtime-test'`); err != nil {
		t.Fatal(err)
	}
	if page, err := store.Page(ctx, id, nil, 100, 10000); err != nil || page.Role != policy.Admin {
		t.Fatalf("restricted admin collection read: %+v %v", page, err)
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(true)`); err != nil {
		t.Fatal(err)
	}
	if status, err := store.Resolve(ctx, id); err != nil || status != service.Existing {
		t.Fatalf("restricted existing resolution during freeze: %s %v", status, err)
	}
	if _, err := store.Resolve(ctx, contract.Identity{Kind: "OIDC", Issuer: "issuer", Subject: "runtime-blocked"}); err == nil {
		t.Fatal("restricted provisioning succeeded during freeze")
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(false)`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO eka_auth.identities(kind, issuer, subject, role) VALUES ('OIDC', 'issuer', 'bypass', 'ADMIN')`,
		`UPDATE eka_auth.control SET frozen = false`,
		`SELECT eka_auth.test_set_freeze(false)`,
		`SELECT eka_auth.test_restore_epoch(gen_random_uuid())`,
		`SET ROLE eka_auth_candidate_owner`,
		`ALTER TABLE eka_auth.identities DISABLE TRIGGER ALL`,
		`CREATE TABLE eka_auth.bypass (id integer)`,
		`DELETE FROM public.collections`,
		`SELECT private_test_field FROM public.collections`,
	} {
		_, statementErr := runtime.Exec(ctx, statement)
		var pgErr *pgconn.PgError
		if !errors.As(statementErr, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("restricted runtime must reject %s with insufficient privilege: %v", statement, statementErr)
		}
	}
}

// verifyRevisionChanges covers committed and rolled-back policy mutations and
// an epoch replacement using the synthetic fixture, not production triggers.
func verifyRevisionChanges(t *testing.T, ctx context.Context, pool *pgxpool.Pool, svc *service.Service, id contract.Identity) {
	t.Helper()
	const caller = "spiffe://test/backend"
	firstPage := func() service.Page {
		t.Helper()
		page, err := svc.Page(ctx, id, caller, 1, "")
		if err != nil || page.NextCursor == nil || len(page.Entries) != 1 {
			t.Fatalf("first policy page: %+v %v", page, err)
		}
		return page
	}
	page := firstPage()
	if _, err := pool.Exec(ctx, `UPDATE public.app_users SET role = 'ADMIN' WHERE subject = 'legacy-test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Page(ctx, id, caller, 1, *page.NextCursor); !errors.Is(err, service.ErrRevisionChanged) {
		t.Fatalf("legacy role update did not invalidate cursor: %v", err)
	}
	page = firstPage()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE eka_auth.grants SET permission = 'READ' WHERE collection_id = $1`, page.Entries[0].CollectionID); err != nil {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Errorf("rollback failed: %v", rollbackErr)
		}
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Page(ctx, id, caller, 1, *page.NextCursor); err != nil {
		t.Fatalf("rolled-back grant invalidated cursor: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.grants SET permission = 'READ' WHERE collection_id = $1`, page.Entries[0].CollectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Page(ctx, id, caller, 1, *page.NextCursor); !errors.Is(err, service.ErrRevisionChanged) {
		t.Fatalf("grant update did not invalidate cursor: %v", err)
	}
	page = firstPage()
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.identities SET role = 'ADMIN' WHERE kind = 'OIDC' AND issuer = $1 AND subject = $2`, id.Issuer, id.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Page(ctx, id, caller, 1, *page.NextCursor); !errors.Is(err, service.ErrRevisionChanged) {
		t.Fatalf("role update did not invalidate cursor: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.identities SET role = 'MEMBER' WHERE kind = 'OIDC' AND issuer = $1 AND subject = $2`, id.Issuer, id.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.control SET revision = 0 WHERE singleton = true`); err != nil {
		t.Fatal(err)
	}
	page = firstPage()
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_restore_epoch(gen_random_uuid())`); err == nil {
		t.Fatal("epoch change succeeded while policy was not frozen")
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_restore_epoch(epoch) FROM eka_auth.control`); err == nil {
		t.Fatal("epoch change accepted the restored epoch")
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_restore_epoch('00000000-0000-0000-0000-000000000000')`); err == nil {
		t.Fatal("epoch change accepted a zero epoch")
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_restore_epoch(gen_random_uuid())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT eka_auth.test_set_freeze(false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Page(ctx, id, caller, 1, *page.NextCursor); !errors.Is(err, service.ErrRevisionChanged) {
		t.Fatalf("epoch replacement did not invalidate cursor: %v", err)
	}
}

// verifyConcurrentSnapshot blocks the identity read after the revision read,
// commits a collection change, and verifies the page still sees one snapshot.
func verifyConcurrentSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *Store, id contract.Identity, revision service.Revision) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	lock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("release test lock: %v", err)
		}
	}()
	if _, err := lock.Exec(ctx, `LOCK TABLE eka_auth.identities IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		page service.Snapshot
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		page, err := store.Page(ctx, id, nil, 100, 10001)
		done <- outcome{page: page, err: err}
	}()
	for {
		var waiting bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND query LIKE '%SELECT identity_id, role FROM eka_auth.identities%'
		)`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-done:
			t.Fatalf("scope read finished before lock: %+v, %v", result.page, result.err)
		case <-ctx.Done():
			t.Fatalf("scope read did not block: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	const newID = "00000000-0000-0000-0000-000000000000"
	if _, err := pool.Exec(ctx, `INSERT INTO public.collections(id) VALUES ($1)`, newID); err != nil {
		t.Fatal(err)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.page.Revision != revision || result.page.Total != 10000 || len(result.page.Entries) != 101 {
			t.Fatalf("mixed snapshot: revision=%+v total=%d entries=%d error=%v", result.page.Revision, result.page.Total, len(result.page.Entries), result.err)
		}
	case <-ctx.Done():
		t.Fatalf("scope read did not finish: %v", ctx.Err())
	}
	current, err := store.Page(ctx, id, nil, 100, 10001)
	if err != nil || current.Revision == revision || current.Total != 10001 {
		t.Fatalf("fresh snapshot: revision=%+v total=%d error=%v", current.Revision, current.Total, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM public.collections WHERE id = $1`, newID); err != nil {
		t.Fatal(err)
	}
}
