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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
)

// This synthetic fixture is not a migration or a production freeze design.
const fixture = `
CREATE SCHEMA eka_auth;
CREATE TABLE public.collections (id uuid PRIMARY KEY);
CREATE TABLE eka_auth.identities (
 identity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 kind text NOT NULL,
 issuer text COLLATE "C", subject text COLLATE "C",
 local_namespace text COLLATE "C", username text COLLATE "C",
 role text NOT NULL CHECK (role IN ('ADMIN', 'MEMBER')));
CREATE UNIQUE INDEX oidc_unique ON eka_auth.identities (issuer, subject) WHERE kind = 'OIDC';
CREATE UNIQUE INDEX local_unique ON eka_auth.identities (local_namespace, username) WHERE kind = 'LOCAL';
CREATE TABLE eka_auth.grants (
 identity_id uuid NOT NULL REFERENCES eka_auth.identities ON DELETE CASCADE,
 collection_id uuid NOT NULL REFERENCES public.collections ON DELETE CASCADE,
 permission text NOT NULL CHECK (permission IN ('READ','MANAGE')),
 PRIMARY KEY(identity_id, collection_id));
CREATE TABLE eka_auth.control (
 singleton boolean PRIMARY KEY CHECK (singleton),
 frozen boolean NOT NULL, epoch uuid NOT NULL, revision bigint NOT NULL CHECK(revision >= 0));
INSERT INTO eka_auth.control VALUES (true, false, gen_random_uuid(), 0);
CREATE FUNCTION eka_auth.fixture_bump() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE eka_auth.control SET revision = revision + 1 WHERE singleton = true;
 IF NOT FOUND THEN RAISE EXCEPTION 'missing control'; END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER fixture_identity_revision AFTER INSERT OR UPDATE OR DELETE ON eka_auth.identities FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.fixture_bump();
CREATE TRIGGER fixture_grant_revision AFTER INSERT OR UPDATE OR DELETE ON eka_auth.grants FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.fixture_bump();
CREATE TRIGGER fixture_collection_revision AFTER INSERT OR UPDATE OR DELETE ON public.collections FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.fixture_bump();
CREATE FUNCTION eka_auth.resolve_oidc(p_issuer text, p_subject text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE is_frozen boolean; inserted uuid;
BEGIN
 SELECT frozen INTO STRICT is_frozen FROM eka_auth.control WHERE singleton = true FOR UPDATE;
 IF EXISTS (SELECT 1 FROM eka_auth.identities WHERE kind = 'OIDC' AND issuer = p_issuer AND subject = p_subject) THEN RETURN 'EXISTING'; END IF;
 IF is_frozen THEN RAISE EXCEPTION 'frozen'; END IF;
 INSERT INTO eka_auth.identities(kind, issuer, subject, role) VALUES ('OIDC', p_issuer, p_subject, 'MEMBER')
 ON CONFLICT DO NOTHING RETURNING identity_id INTO inserted;
 IF inserted IS NULL THEN RETURN 'EXISTING'; END IF;
 RETURN 'CREATED';
END $$;
`

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
	if err := pool.QueryRow(ctx, `SELECT current_database(), NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eka_auth') AND to_regclass('public.collections') IS NULL`).Scan(&db, &empty); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(db, "eka_auth_test_") || !empty {
		t.Fatal("integration tests require a new, empty synthetic database named eka_auth_test_*")
	}
	if _, err := pool.Exec(ctx, fixture); err != nil {
		t.Fatal(err)
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
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.control SET frozen = true WHERE singleton = true`); err != nil {
		t.Fatal(err)
	}
	if status, err := store.Resolve(ctx, oidc); err != nil || status != service.Existing {
		t.Fatalf("existing during freeze: %s %v", status, err)
	}
	if _, err := store.Resolve(ctx, contract.Identity{Kind: "OIDC", Issuer: "issuer", Subject: "new"}); err == nil {
		t.Fatal("new identity accepted during synthetic freeze")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE eka_auth.control SET frozen = false;
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
	t.Log(fmt.Sprintf("synthetic PostgreSQL store checks passed for %d concurrent resolves and 10000/10001 scopes", parallel))
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
	page = firstPage()
	if _, err := pool.Exec(ctx, `UPDATE eka_auth.control SET epoch = gen_random_uuid(), revision = 0 WHERE singleton = true`); err != nil {
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
