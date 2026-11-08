package localapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/authserver"
)

func TestLocalServerWithSyntheticPostgres(t *testing.T) {
	dsn := os.Getenv("EKA_LOCALAPP_TEST_DSN")
	if dsn == "" {
		if os.Getenv("EKA_REQUIRE_POSTGRES_TEST") == "1" {
			t.Fatal("local server integration test requires EKA_LOCALAPP_TEST_DSN")
		}
		t.Skip("EKA_LOCALAPP_TEST_DSN is not configured for a disposable database")
	}
	cfg := validConfig()
	cfg.DatabaseURL = dsn
	dbCfg, err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, dbCfg)
	if err != nil {
		t.Fatal("cannot initialize test database")
	}
	defer pool.Close()
	var empty bool
	if err := pool.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eka_auth') AND to_regclass('public.collections') IS NULL AND to_regclass('public.app_users') IS NULL AND to_regclass('public.collection_grants') IS NULL`).Scan(&empty); err != nil || !empty {
		t.Fatal("local integration test requires a fresh, empty synthetic database")
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
	ownership, err := os.ReadFile("../postgres/testdata/guarded_ownership.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(ownership)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT CREATE ON DATABASE `+pgx.Identifier{dbCfg.ConnConfig.Database}.Sanitize()+` TO eka_auth_candidate_owner`); err != nil {
		t.Fatal(err)
	}
	guardedSchema, err := os.ReadFile("../postgres/testdata/guarded_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	installerConfig := *dbCfg.ConnConfig
	installerConfig.User = "eka_auth_candidate_schema"
	installerConfig.Password = "synthetic-only"
	installer, err := pgx.ConnectConfig(ctx, &installerConfig)
	if err != nil {
		t.Fatal("cannot connect to synthetic schema installer")
	}
	if _, err := installer.Exec(ctx, `SET ROLE eka_auth_candidate_owner`); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Exec(ctx, string(guardedSchema)); err != nil {
		t.Fatalf("cannot install guarded synthetic schema: %v", err)
	}
	if _, err := installer.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if err := installer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `REVOKE TRIGGER ON public.collections, public.app_users, public.collection_grants FROM eka_auth_candidate_owner;
		REVOKE REFERENCES (id) ON public.collections FROM eka_auth_candidate_owner;
		REVOKE CREATE ON DATABASE `+pgx.Identifier{dbCfg.ConnConfig.Database}.Sanitize()+` FROM eka_auth_candidate_owner;
		REVOKE eka_auth_candidate_owner FROM eka_auth_candidate_schema;
		CREATE ROLE eka_auth_localapp_runtime LOGIN PASSWORD 'synthetic-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
		GRANT USAGE ON SCHEMA eka_auth TO eka_auth_localapp_runtime;
		GRANT SELECT ON eka_auth.control, eka_auth.identities, eka_auth.grants TO eka_auth_localapp_runtime;
		GRANT SELECT (id) ON public.collections TO eka_auth_localapp_runtime;
		GRANT EXECUTE ON FUNCTION eka_auth.resolve_oidc(text, text) TO eka_auth_localapp_runtime`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DROP OWNED BY eka_auth_localapp_runtime; DROP ROLE eka_auth_localapp_runtime;
			REASSIGN OWNED BY eka_auth_candidate_owner TO CURRENT_USER; DROP OWNED BY eka_auth_candidate_owner;
			DROP OWNED BY eka_auth_candidate_schema; DROP ROLE eka_auth_candidate_schema; DROP ROLE eka_auth_candidate_owner`); err != nil {
			t.Errorf("remove synthetic database roles: %v", err)
		}
	}()
	runtimeURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("cannot parse synthetic database URL")
	}
	runtimeURL.User = url.UserPassword("eka_auth_localapp_runtime", "synthetic-only")
	cfg.DatabaseURL = runtimeURL.String()
	ca, caKey, caDER := issueTestCert(t, nil, nil, true, false)
	_, serverKey, serverDER := issueTestCert(t, ca, caKey, false, true)
	_, clientKey, clientDER := issueTestCert(t, ca, caKey, false, false)
	dir := t.TempDir()
	cfg.ServerCertificate = writeTestFile(t, dir, "server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}))
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerKey = writeTestFile(t, dir, "server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}))
	cfg.ClientCA = writeTestFile(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	cfg.SigningKeyFile = writeTestFile(t, dir, "sign.key", bytes.Repeat([]byte{1}, 32))
	cfg.BindingKeyFile = writeTestFile(t, dir, "bind.key", bytes.Repeat([]byte{2}, 32))
	cfg.Issuer = "https://issuer.example"
	ready := make(chan string, 1)
	result := make(chan error, 1)
	runCtx, stop := context.WithCancel(ctx)
	go func() {
		result <- Run(runCtx, cfg, func(addr string) { ready <- addr }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() { stop() })
	var addr string
	select {
	case addr = <-ready:
	case err := <-result:
		t.Fatalf("local server failed to start: %v", err)
	case <-ctx.Done():
		t.Fatal("local server startup timed out")
	}
	root := x509.NewCertPool()
	root.AddCert(ca)
	clientCert := tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: clientKey}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	post := func(path, body string, status int) map[string]any {
		t.Helper()
		resp, err := client.Post("https://"+addr+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var data map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || resp.StatusCode != status {
			t.Fatalf("request %s: status=%d error=%v", path, resp.StatusCode, err)
		}
		return data
	}
	identity := `"identity":{"kind":"OIDC","issuer":"https://issuer.example","subject":"test-user"}`
	if got := post("/internal/v1/users/resolve", "{"+identity+"}", 200); got["status"] != "CREATED" {
		t.Fatalf("provision: %v", got)
	}
	if got := post("/internal/v1/users/resolve", "{"+identity+"}", 200); got["status"] != "EXISTING" {
		t.Fatalf("resolve: %v", got)
	}
	const collection = "00000000-0000-0000-0000-000000000001"
	check := "{" + identity + `,"collectionId":"` + collection + `","permission":"READ"}`
	if got := post("/internal/v1/permissions/check", check, 200); got["decision"] != "DENY" {
		t.Fatalf("new user must lack grants: %v", got)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.collections(id) VALUES ($1);`, collection); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO eka_auth.grants SELECT identity_id, $1, 'MANAGE' FROM eka_auth.identities WHERE subject = 'test-user'`, collection); err != nil {
		t.Fatal(err)
	}
	if got := post("/internal/v1/permissions/check", check, 200); got["decision"] != "ALLOW" {
		t.Fatalf("manage grant must allow read: %v", got)
	}
	got := post("/internal/v1/scopes/page", "{"+identity+"}", 200)
	entries, ok := got["entries"].([]any)
	if !ok || got["role"] != "MEMBER" || len(entries) != 1 {
		t.Fatalf("scope page: %v", got)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM eka_auth.grants`); err != nil {
		t.Fatal(err)
	}
	if got := post("/internal/v1/permissions/check", check, 200); got["decision"] != "DENY" {
		t.Fatalf("revoked grant must deny: %v", got)
	}
	stop()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("local server shutdown timed out")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE eka_auth.grants DISABLE TRIGGER test_revision_grants`); err != nil {
		t.Fatal(err)
	}
	started := false
	err = Run(ctx, cfg, func(string) { started = true }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || started {
		t.Fatalf("local service started with disabled revision trigger: started=%t err=%v", started, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE eka_auth.grants ENABLE TRIGGER test_revision_grants`); err != nil {
		t.Fatal(err)
	}

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	daemonAddress := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	daemonConfig := authserver.Config{
		Address: daemonAddress, DatabaseURL: cfg.DatabaseURL,
		ServerCertificate: cfg.ServerCertificate, ServerKey: cfg.ServerKey, ClientCA: cfg.ClientCA,
		SigningKeyID: "test-key", SigningKeyFile: cfg.SigningKeyFile, BindingKeyFile: cfg.BindingKeyFile,
		CallerURIs: []string{"spiffe://test/backend"}, Issuers: []string{cfg.Issuer},
		MaxPageSize: 500, ScopeLimit: 10000,
	}
	daemonReady := make(chan string, 1)
	daemonResult := make(chan error, 1)
	daemonCtx, stopDaemon := context.WithCancel(ctx)
	go func() {
		daemonResult <- authserver.Run(daemonCtx, daemonConfig, func(address string) {
			daemonReady <- address
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	defer stopDaemon()
	select {
	case addr = <-daemonReady:
	case err := <-daemonResult:
		t.Fatalf("authd failed to start: %v", err)
	case <-ctx.Done():
		t.Fatal("authd startup timed out")
	}
	if got := post("/internal/v1/users/resolve", "{"+identity+"}", 200); got["status"] != "EXISTING" {
		t.Fatalf("authd could not use existing policy service: %v", got)
	}
	stopDaemon()
	select {
	case err := <-daemonResult:
		if err != nil {
			t.Fatalf("authd shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("authd shutdown timed out")
	}

	if _, err := pool.Exec(ctx, `ALTER TABLE eka_auth.grants DISABLE TRIGGER test_revision_grants`); err != nil {
		t.Fatal(err)
	}
	started = false
	err = authserver.Run(ctx, daemonConfig, func(string) { started = true }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || started {
		t.Fatalf("authd started with disabled revision trigger: started=%t err=%v", started, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE eka_auth.grants ENABLE TRIGGER test_revision_grants`); err != nil {
		t.Fatal(err)
	}
}

func writeTestFile(t *testing.T, dir, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func issueTestCert(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, isCA, server bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature}
	switch {
	case isCA:
		cert.KeyUsage |= x509.KeyUsageCertSign
		parent, signer = cert, key
	case server:
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	default:
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		cert.URIs = []*url.URL{{Scheme: "spiffe", Host: "test", Path: "/backend"}}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key, der
}
