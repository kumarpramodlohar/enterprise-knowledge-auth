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

	"github.com/jackc/pgx/v5/pgxpool"
)

// This synthetic fixture is not a production migration or freeze guard.
const integrationFixture = `
CREATE SCHEMA eka_auth;
CREATE TABLE public.collections (id uuid PRIMARY KEY);
CREATE TABLE eka_auth.control (singleton boolean PRIMARY KEY, frozen boolean NOT NULL, epoch uuid NOT NULL, revision bigint NOT NULL);
INSERT INTO eka_auth.control VALUES (true, false, gen_random_uuid(), 0);
CREATE TABLE eka_auth.identities (identity_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), kind text NOT NULL, issuer text, subject text, local_namespace text, username text, role text NOT NULL);
CREATE UNIQUE INDEX oidc_identity ON eka_auth.identities(issuer, subject) WHERE kind = 'OIDC';
CREATE TABLE eka_auth.grants (identity_id uuid NOT NULL REFERENCES eka_auth.identities ON DELETE CASCADE, collection_id uuid NOT NULL REFERENCES public.collections ON DELETE CASCADE, permission text NOT NULL, PRIMARY KEY(identity_id, collection_id));
CREATE FUNCTION eka_auth.fixture_bump() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN UPDATE eka_auth.control SET revision = revision + 1 WHERE singleton = true;
IF NOT FOUND THEN RAISE EXCEPTION 'missing control'; END IF; RETURN NULL; END $$;
CREATE TRIGGER revision_id AFTER INSERT OR UPDATE OR DELETE ON eka_auth.identities FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.fixture_bump();
CREATE TRIGGER revision_grant AFTER INSERT OR UPDATE OR DELETE ON eka_auth.grants FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.fixture_bump();
CREATE TRIGGER revision_collection AFTER INSERT OR UPDATE OR DELETE ON public.collections FOR EACH STATEMENT EXECUTE FUNCTION eka_auth.fixture_bump();
CREATE FUNCTION eka_auth.resolve_oidc(p_issuer text, p_subject text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE is_frozen boolean; inserted uuid;
BEGIN SELECT frozen INTO STRICT is_frozen FROM eka_auth.control WHERE singleton = true FOR UPDATE;
IF EXISTS(SELECT 1 FROM eka_auth.identities WHERE kind = 'OIDC' AND issuer = p_issuer AND subject = p_subject) THEN RETURN 'EXISTING'; END IF;
IF is_frozen THEN RAISE EXCEPTION 'frozen'; END IF;
INSERT INTO eka_auth.identities(kind,issuer,subject,role) VALUES('OIDC',p_issuer,p_subject,'MEMBER') ON CONFLICT DO NOTHING RETURNING identity_id INTO inserted;
IF inserted IS NULL THEN RETURN 'EXISTING'; END IF; RETURN 'CREATED'; END $$;
`

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
	if err := pool.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eka_auth') AND to_regclass('public.collections') IS NULL`).Scan(&empty); err != nil || !empty {
		t.Fatal("local integration test requires a fresh, empty synthetic database")
	}
	if _, err := pool.Exec(ctx, integrationFixture); err != nil {
		t.Fatal(err)
	}
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
