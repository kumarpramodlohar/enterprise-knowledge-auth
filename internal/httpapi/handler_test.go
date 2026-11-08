package httpapi

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
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
)

type store struct {
	err      error
	snapshot service.Snapshot
	calls    int
}

func (s *store) Resolve(context.Context, contract.Identity) (service.ResolveStatus, error) {
	s.calls++
	return service.Existing, s.err
}
func (s *store) Check(context.Context, contract.Identity, [16]byte) (policy.Role, *policy.Permission, error) {
	s.calls++
	return policy.Admin, nil, s.err
}
func (s *store) Page(context.Context, contract.Identity, *[16]byte, int, int) (service.Snapshot, error) {
	s.calls++
	return s.snapshot, s.err
}

func testHandler(t *testing.T, st *store) *Handler {
	t.Helper()
	codec, err := cursor.New("active", map[string]cursor.KeyPair{"active": {Signing: bytes.Repeat([]byte{1}, 32), Binding: bytes.Repeat([]byte{2}, 32)}}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(st, codec, 500, 10000)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc, contract.Trust{AllowedIssuers: map[string]struct{}{"issuer": {}}}, []string{"spiffe://eka/backend"}, 500, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func certificate(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, uri string, ca bool, until time.Time) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "synthetic"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: until,
		BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
		parent, signer = template, key
	}
	if uri != "" {
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{parsed}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestMutualTLSAndContract(t *testing.T) {
	st := &store{snapshot: service.Snapshot{Revision: service.Revision{Epoch: [16]byte{1}, Counter: 2}, Role: policy.Member}}
	h := testHandler(t, st)
	ca, key, _ := certificate(t, nil, nil, "", true, time.Now().Add(time.Hour))
	_, _, allowed := certificate(t, ca, key, "spiffe://eka/backend", false, time.Now().Add(time.Hour))
	_, _, rotated := certificate(t, ca, key, "spiffe://eka/backend", false, time.Now().Add(time.Hour))
	_, _, unknown := certificate(t, ca, key, "spiffe://eka/other", false, time.Now().Add(time.Hour))
	_, _, noURI := certificate(t, ca, key, "", false, time.Now().Add(time.Hour))
	otherCA, otherKey, _ := certificate(t, nil, nil, "", true, time.Now().Add(time.Hour))
	_, _, untrusted := certificate(t, otherCA, otherKey, "spiffe://eka/backend", false, time.Now().Add(time.Hour))
	_, _, expired := certificate(t, ca, key, "spiffe://eka/backend", false, time.Now().Add(-time.Minute))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server := httptest.NewUnstartedServer(h)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)

	client := func(cert *tls.Certificate) *http.Client {
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		transport := &http.Transport{TLSClientConfig: cfg}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport}
	}
	body := `{"identity":{"kind":"OIDC","issuer":"issuer","subject":"subject"}}`
	for _, tt := range []struct {
		name           string
		cert           *tls.Certificate
		handshakeFails bool
		status         int
	}{
		{"allowed", &allowed, false, 200},
		{"rotated", &rotated, false, 200},
		{"unknown identity", &unknown, false, 403},
		{"missing URI", &noURI, false, 403},
		{"missing cert", nil, true, 0},
		{"untrusted", &untrusted, true, 0},
		{"expired", &expired, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, server.URL+"/internal/v1/users/resolve", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			res, err := client(tt.cert).Do(req)
			if tt.handshakeFails {
				if err == nil {
					res.Body.Close()
					t.Fatal("expected TLS failure")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tt.status {
				t.Fatalf("status %d", res.StatusCode)
			}
			if tt.status == 403 {
				var response map[string]string
				if err := json.NewDecoder(res.Body).Decode(&response); err != nil || response["code"] != "CALLER_FORBIDDEN" || !correlationPattern.MatchString(response["correlationId"]) {
					t.Fatalf("unsafe error: %#v %v", response, err)
				}
			}
		})
	}
	good := client(&allowed)
	checks := []struct {
		path, body string
		status     int
		contains   string
	}{
		{"/internal/v1/permissions/check", `{"identity":{"kind":"OIDC","issuer":"issuer","subject":"subject"},"collectionId":"00000000-0000-0000-0000-000000000001","permission":"READ"}`, 200, `"decision":"ALLOW"`},
		{"/internal/v1/scopes/page", body, 200, `"entries":[]`},
		{"/internal/v1/scopes/page", `{"identity":{"kind":"OIDC","issuer":"issuer","subject":"subject"},"cursor":"tampered"}`, 400, `"code":"INVALID_CURSOR"`},
		{"/internal/v1/users/resolve", `{"identity":{"kind":"OIDC","issuer":"other","subject":"secret"}}`, 400, `"code":"INVALID_REQUEST"`},
	}
	for _, tt := range checks {
		req, err := http.NewRequest(http.MethodPost, server.URL+tt.path, strings.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Correlation-Id", "test-id")
		res, err := good.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != tt.status || !bytes.Contains(got, []byte(tt.contains)) || bytes.Contains(got, []byte("secret")) {
			t.Fatalf("%s: status=%d body=%s err=%v", tt.path, res.StatusCode, got, err)
		}
	}
	st.err = io.ErrUnexpectedEOF
	req, err := http.NewRequest(http.MethodPost, server.URL+"/internal/v1/users/resolve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "safe-id")
	res, err := good.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 503 || !bytes.Contains(got, []byte(`"code":"SERVICE_UNAVAILABLE"`)) || bytes.Contains(got, []byte("unexpected EOF")) {
		t.Fatalf("unsafe store failure: %d %s %v", res.StatusCode, got, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{allowed}, ServerName: "wrong.example", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	wrongHostClient := &http.Client{Transport: transport}
	if response, err := wrongHostClient.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("accepted incorrect server DNS name")
	}
}

func TestNoTLSIsForbidden(t *testing.T) {
	st := &store{}
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/users/resolve", strings.NewReader(`{}`))
	res := httptest.NewRecorder()
	testHandler(t, st).ServeHTTP(res, req)
	if res.Code != http.StatusForbidden || st.calls != 0 {
		t.Fatalf("unverified request reached store: %d, %d", res.Code, st.calls)
	}
}

func TestFailureMapping(t *testing.T) {
	h := testHandler(t, &store{})
	for _, tt := range []struct {
		err    error
		status int
		code   string
	}{
		{service.ErrInvalidCursor, 400, "INVALID_CURSOR"},
		{service.ErrRevisionChanged, 409, "POLICY_REVISION_CHANGED"},
		{service.ErrScopeLimit, 422, "SCOPE_LIMIT_EXCEEDED"},
		{service.ErrUnavailable, 503, "SERVICE_UNAVAILABLE"},
		{errors.New("private policy data"), 500, "INTERNAL_ERROR"},
	} {
		res := httptest.NewRecorder()
		h.failure(res, tt.err, "safe-id")
		var body map[string]string
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil || res.Code != tt.status || body["code"] != tt.code || body["correlationId"] != "safe-id" || len(body) != 2 {
			t.Fatalf("status=%d body=%s err=%v", res.Code, res.Body.String(), err)
		}
	}
}
