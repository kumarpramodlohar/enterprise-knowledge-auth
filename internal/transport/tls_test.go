package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCertificate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	tls  tls.Certificate
}

func makeCertificate(t *testing.T, parent *testCertificate, ca bool, usage x509.ExtKeyUsage, expires time.Time) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
		BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		if usage == x509.ExtKeyUsageServerAuth {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
	}
	signer, signingKey := template, key
	if parent != nil {
		signer, signingKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), tls: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

func writeCertificateFiles(t *testing.T, cert, ca testCertificate) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, caPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"), filepath.Join(dir, "client-ca.pem")
	for path, content := range map[string][]byte{
		certPath: cert.pem,
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		caPath:   ca.pem,
	} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath, caPath
}

func TestServerTLSConfig(t *testing.T) {
	now := time.Now()
	ca := makeCertificate(t, nil, true, 0, now.Add(time.Hour))
	serverCert := makeCertificate(t, &ca, false, x509.ExtKeyUsageServerAuth, now.Add(time.Hour))
	clientCert := makeCertificate(t, &ca, false, x509.ExtKeyUsageClientAuth, now.Add(time.Hour))
	expiredClient := makeCertificate(t, &ca, false, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute))
	otherCA := makeCertificate(t, nil, true, 0, now.Add(time.Hour))
	otherClient := makeCertificate(t, &otherCA, false, x509.ExtKeyUsageClientAuth, now.Add(time.Hour))
	certPath, keyPath, caPath := writeCertificateFiles(t, serverCert, ca)
	cfg, err := ServerTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = cfg
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	for _, tt := range []struct {
		name       string
		client     *tls.Certificate
		serverName string
		wantOK     bool
	}{
		{"valid client", &clientCert.tls, "localhost", true},
		{"missing client", nil, "localhost", false},
		{"untrusted client", &otherClient.tls, "localhost", false},
		{"expired client", &expiredClient.tls, "localhost", false},
		{"wrong server name", &clientCert.tls, "wrong.example", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := &tls.Config{RootCAs: roots, ServerName: tt.serverName, MinVersion: tls.VersionTLS12}
			if tt.client != nil {
				config.Certificates = []tls.Certificate{*tt.client}
			}
			transport := &http.Transport{TLSClientConfig: config}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			resp, err := client.Get(server.URL)
			if err != nil {
				if tt.wantOK {
					t.Fatal(err)
				}
				return
			}
			defer resp.Body.Close()
			if !tt.wantOK || resp.StatusCode != http.StatusNoContent {
				t.Fatalf("unexpected successful response: %s", resp.Status)
			}
		})
	}
}

func TestServerTLSConfigRejectsInvalidFiles(t *testing.T) {
	now := time.Now()
	ca := makeCertificate(t, nil, true, 0, now.Add(time.Hour))
	server := makeCertificate(t, &ca, false, x509.ExtKeyUsageServerAuth, now.Add(time.Hour))
	certPath, keyPath, caPath := writeCertificateFiles(t, server, ca)
	if _, err := ServerTLSConfig("", keyPath, caPath); err == nil {
		t.Fatal("accepted missing server certificate")
	}
	expired := makeCertificate(t, &ca, false, x509.ExtKeyUsageServerAuth, now.Add(-time.Minute))
	expiredCert, expiredKey, _ := writeCertificateFiles(t, expired, ca)
	if _, err := ServerTLSConfig(expiredCert, expiredKey, caPath); err == nil {
		t.Fatal("accepted expired server certificate")
	}
	for _, content := range [][]byte{nil, []byte("not a PEM file"), append([]byte("unexpected\n"), ca.pem...), server.pem} {
		if err := os.WriteFile(caPath, content, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ServerTLSConfig(certPath, keyPath, caPath); err == nil {
			t.Fatal("accepted invalid CA bundle")
		}
	}
}
