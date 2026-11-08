// Package transport configures the auth service's end-to-end TLS boundary.
package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// ServerTLSConfig loads a server certificate and a client CA bundle and
// requires every connection to present a verified client certificate.
// The HTTP handler must still authorize the client's URI SAN. Reloading or
// revoking trust and terminating existing connections are not handled here.
func ServerTLSConfig(serverCertFile, serverKeyFile, clientCAFile string) (*tls.Config, error) {
	if serverCertFile == "" || serverKeyFile == "" || clientCAFile == "" {
		return nil, errors.New("server certificate, key and client CA files are required")
	}
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate and key: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("server certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse server certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("server certificate is not currently valid")
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(caPEM)) != 0 {
		caPEM = bytes.TrimSpace(caPEM)
		if !bytes.HasPrefix(caPEM, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("client CA bundle contains invalid PEM")
		}
		block, rest := pem.Decode(caPEM)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("client CA bundle contains invalid PEM")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse client CA certificate: %w", err)
		}
		if !ca.IsCA || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
			return nil, errors.New("client CA is not a currently valid CA certificate")
		}
		pool.AddCert(ca)
		count++
		caPEM = rest
	}
	if count == 0 {
		return nil, errors.New("client CA bundle is empty")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}
