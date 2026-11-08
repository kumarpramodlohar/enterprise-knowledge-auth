// Package localapp wires the experimental auth components for isolated tests.
// It must not be used as a production service or a policy authority.
package localapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/httpapi"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/postgres"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/transport"
)

// Config contains paths to test-only secrets and connection settings.
// DatabaseURL must never be logged.
type Config struct {
	Address, DatabaseURL, ServerCertificate, ServerKey, ClientCA      string
	SigningKeyFile, BindingKeyFile, CallerURI, Issuer, LocalNamespace string
}

// FromEnv loads explicit local test settings without printing sensitive values.
func FromEnv() Config {
	return Config{
		Address: os.Getenv("EKA_LOCAL_LISTEN"), DatabaseURL: os.Getenv("EKA_LOCAL_DATABASE_URL"),
		ServerCertificate: os.Getenv("EKA_LOCAL_SERVER_CERT"), ServerKey: os.Getenv("EKA_LOCAL_SERVER_KEY"),
		ClientCA: os.Getenv("EKA_LOCAL_CLIENT_CA"), SigningKeyFile: os.Getenv("EKA_LOCAL_SIGNING_KEY"),
		BindingKeyFile: os.Getenv("EKA_LOCAL_BINDING_KEY"), CallerURI: os.Getenv("EKA_LOCAL_CALLER_URI"),
		Issuer: os.Getenv("EKA_LOCAL_OIDC_ISSUER"), LocalNamespace: os.Getenv("EKA_LOCAL_NAMESPACE"),
	}
}

// Validate limits the test process to loopback and a named synthetic database.
// These checks are not a substitute for production schema and role controls.
func (c Config) Validate() (*pgxpool.Config, error) {
	host, port, err := net.SplitHostPort(c.Address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("EKA_LOCAL_LISTEN must use a loopback IP and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return nil, errors.New("invalid local listen port")
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("EKA_LOCAL_DATABASE_URL is required")
	}
	db, err := pgxpool.ParseConfig(c.DatabaseURL)
	if err != nil {
		return nil, errors.New("invalid local database configuration")
	}
	dbIP := net.ParseIP(db.ConnConfig.Host)
	if dbIP == nil || !dbIP.IsLoopback() || !strings.HasPrefix(db.ConnConfig.Database, "eka_auth_test_") || len(db.ConnConfig.Database) == len("eka_auth_test_") {
		return nil, errors.New("local database must use a loopback IP and an eka_auth_test_* database")
	}
	for _, fallback := range db.ConnConfig.Fallbacks {
		ip := net.ParseIP(fallback.Host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("database fallback must use a loopback IP")
		}
	}
	if c.ServerCertificate == "" || c.ServerKey == "" || c.ClientCA == "" || c.SigningKeyFile == "" || c.BindingKeyFile == "" || c.CallerURI == "" || (c.Issuer == "" && c.LocalNamespace == "") {
		return nil, errors.New("local certificate, key, caller and identity settings are required")
	}
	return db, nil
}

// Run starts the loopback-only mTLS server against an already prepared
// synthetic schema and stops it when ctx is cancelled.
func Run(ctx context.Context, c Config, ready func(string), logger *slog.Logger) error {
	if logger == nil || ready == nil {
		return errors.New("logger and readiness callback are required")
	}
	db, err := c.Validate()
	if err != nil {
		return err
	}
	tlsConfig, err := transport.ServerTLSConfig(c.ServerCertificate, c.ServerKey, c.ClientCA)
	if err != nil {
		return fmt.Errorf("invalid local TLS configuration: %w", err)
	}
	signing, err := readKey(c.SigningKeyFile)
	if err != nil {
		return errors.New("cannot load local cursor signing key")
	}
	binding, err := readKey(c.BindingKeyFile)
	if err != nil {
		return errors.New("cannot load local cursor binding key")
	}
	codec, err := cursor.New("local", map[string]cursor.KeyPair{"local": {Signing: signing, Binding: binding}}, time.Minute, 5*time.Second)
	if err != nil {
		return errors.New("invalid local cursor keys")
	}
	pool, err := pgxpool.NewWithConfig(ctx, db)
	if err != nil {
		return errors.New("cannot initialize local database pool")
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return errors.New("cannot connect to local test database")
	}
	store, err := postgres.New(pool)
	if err != nil {
		return errors.New("cannot initialize local policy store")
	}
	if err := store.VerifySchema(pingCtx); err != nil {
		return fmt.Errorf("local database policy controls are not safe: %w", err)
	}
	svc, err := service.New(store, codec, 500, 10000)
	if err != nil {
		return errors.New("cannot initialize local policy service")
	}
	trust := contract.Trust{AllowedIssuers: map[string]struct{}{}, LocalNamespace: c.LocalNamespace, LocalEnabled: c.LocalNamespace != ""}
	if c.Issuer != "" {
		trust.AllowedIssuers[c.Issuer] = struct{}{}
	}
	handler, err := httpapi.New(svc, trust, []string{c.CallerURI}, 500, logger)
	if err != nil {
		return errors.New("invalid local identity configuration")
	}
	listener, err := net.Listen("tcp", c.Address)
	if err != nil {
		return errors.New("cannot bind local listener")
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	result := make(chan error, 1)
	go func() { result <- server.ServeTLS(listener, "", "") }()
	ready(listener.Addr().String())
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("local TLS listener failed")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			if closeErr := server.Close(); closeErr != nil {
				return errors.New("local server shutdown and close failed")
			}
			return errors.New("local server shutdown timed out")
		}
		if err := <-result; !errors.Is(err, http.ErrServerClosed) {
			return errors.New("local TLS listener failed during shutdown")
		}
		return nil
	}
}

func readKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("invalid key size or file")
	}
	return key, nil
}
