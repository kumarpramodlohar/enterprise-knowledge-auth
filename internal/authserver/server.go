package authserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/httpapi"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/postgres"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/transport"
)

// Run validates all runtime controls before opening its listener, requires
// end-to-end mutual TLS, and shuts down gracefully when the context is cancelled.
func Run(ctx context.Context, cfg Config, ready func(string), logger *slog.Logger) error {
	if ready == nil || logger == nil {
		return errors.New("readiness callback and logger are required")
	}
	dbConfig, err := cfg.Validate()
	if err != nil {
		return err
	}
	tlsConfig, err := transport.ServerTLSConfig(cfg.ServerCertificate, cfg.ServerKey, cfg.ClientCA)
	if err != nil {
		return fmt.Errorf("invalid auth server TLS configuration: %w", err)
	}
	keys := map[string]cursor.KeyPair{}
	signing, err := readSecret(cfg.SigningKeyFile)
	if err != nil {
		return errors.New("cannot load active cursor signing key")
	}
	binding, err := readSecret(cfg.BindingKeyFile)
	if err != nil {
		return errors.New("cannot load active cursor binding key")
	}
	keys[cfg.SigningKeyID] = cursor.KeyPair{Signing: signing, Binding: binding}
	if cfg.PreviousSigningKeyID != "" {
		previousSigning, err := readSecret(cfg.PreviousSigningKeyFile)
		if err != nil {
			return errors.New("cannot load previous cursor signing key")
		}
		previousBinding, err := readSecret(cfg.PreviousBindingKeyFile)
		if err != nil {
			return errors.New("cannot load previous cursor binding key")
		}
		keys[cfg.PreviousSigningKeyID] = cursor.KeyPair{Signing: previousSigning, Binding: previousBinding}
	}
	codec, err := cursor.New(cfg.SigningKeyID, keys, cursorLifetime, clockSkew)
	if err != nil {
		return errors.New("invalid cursor key configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		return errors.New("cannot initialize auth database pool")
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return errors.New("cannot connect to auth database")
	}
	store, err := postgres.New(pool)
	if err != nil {
		return errors.New("cannot initialize auth policy store")
	}
	if err := store.VerifySchema(pingCtx); err != nil {
		return fmt.Errorf("auth database policy controls are not safe: %w", err)
	}
	svc, err := service.New(store, codec, cfg.MaxPageSize, cfg.ScopeLimit)
	if err != nil {
		return errors.New("cannot initialize auth policy service")
	}
	issuers := make(map[string]struct{}, len(cfg.Issuers))
	for _, issuer := range cfg.Issuers {
		issuers[issuer] = struct{}{}
	}
	trust := contract.Trust{AllowedIssuers: issuers, LocalNamespace: cfg.LocalNamespace, LocalEnabled: cfg.LocalNamespace != ""}
	handler, err := httpapi.New(svc, trust, cfg.CallerURIs, cfg.MaxPageSize, logger)
	if err != nil {
		return errors.New("invalid auth API trust configuration")
	}
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return errors.New("cannot bind auth listener")
	}
	server := &http.Server{
		Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}
	result := make(chan error, 1)
	go func() { result <- server.ServeTLS(listener, "", "") }()
	ready(listener.Addr().String())
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("auth TLS listener failed")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			if closeErr := server.Close(); closeErr != nil {
				return errors.New("auth server shutdown and close failed")
			}
			return errors.New("auth server shutdown timed out")
		}
		if err := <-result; !errors.Is(err, http.ErrServerClosed) {
			return errors.New("auth TLS listener failed during shutdown")
		}
		return nil
	}
}

func readSecret(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("secret key must be a regular file")
	}
	key, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("invalid secret key size")
	}
	return key, nil
}
