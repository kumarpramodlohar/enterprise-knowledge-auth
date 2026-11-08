// authd runs the versioned internal auth API behind verified mutual TLS.
// Database schema and role provisioning are managed separately.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/authserver"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := authserver.FromEnv()
	if err != nil {
		logger.Error("invalid auth server environment", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = authserver.Run(ctx, cfg, func(address string) {
		fmt.Printf("auth service listening on %s\n", address)
	}, logger)
	if err != nil {
		logger.Error("auth service stopped", "error", err)
		os.Exit(1)
	}
}
