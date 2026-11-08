// auth-local runs the experimental auth service only on loopback and against
// a separately created synthetic test database. It is not a production server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/localapp"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := localapp.Run(ctx, localapp.FromEnv(), func(address string) {
		fmt.Printf("local test service listening on %s\n", address)
	}, logger)
	if err != nil {
		logger.Error("local test service stopped", "error", err)
		os.Exit(1)
	}
}
