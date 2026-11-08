// auth-compat checks legacy subjects with one explicit identity interpretation.
// It does not infer migration mappings or authorize deployment.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/compatibility"
)

func main() {
	os.Exit(run())
}

// run keeps connection cleanup active for both successful and failed checks.
func run() int {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dsn := os.Getenv("EKA_COMPAT_DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "EKA_COMPAT_DATABASE_URL is required")
		return 1
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot configure compatibility database")
		return 1
	}
	defer pool.Close()
	result, err := compatibility.Check(ctx, pool, compatibility.Config{
		Kind: os.Getenv("EKA_COMPAT_IDENTITY_KIND"), Issuer: os.Getenv("EKA_COMPAT_ISSUER"), Namespace: os.Getenv("EKA_COMPAT_LOCAL_NAMESPACE"),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(result.Summary())
	if result.Total == 0 || result.Incompatible != 0 {
		return 1
	}
	return 0
}
