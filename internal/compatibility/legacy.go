// Package compatibility checks legacy identity field limits without emitting
// identity values. It cannot determine or approve identity mappings.
package compatibility

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
)

// Config selects one candidate interpretation for every legacy subject.
// The operator must establish identity mappings separately.
type Config struct {
	Kind      string
	Issuer    string
	Namespace string
}

// Result contains aggregate counts only; an empty table is inconclusive.
type Result struct {
	Total        int64 `json:"total"`
	Incompatible int64 `json:"incompatible"`
}

// Check reads legacy subjects from one read-only snapshot and validates all
// three request shapes using the actual contract decoder. No identity values
// or raw database errors are returned.
func Check(ctx context.Context, pool *pgxpool.Pool, config Config) (result Result, err error) {
	if pool == nil {
		return result, errors.New("missing database pool")
	}
	trust := contract.Trust{}
	switch config.Kind {
	case "OIDC":
		if config.Namespace != "" || config.Issuer == "" {
			return result, errors.New("invalid OIDC compatibility configuration")
		}
		trust.AllowedIssuers = map[string]struct{}{config.Issuer: {}}
	case "LOCAL":
		if config.Issuer != "" || config.Namespace == "" {
			return result, errors.New("invalid local compatibility configuration")
		}
		trust.LocalEnabled = true
		trust.LocalNamespace = config.Namespace
	default:
		return result, errors.New("identity kind must be OIDC or LOCAL")
	}
	if !compatible("test", config, trust) {
		return result, errors.New("identity configuration exceeds contract limits")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, errors.New("cannot start read-only compatibility snapshot")
	}
	defer func() {
		if rollbackErr := tx.Rollback(context.WithoutCancel(ctx)); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.New("cannot close compatibility snapshot")
		}
	}()
	var encoding string
	var filtered, table bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_setting('server_encoding'), pg_catalog.row_security_active('public.app_users'::regclass), EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE oid = 'public.app_users'::regclass AND relkind IN ('r', 'p'))`).Scan(&encoding, &filtered, &table); err != nil {
		return result, errors.New("cannot verify legacy table visibility")
	}
	if encoding != "UTF8" || filtered || !table {
		return result, errors.New("legacy table requires UTF8, a base table, and unfiltered row visibility")
	}
	rows, err := tx.Query(ctx, `SELECT subject FROM public.app_users`)
	if err != nil {
		return result, errors.New("cannot read legacy subjects")
	}
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			rows.Close()
			return result, errors.New("cannot read legacy subject")
		}
		result.Total++
		if !compatible(subject, config, trust) {
			result.Incompatible++
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return result, errors.New("cannot complete legacy subject scan")
	}
	if err := tx.Commit(ctx); err != nil {
		return result, errors.New("cannot complete compatibility snapshot")
	}
	return result, nil
}

// compatible tests the real request serializers and validators, including
// encoded body size; it does not normalize or truncate the legacy subject.
func compatible(subject string, config Config, trust contract.Trust) bool {
	id := contract.Identity{Kind: config.Kind}
	if config.Kind == "OIDC" {
		id.Issuer, id.Subject = config.Issuer, subject
	} else {
		id.Namespace, id.Username = config.Namespace, subject
	}
	resolve, err := json.Marshal(contract.ResolveRequest{Identity: id})
	if err != nil {
		return false
	}
	check, err := json.Marshal(contract.CheckRequest{Identity: id, CollectionID: "00000000-0000-0000-0000-000000000001", Permission: "READ"})
	if err != nil {
		return false
	}
	page, err := json.Marshal(struct {
		Identity contract.Identity `json:"identity"`
	}{Identity: id})
	if err != nil {
		return false
	}
	if _, err := contract.DecodeResolve(resolve, trust); err != nil {
		return false
	}
	if _, err := contract.DecodeCheck(check, trust); err != nil {
		return false
	}
	if _, err := contract.DecodePage(page, trust, contract.DefaultPageSize); err != nil {
		return false
	}
	return true
}

// Summary reports compatibility without including identities or configuration.
func (r Result) Summary() string {
	if r.Total == 0 {
		return "inconclusive: no legacy identities were found"
	}
	if r.Incompatible != 0 {
		return fmt.Sprintf("incompatible: %d of %d legacy subjects exceed or violate candidate request limits", r.Incompatible, r.Total)
	}
	return fmt.Sprintf("field and request limits compatible for %d legacy subjects under the selected candidate interpretation", r.Total)
}
