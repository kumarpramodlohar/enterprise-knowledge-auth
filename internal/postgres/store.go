// Package postgres implements policy reads against the proposed auth schema.
// Schema creation and production guard installation are deliberately separate.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/service"
)

var errMissingOIDC = errors.New("OIDC identity not found")

// Store depends on a separately provisioned schema and guarded provisioning
// function. It never creates or modifies database objects.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("missing PostgreSQL pool")
	}
	return &Store{pool: pool}, nil
}

// Resolve reads existing users without writing, including during a freeze.
// First-time OIDC creation is delegated to the database's guarded function.
func (s *Store) Resolve(ctx context.Context, id contract.Identity) (service.ResolveStatus, error) {
	var exists bool
	switch id.Kind {
	case "OIDC":
		err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM eka_auth.identities WHERE kind = 'OIDC' AND issuer = $1 AND subject = $2) FROM eka_auth.control WHERE singleton = true`, id.Issuer, id.Subject).Scan(&exists)
		if err != nil {
			return "", fmt.Errorf("resolve OIDC identity: %w", err)
		}
		if exists {
			return service.Existing, nil
		}
		var status string
		if err := s.pool.QueryRow(ctx, `SELECT eka_auth.resolve_oidc($1, $2)`, id.Issuer, id.Subject).Scan(&status); err != nil {
			return "", fmt.Errorf("guarded OIDC resolution: %w", err)
		}
		if status != string(service.Created) && status != string(service.Existing) {
			return "", errors.New("invalid guarded resolution result")
		}
		return service.ResolveStatus(status), nil
	case "LOCAL":
		err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM eka_auth.identities WHERE kind = 'LOCAL' AND local_namespace = $1 AND username = $2) FROM eka_auth.control WHERE singleton = true`, id.Namespace, id.Username).Scan(&exists)
		if err != nil {
			return "", fmt.Errorf("resolve local identity: %w", err)
		}
		if exists {
			return service.Existing, nil
		}
		return service.NotFound, nil
	default:
		return "", errors.New("unsupported identity kind")
	}
}

// Check reads the identity and requested grant together in one SQL snapshot.
func (s *Store) Check(ctx context.Context, id contract.Identity, collection [16]byte) (policy.Role, *policy.Permission, error) {
	kind, first, second, err := identityArgs(id)
	if err != nil {
		return "", nil, err
	}
	var role *string
	var permission *string
	err = s.pool.QueryRow(ctx, `
		SELECT i.role, g.permission
		FROM eka_auth.control c
		LEFT JOIN eka_auth.identities i ON i.kind = $1
		   AND (($1 = 'OIDC' AND i.issuer = $2 AND i.subject = $3)
		   OR ($1 = 'LOCAL' AND i.local_namespace = $2 AND i.username = $3))
		LEFT JOIN eka_auth.grants g ON g.identity_id = i.identity_id AND g.collection_id = $4
		WHERE c.singleton = true`,
		kind, first, second, pgtype.UUID{Bytes: collection, Valid: true}).Scan(&role, &permission)
	if err != nil {
		return "", nil, fmt.Errorf("read permission: %w", err)
	}
	if role == nil {
		if kind == "LOCAL" {
			return policy.None, nil, nil
		}
		return "", nil, errMissingOIDC
	}
	if permission == nil {
		return policy.Role(*role), nil, nil
	}
	value := policy.Permission(*permission)
	return policy.Role(*role), &value, nil
}

// Page obtains revision, role, count and keyset page from one repeatable-read
// snapshot. Scope-changing triggers must be installed separately on all writers.
func (s *Store) Page(ctx context.Context, id contract.Identity, after *[16]byte, pageSize, limit int) (result service.Snapshot, err error) {
	kind, first, second, err := identityArgs(id)
	if err != nil {
		return result, err
	}
	if pageSize < 1 || limit < 1 || pageSize >= int(^uint(0)>>1) || limit >= int(^uint(0)>>1) {
		return result, errors.New("invalid page limits")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, fmt.Errorf("begin scope snapshot: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(context.WithoutCancel(ctx)); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, fmt.Errorf("rollback scope snapshot: %w", rollbackErr))
		}
	}()
	var epoch pgtype.UUID
	var counter int64
	if err = tx.QueryRow(ctx, `SELECT epoch, revision FROM eka_auth.control WHERE singleton = true`).Scan(&epoch, &counter); err != nil {
		return result, fmt.Errorf("read policy revision: %w", err)
	}
	if !epoch.Valid || counter < 0 {
		return result, errors.New("invalid policy revision")
	}
	result.Revision = service.Revision{Epoch: epoch.Bytes, Counter: uint64(counter)}
	var identityID pgtype.UUID
	var role string
	err = tx.QueryRow(ctx, `
		SELECT identity_id, role FROM eka_auth.identities
		WHERE kind = $1 AND (($1 = 'OIDC' AND issuer = $2 AND subject = $3)
		   OR ($1 = 'LOCAL' AND local_namespace = $2 AND username = $3))`,
		kind, first, second).Scan(&identityID, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		if kind != "LOCAL" {
			return result, errMissingOIDC
		}
		result.Role = policy.None
		result.Entries = []service.Entry{}
		if err = tx.Commit(ctx); err != nil {
			return result, fmt.Errorf("commit scope snapshot: %w", err)
		}
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("read scope identity: %w", err)
	}
	result.Role = policy.Role(role)
	if !identityID.Valid || (result.Role != policy.Admin && result.Role != policy.Member) {
		return result, errors.New("invalid stored identity")
	}
	var query string
	if result.Role == policy.Admin {
		query = `SELECT id AS collection_id, 'MANAGE'::text AS permission FROM public.collections`
	} else {
		query = `SELECT collection_id, permission FROM eka_auth.grants WHERE identity_id = $1`
	}
	args := []any{}
	if result.Role == policy.Member {
		args = append(args, identityID)
	}
	countSQL := `SELECT count(*) FROM (SELECT collection_id FROM (` + query + `) scopes LIMIT $` + fmt.Sprint(len(args)+1) + `) bounded`
	countArgs := append(append([]any{}, args...), limit+1)
	if err = tx.QueryRow(ctx, countSQL, countArgs...).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count authorized scopes: %w", err)
	}
	result.Entries = []service.Entry{}
	if result.Total <= limit {
		afterUUID := pgtype.UUID{}
		if after != nil {
			afterUUID = pgtype.UUID{Bytes: *after, Valid: true}
		}
		nextArg := len(args) + 1
		pageSQL := fmt.Sprintf(`SELECT collection_id, permission FROM (%s) scopes WHERE ($%d::uuid IS NULL OR collection_id > $%d::uuid) ORDER BY collection_id LIMIT $%d`, query, nextArg, nextArg, nextArg+1)
		pageArgs := append(append([]any{}, args...), afterUUID, pageSize+1)
		rows, queryErr := tx.Query(ctx, pageSQL, pageArgs...)
		if queryErr != nil {
			return result, fmt.Errorf("read scope page: %w", queryErr)
		}
		for rows.Next() {
			var collection pgtype.UUID
			var permission string
			if scanErr := rows.Scan(&collection, &permission); scanErr != nil {
				rows.Close()
				return result, fmt.Errorf("scan scope page: %w", scanErr)
			}
			if !collection.Valid {
				rows.Close()
				return result, errors.New("invalid collection UUID")
			}
			result.Entries = append(result.Entries, service.Entry{CollectionID: collection.Bytes, Permission: policy.Permission(permission)})
		}
		rows.Close()
		if rows.Err() != nil {
			return result, fmt.Errorf("iterate scope page: %w", rows.Err())
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit scope snapshot: %w", err)
	}
	return result, nil
}

func identityArgs(id contract.Identity) (string, string, string, error) {
	switch id.Kind {
	case "OIDC":
		return id.Kind, id.Issuer, id.Subject, nil
	case "LOCAL":
		return id.Kind, id.Namespace, id.Username, nil
	default:
		return "", "", "", errors.New("unsupported identity kind")
	}
}
