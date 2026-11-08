// Package service coordinates policy operations against a transactional store.
// It validates store results and binds scope pages to cursors and revisions;
// the store interface's transactional guarantees must be implemented separately.
package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
)

var (
	ErrUnavailable     = errors.New("policy store unavailable")
	ErrInvalidCursor   = errors.New("invalid cursor")
	ErrRevisionChanged = errors.New("policy revision changed")
	ErrScopeLimit      = errors.New("scope limit exceeded")
	ErrInvalidState    = errors.New("invalid policy state")
)

type ResolveStatus string

const (
	Created  ResolveStatus = "CREATED"
	Existing ResolveStatus = "EXISTING"
	NotFound ResolveStatus = "NOT_FOUND"
)

type Revision struct {
	Epoch   [16]byte
	Counter uint64
}

type Entry struct {
	CollectionID [16]byte
	Permission   policy.Permission
}

type Snapshot struct {
	Revision Revision
	Role     policy.Role
	// Total is the number of authorized collections, capped at limit + 1.
	Total   int
	Entries []Entry
}

// Store must resolve identities atomically and return fresh policy. Page must
// read revision, role, count and entries in a single repeatable-read snapshot.
// It returns up to pageSize+1 ordered entries strictly after after, or from the
// beginning when after is nil. A missing OIDC identity is an error.
type Store interface {
	// Resolve atomically resolves or provisions an eligible identity.
	// Existing users must retain their roles and grants, while unknown local
	// identities must not be created.
	Resolve(context.Context, contract.Identity) (ResolveStatus, error)
	// Check loads the current role and optional grant for a collection.
	// It must distinguish an unknown local identity from a missing OIDC identity.
	Check(context.Context, contract.Identity, [16]byte) (policy.Role, *policy.Permission, error)
	// Page loads the revision, role, total, and ordered page in one consistent
	// snapshot so the service can detect policy changes and incomplete scopes.
	Page(context.Context, contract.Identity, *[16]byte, int, int) (Snapshot, error)
}

type Service struct {
	store       Store
	codec       *cursor.Codec
	maxPageSize int
	scopeLimit  int
	now         func() time.Time
}

// New validates the store, cursor codec, and scope/page limits before creating
// a service. Rejecting invalid configuration prevents unsafe pagination.
func New(store Store, codec *cursor.Codec, maxPageSize, scopeLimit int) (*Service, error) {
	if store == nil || codec == nil || maxPageSize < contract.DefaultPageSize || uint64(maxPageSize) > uint64(^uint32(0)) || scopeLimit < 1 || scopeLimit == int(^uint(0)>>1) {
		return nil, errors.New("invalid service configuration")
	}
	return &Service{store: store, codec: codec, maxPageSize: maxPageSize, scopeLimit: scopeLimit, now: time.Now}, nil
}

// MaxPageSize returns the configured page bound so the HTTP layer and service
// can use the same request limit.
func (s *Service) MaxPageSize() int {
	return s.maxPageSize
}

// Resolve delegates identity resolution to the store and checks that its status
// is valid for the identity kind. Store failures and inconsistent results are
// errors, so they cannot be reported as successful provisioning.
func (s *Service) Resolve(ctx context.Context, id contract.Identity) (ResolveStatus, error) {
	status, err := s.store.Resolve(ctx, id)
	if err != nil {
		return "", fmt.Errorf("%w: resolve failed", ErrUnavailable)
	}
	switch status {
	case Created:
		if id.Kind != "OIDC" {
			return "", ErrInvalidState
		}
	case NotFound:
		if id.Kind != "LOCAL" {
			return "", ErrInvalidState
		}
	case Existing:
		if id.Kind != "OIDC" && id.Kind != "LOCAL" {
			return "", ErrInvalidState
		}
	default:
		return "", ErrInvalidState
	}
	return status, nil
}

// Check loads fresh role and grant data and evaluates the requested permission.
// Store failures or invalid policy state produce an error rather than ALLOW or
// DENY; protected-resource existence remains the caller's responsibility.
func (s *Service) Check(ctx context.Context, id contract.Identity, collection [16]byte, requested policy.Permission) (policy.Decision, error) {
	role, grant, err := s.store.Check(ctx, id, collection)
	if err != nil {
		return "", fmt.Errorf("%w: check failed", ErrUnavailable)
	}
	decision, err := policy.Evaluate(id.Kind, role, grant, requested)
	if err != nil {
		return "", ErrInvalidState
	}
	return decision, nil
}

type Page struct {
	Role       policy.Role
	Revision   string
	Entries    []Entry
	NextCursor *string
}

// Page verifies any cursor against the caller and identity, then reads a store
// snapshot and compares revisions. It checks limits, ordering, roles and
// permissions before returning entries and signing a continuation cursor.
// Consistency depends on Store.Page implementing its snapshot contract.
func (s *Service) Page(ctx context.Context, id contract.Identity, caller string, pageSize int, token string) (Page, error) {
	if caller == "" || pageSize < 1 || pageSize > s.maxPageSize {
		return Page{}, ErrInvalidState
	}
	binding := cursor.Binding{Caller: caller, Kind: id.Kind, Issuer: id.Issuer, Subject: id.Subject, Namespace: id.Namespace, Username: id.Username, PageSize: uint32(pageSize)}
	var prior *cursor.State
	var after *[16]byte
	if token != "" {
		state, err := s.codec.Verify(token, binding, s.now())
		if err != nil {
			return Page{}, ErrInvalidCursor
		}
		prior = &state
		after = &state.LastID
	}
	snapshot, err := s.store.Page(ctx, id, after, pageSize, s.scopeLimit)
	if err != nil {
		return Page{}, fmt.Errorf("%w: page failed", ErrUnavailable)
	}
	if prior != nil && (snapshot.Revision.Epoch != prior.Epoch || snapshot.Revision.Counter != prior.Revision) {
		return Page{}, ErrRevisionChanged
	}
	if snapshot.Total < 0 || snapshot.Total > s.scopeLimit+1 {
		return Page{}, ErrInvalidState
	}
	if snapshot.Total > s.scopeLimit {
		return Page{}, ErrScopeLimit
	}
	if (snapshot.Role != policy.Admin && snapshot.Role != policy.Member && snapshot.Role != policy.None) ||
		(snapshot.Role == policy.None && (id.Kind != "LOCAL" || snapshot.Total != 0)) ||
		(id.Kind != "LOCAL" && id.Kind != "OIDC") ||
		len(snapshot.Entries) > pageSize+1 || len(snapshot.Entries) > snapshot.Total ||
		(after != nil && len(snapshot.Entries) == 0) {
		return Page{}, ErrInvalidState
	}
	if after == nil {
		expected := snapshot.Total
		if expected > pageSize+1 {
			expected = pageSize + 1
		}
		if len(snapshot.Entries) != expected {
			return Page{}, ErrInvalidState
		}
	}
	last := after
	for i := range snapshot.Entries {
		entry := &snapshot.Entries[i]
		if (entry.Permission != policy.Read && entry.Permission != policy.Manage) ||
			(snapshot.Role == policy.Admin && entry.Permission != policy.Manage) ||
			(last != nil && bytes.Compare(last[:], entry.CollectionID[:]) >= 0) {
			return Page{}, ErrInvalidState
		}
		last = &entry.CollectionID
	}
	entries := snapshot.Entries
	var next *string
	if len(entries) > pageSize {
		entries = entries[:pageSize]
		state := cursor.State{Epoch: snapshot.Revision.Epoch, Revision: snapshot.Revision.Counter, LastID: entries[len(entries)-1].CollectionID}
		value, err := s.codec.Sign(state, binding, s.now())
		if err != nil {
			return Page{}, ErrInvalidState
		}
		next = &value
	}
	result := Page{Role: snapshot.Role, Revision: encodeRevision(snapshot.Revision), Entries: append([]Entry{}, entries...), NextCursor: next}
	return result, nil
}

// encodeRevision converts the epoch and counter into an opaque API string.
// A stable encoding lets consumers compare revisions without depending on the
// store's internal representation.
func encodeRevision(revision Revision) string {
	var raw [24]byte
	copy(raw[:16], revision.Epoch[:])
	binary.BigEndian.PutUint64(raw[16:], revision.Counter)
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
