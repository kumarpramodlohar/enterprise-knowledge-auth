package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/cursor"
	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/policy"
)

type fakeStore struct {
	snapshot Snapshot
	status   ResolveStatus
	role     policy.Role
	grant    *policy.Permission
	err      error
	calls    int
	after    *[16]byte
}

func (f *fakeStore) Resolve(context.Context, contract.Identity) (ResolveStatus, error) {
	return f.status, f.err
}
func (f *fakeStore) Check(context.Context, contract.Identity, [16]byte) (policy.Role, *policy.Permission, error) {
	return f.role, f.grant, f.err
}
func (f *fakeStore) Page(_ context.Context, _ contract.Identity, after *[16]byte, _, _ int) (Snapshot, error) {
	f.calls++
	f.after = after
	return f.snapshot, f.err
}

func setup(t *testing.T, f *fakeStore) *Service {
	t.Helper()
	codec, err := cursor.New("k", map[string]cursor.KeyPair{"k": {Signing: bytes.Repeat([]byte{1}, 32), Binding: bytes.Repeat([]byte{2}, 32)}}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(f, codec, 500, 3)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	return s
}

func entry(n byte) Entry {
	return Entry{CollectionID: [16]byte{15: n}, Permission: policy.Read}
}

var oidc = contract.Identity{Kind: "OIDC", Issuer: "issuer", Subject: "subject"}
var local = contract.Identity{Kind: "LOCAL", Namespace: "local", Username: "user"}

func TestResolveAndCheckFailClosed(t *testing.T) {
	f := &fakeStore{status: Created, role: policy.Member}
	s := setup(t, f)
	if got, err := s.Resolve(context.Background(), oidc); got != Created || err != nil {
		t.Fatalf("resolve: %s %v", got, err)
	}
	if _, err := s.Resolve(context.Background(), local); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid local creation: %v", err)
	}
	f.status = NotFound
	if _, err := s.Resolve(context.Background(), oidc); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("missing OIDC resolution: %v", err)
	}
	f.role = policy.None
	if _, err := s.Check(context.Background(), oidc, [16]byte{}, policy.Read); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("missing OIDC check: %v", err)
	}
	if got, err := s.Check(context.Background(), local, [16]byte{}, policy.Read); got != policy.Deny || err != nil {
		t.Fatalf("unknown local: %s %v", got, err)
	}
	f.err = errors.New("private database detail")
	if _, err := s.Check(context.Background(), oidc, [16]byte{}, policy.Read); !errors.Is(err, ErrUnavailable) || err.Error() == f.err.Error() {
		t.Fatalf("store failure: %v", err)
	}
}

func TestPaginationRevisionBindingAndLimits(t *testing.T) {
	ctx := context.Background()
	f := &fakeStore{snapshot: Snapshot{Revision: Revision{Epoch: [16]byte{1}, Counter: 2}, Role: policy.Member, Total: 3, Entries: []Entry{entry(1), entry(2), entry(3)}}}
	s := setup(t, f)
	first, err := s.Page(ctx, oidc, "spiffe://backend", 2, "")
	if err != nil || len(first.Entries) != 2 || first.NextCursor == nil || first.Revision == "" {
		t.Fatalf("first page: %+v %v", first, err)
	}
	f.snapshot.Entries = []Entry{entry(3)}
	second, err := s.Page(ctx, oidc, "spiffe://backend", 2, *first.NextCursor)
	if err != nil || len(second.Entries) != 1 || second.NextCursor != nil || second.Revision != first.Revision || f.after == nil || *f.after != entry(2).CollectionID {
		t.Fatalf("second page: %+v %v", second, err)
	}
	calls := f.calls
	if _, err := s.Page(ctx, oidc, "spiffe://other", 2, *first.NextCursor); !errors.Is(err, ErrInvalidCursor) || f.calls != calls {
		t.Fatalf("binding should fail before store: %v", err)
	}
	f.snapshot.Revision.Counter++
	if _, err := s.Page(ctx, oidc, "spiffe://backend", 2, *first.NextCursor); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("stale revision: %v", err)
	}
	f.snapshot = Snapshot{Role: policy.Admin, Total: 4}
	if _, err := s.Page(ctx, oidc, "spiffe://backend", 2, ""); !errors.Is(err, ErrScopeLimit) {
		t.Fatalf("over limit: %v", err)
	}
}

func TestInvalidSnapshots(t *testing.T) {
	tests := []Snapshot{
		{Role: policy.Member, Total: 2, Entries: []Entry{entry(1)}},
		{Role: policy.Member, Total: 2, Entries: []Entry{entry(2), entry(1)}},
		{Role: policy.Member, Total: 2, Entries: []Entry{entry(1), entry(1)}},
		{Role: policy.Member, Total: 1, Entries: []Entry{{Permission: "WRITE"}}},
		{Role: policy.Admin, Total: 1, Entries: []Entry{entry(1)}},
		{Role: policy.None, Total: 0},
		{Role: "OTHER", Total: 0},
		{Role: policy.Member, Total: -1},
	}

	for _, snapshot := range tests {
		f := &fakeStore{snapshot: snapshot}
		if _, err := setup(t, f).Page(context.Background(), oidc, "backend", 2, ""); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("accepted snapshot %+v: %v", snapshot, err)
		}
	}
	f := &fakeStore{snapshot: Snapshot{Role: policy.None, Entries: nil}}
	page, err := setup(t, f).Page(context.Background(), local, "backend", 2, "")
	if err != nil || page.Entries == nil || len(page.Entries) != 0 {
		t.Fatalf("unknown local: %+v, %v", page, err)
	}
}

func TestScopeLimitAtTenThousand(t *testing.T) {
	codec, err := cursor.New("k", map[string]cursor.KeyPair{"k": {Signing: bytes.Repeat([]byte{1}, 32), Binding: bytes.Repeat([]byte{2}, 32)}}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]Entry, 501)
	for i := range entries {
		entries[i].CollectionID[14] = byte(i >> 8)
		entries[i].CollectionID[15] = byte(i)
		entries[i].Permission = policy.Manage
	}
	f := &fakeStore{snapshot: Snapshot{Role: policy.Admin, Total: 10000, Entries: entries}}
	s, err := New(f, codec, 500, 10000)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Page(context.Background(), oidc, "backend", 500, "")
	if err != nil || len(page.Entries) != 500 || page.NextCursor == nil {
		t.Fatalf("10,000 scopes: %d %v", len(page.Entries), err)
	}
	f.snapshot.Total = 10001
	if _, err := s.Page(context.Background(), oidc, "backend", 500, ""); !errors.Is(err, ErrScopeLimit) {
		t.Fatalf("10,001 scopes: %v", err)
	}
}
