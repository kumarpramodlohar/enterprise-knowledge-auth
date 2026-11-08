// Package cursor authenticates and binds pagination state without exposing identities.
// Signing records a keyed request binding; verification checks the signature,
// lifetime, and binding before callers compare the revision with the store.
package cursor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid cursor")

type KeyPair struct {
	Signing []byte
	Binding []byte
}

type Binding struct {
	Caller, Kind, Issuer, Subject, Namespace, Username string
	PageSize                                           uint32
}

type State struct {
	Epoch    [16]byte
	Revision uint64
	LastID   [16]byte
}

type Codec struct {
	active   string
	keys     map[string]KeyPair
	lifetime time.Duration
	skew     time.Duration
}

// New validates and copies the active and optional previous key pairs and the
// lifetime and skew limits. Separate, sufficiently long keys and bounded
// rotation reduce the risk of accepting invalid or indefinitely valid cursors.
func New(active string, keys map[string]KeyPair, lifetime, skew time.Duration) (*Codec, error) {
	if active == "" || len(active) > 64 || len(keys) < 1 || len(keys) > 2 || lifetime <= 0 || lifetime > 60*time.Second || skew < 0 || skew > 5*time.Second || lifetime%time.Second != 0 || skew%time.Second != 0 {
		return nil, errors.New("invalid cursor configuration")
	}
	copyKeys := make(map[string]KeyPair, len(keys))
	for id, key := range keys {
		if len(id) == 0 || len(id) > 64 || len(key.Signing) < 32 || len(key.Binding) < 32 || hmac.Equal(key.Signing, key.Binding) {
			return nil, errors.New("invalid cursor key pair")
		}
		copyKeys[id] = KeyPair{Signing: bytes.Clone(key.Signing), Binding: bytes.Clone(key.Binding)}
	}
	if _, ok := copyKeys[active]; !ok {
		return nil, errors.New("active cursor key not found")
	}
	return &Codec{active: active, keys: copyKeys, lifetime: lifetime, skew: skew}, nil
}

// Sign encodes the revision and last collection ID, adds a keyed digest of the
// request binding, and signs the payload with the active key. This allows
// stateless continuation without placing raw user identities in the cursor.
// The signed payload is not encrypted.
func (c *Codec) Sign(state State, binding Binding, now time.Time) (string, error) {
	if binding.Caller == "" || binding.PageSize == 0 {
		return "", errors.New("invalid cursor binding")
	}
	key := c.keys[c.active]
	var payload bytes.Buffer
	payload.WriteByte(1)
	payload.WriteByte(byte(len(c.active)))
	payload.WriteString(c.active)
	write64(&payload, uint64(now.Unix()))
	write64(&payload, uint64(now.Add(c.lifetime).Unix()))
	payload.Write(state.Epoch[:])
	write64(&payload, state.Revision)
	payload.Write(state.LastID[:])
	payload.Write(bindingDigest(key.Binding, binding, state))
	mac := hmac.New(sha256.New, key.Signing)
	mac.Write(payload.Bytes())
	return base64.RawURLEncoding.EncodeToString(payload.Bytes()) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify authenticates the cursor, checks its timestamps, and validates its
// binding before returning pagination state. The caller must still compare the
// returned revision with a fresh store snapshot; a cursor is not authorization.
func (c *Codec) Verify(token string, binding Binding, now time.Time) (State, error) {
	var state State
	if len(token) == 0 || len(token) > 4096 || binding.Caller == "" || binding.PageSize == 0 {
		return state, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return state, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(payload) < 2 || payload[0] != 1 {
		return state, ErrInvalid
	}
	idLen := int(payload[1])
	if idLen < 1 || idLen > 64 || len(payload) != 2+idLen+8+8+16+8+16+sha256.Size {
		return state, ErrInvalid
	}
	key, ok := c.keys[string(payload[2:2+idLen])]
	tag, tagErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if !ok || tagErr != nil || len(tag) != sha256.Size {
		return state, ErrInvalid
	}
	mac := hmac.New(sha256.New, key.Signing)
	mac.Write(payload)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return state, ErrInvalid
	}
	reader := bytes.NewReader(payload[2+idLen:])
	var issued, expires uint64
	if binary.Read(reader, binary.BigEndian, &issued) != nil || binary.Read(reader, binary.BigEndian, &expires) != nil ||
		issued > uint64(^uint64(0)>>1) || expires > uint64(^uint64(0)>>1) {
		return State{}, ErrInvalid
	}
	issueTime, expiryTime := time.Unix(int64(issued), 0), time.Unix(int64(expires), 0)
	if expiryTime.Before(issueTime) || expiryTime.Sub(issueTime) > c.lifetime ||
		issueTime.After(now.Add(c.skew)) || !now.Before(expiryTime.Add(c.skew)) {
		return State{}, ErrInvalid
	}
	if _, err := io.ReadFull(reader, state.Epoch[:]); err != nil {
		return State{}, ErrInvalid
	}
	if binary.Read(reader, binary.BigEndian, &state.Revision) != nil {
		return State{}, ErrInvalid
	}
	if _, err := io.ReadFull(reader, state.LastID[:]); err != nil {
		return State{}, ErrInvalid
	}
	digest := make([]byte, sha256.Size)
	if _, err := io.ReadFull(reader, digest); err != nil || reader.Len() != 0 ||
		!hmac.Equal(digest, bindingDigest(key.Binding, binding, state)) {
		return State{}, ErrInvalid
	}
	return state, nil
}

// bindingDigest computes a domain-separated HMAC over length-delimited caller,
// identity, endpoint, page size, and revision fields. This binds a cursor to
// its originating request without embedding the raw identity in the payload.
func bindingDigest(key []byte, binding Binding, state State) []byte {
	mac := hmac.New(sha256.New, key)
	for _, field := range []string{"eka.scope.cursor.binding.v1", binding.Caller, binding.Kind, binding.Issuer, binding.Subject, binding.Namespace, binding.Username, "/internal/v1/scopes/page"} {
		_ = binary.Write(mac, binary.BigEndian, uint32(len(field)))
		mac.Write([]byte(field))
	}
	_ = binary.Write(mac, binary.BigEndian, binding.PageSize)
	mac.Write(state.Epoch[:])
	_ = binary.Write(mac, binary.BigEndian, state.Revision)
	return mac.Sum(nil)
}

// write64 appends a big-endian integer to the cursor payload. The current
// caller uses an in-memory buffer, so a write error indicates a programming
// failure rather than an invalid cursor.
func write64(w io.Writer, n uint64) {
	if err := binary.Write(w, binary.BigEndian, n); err != nil {
		panic(fmt.Sprintf("in-memory cursor encoding failed: %v", err))
	}
}
