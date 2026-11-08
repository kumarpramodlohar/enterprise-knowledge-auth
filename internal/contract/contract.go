// Package contract validates the internal authorization API's untrusted input.
// Its decoders check JSON structure first, then validate each request and its
// identity against configured trust rules before policy operations are called.
package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

const (
	MaxBodySize     = 16 * 1024
	MaxFieldSize    = 1024
	MaxCursorSize   = 4096
	DefaultPageSize = 100
)

var ErrInvalidRequest = errors.New("invalid request")
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Identity struct {
	Kind      string `json:"kind"`
	Issuer    string `json:"issuer,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Username  string `json:"username,omitempty"`
}

// UnmarshalJSON reads the exact fields required for an OIDC or local identity.
// Rejecting missing, null, and kind-incompatible fields prevents ambiguous
// identities; issuer and namespace trust are checked separately.
func (id *Identity) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return ErrInvalidRequest
	}
	var kind string
	if json.Unmarshal(fields["kind"], &kind) != nil {
		return ErrInvalidRequest
	}
	required := []string{"kind"}
	switch kind {
	case "OIDC":
		required = append(required, "issuer", "subject")
	case "LOCAL":
		required = append(required, "namespace", "username")
	default:
		return ErrInvalidRequest
	}
	if len(fields) != len(required) {
		return ErrInvalidRequest
	}
	for _, field := range required {
		raw, exists := fields[field]
		if !exists || bytes.Equal(raw, []byte("null")) {
			return ErrInvalidRequest
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return ErrInvalidRequest
		}
	}
	type identityWire Identity
	var result identityWire
	if err := json.Unmarshal(data, &result); err != nil {
		return ErrInvalidRequest
	}
	*id = Identity(result)
	return nil
}

type Trust struct {
	AllowedIssuers map[string]struct{}
	LocalNamespace string
	LocalEnabled   bool
}

type ResolveRequest struct {
	Identity Identity `json:"identity"`
}

type CheckRequest struct {
	Identity     Identity `json:"identity"`
	CollectionID string   `json:"collectionId"`
	Permission   string   `json:"permission"`
}

type PageRequest struct {
	Identity Identity `json:"identity"`
	PageSize int      `json:"pageSize"`
	Cursor   string   `json:"cursor,omitempty"`
}

// DecodeResolve parses a resolution request and validates its asserted identity.
// It applies the shared strict JSON rules before checking configured trust, so
// malformed or untrusted identities never reach resolution.
func DecodeResolve(body []byte, trust Trust) (ResolveRequest, error) {
	var request ResolveRequest
	if err := decode(body, &request); err != nil {
		return ResolveRequest{}, err
	}
	if err := validateIdentity(request.Identity, trust); err != nil {
		return ResolveRequest{}, err
	}
	return request, nil
}

// DecodeCheck parses a permission request, then validates its identity,
// collection UUID, and permission. This keeps invalid policy inputs from being
// interpreted as authorization decisions.
func DecodeCheck(body []byte, trust Trust) (CheckRequest, error) {
	var request CheckRequest
	if err := decode(body, &request); err != nil {
		return CheckRequest{}, err
	}
	if err := validateIdentity(request.Identity, trust); err != nil {
		return CheckRequest{}, err
	}
	if !uuidPattern.MatchString(request.CollectionID) || (request.Permission != "READ" && request.Permission != "MANAGE") {
		return CheckRequest{}, ErrInvalidRequest
	}
	return request, nil
}

// DecodePage parses a scope request, validates its identity and bounds, and
// applies the default page size when omitted. It rejects null or empty cursors
// and invalid sizes so pagination cannot silently change the request.
func DecodePage(body []byte, trust Trust, maximum int) (PageRequest, error) {
	var wire struct {
		Identity Identity        `json:"identity"`
		PageSize json.RawMessage `json:"pageSize"`
		Cursor   json.RawMessage `json:"cursor"`
	}
	if err := decode(body, &wire); err != nil {
		return PageRequest{}, err
	}
	if err := validateIdentity(wire.Identity, trust); err != nil {
		return PageRequest{}, err
	}
	if maximum < 1 {
		return PageRequest{}, fmt.Errorf("invalid configured page maximum")
	}
	size := DefaultPageSize
	if len(wire.PageSize) != 0 {
		if bytes.Equal(wire.PageSize, []byte("null")) || json.Unmarshal(wire.PageSize, &size) != nil {
			return PageRequest{}, ErrInvalidRequest
		}
	}
	if size < 1 || size > maximum {
		return PageRequest{}, ErrInvalidRequest
	}
	var cursor string
	if len(wire.Cursor) != 0 {
		if bytes.Equal(wire.Cursor, []byte("null")) || json.Unmarshal(wire.Cursor, &cursor) != nil || len(cursor) == 0 || len(cursor) > MaxCursorSize {
			return PageRequest{}, ErrInvalidRequest
		}
	}
	return PageRequest{Identity: wire.Identity, PageSize: size, Cursor: cursor}, nil
}

// validateIdentity checks field sizes and exact issuer or local namespace
// membership. It prevents unconfigured identity sources from reaching policy
// evaluation without normalizing identity values.
func validateIdentity(id Identity, trust Trust) error {
	valid := func(s string) bool { return len(s) > 0 && len(s) <= MaxFieldSize && utf8.ValidString(s) }
	switch id.Kind {
	case "OIDC":
		_, allowed := trust.AllowedIssuers[id.Issuer]
		if !allowed || !valid(id.Issuer) || !valid(id.Subject) || id.Namespace != "" || id.Username != "" {
			return ErrInvalidRequest
		}
	case "LOCAL":
		if !trust.LocalEnabled || !valid(id.Namespace) || !valid(id.Username) || id.Namespace != trust.LocalNamespace || id.Issuer != "" || id.Subject != "" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

// decode enforces body size, UTF-8, one JSON object, duplicate detection, and
// exact top-level field names before decoding into target. These checks avoid
// accepting ambiguous or silently ignored authorization inputs.
func decode(body []byte, target any) error {
	if len(body) == 0 || len(body) > MaxBodySize || !utf8.Valid(body) || !validUnicodeEscapes(body) {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := scanValue(decoder, 0); err != nil {
		return ErrInvalidRequest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidRequest
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return ErrInvalidRequest
	}
	allowed := map[string]bool{"identity": true}
	switch target.(type) {
	case *CheckRequest:
		allowed["collectionId"], allowed["permission"] = true, true
	case *struct {
		Identity Identity        `json:"identity"`
		PageSize json.RawMessage `json:"pageSize"`
		Cursor   json.RawMessage `json:"cursor"`
	}:
		allowed["pageSize"], allowed["cursor"] = true, true
	}
	for field := range fields {
		if !allowed[field] {
			return ErrInvalidRequest
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

// validUnicodeEscapes checks escaped surrogate pairs before JSON decoding.
// encoding/json replaces unpaired surrogates, which would alter exact identities.
func validUnicodeEscapes(body []byte) bool {
	inString := false
	for i := 0; i < len(body); i++ {
		if !inString {
			if body[i] == '"' {
				inString = true
			}
			continue
		}
		if body[i] == '"' {
			inString = false
			continue
		}
		if body[i] != '\\' {
			continue
		}
		i++
		if i >= len(body) {
			return false
		}
		if body[i] != 'u' {
			continue
		}
		if i+4 >= len(body) {
			return false
		}
		n, err := strconv.ParseUint(string(body[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(body[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// scanValue walks JSON tokens, limits nesting, and rejects duplicate object
// members. The normal JSON decoder alone would accept duplicates, making
// security-sensitive request values ambiguous.
func scanValue(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return ErrInvalidRequest
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		if depth == 0 {
			return ErrInvalidRequest
		}
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return ErrInvalidRequest
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrInvalidRequest
			}
			seen[name] = struct{}{}
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		if depth == 0 {
			return ErrInvalidRequest
		}
		for decoder.More() {
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return ErrInvalidRequest
	}
}
