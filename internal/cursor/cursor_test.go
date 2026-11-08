package cursor

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestCursorBindingAndRotation(t *testing.T) {
	key := KeyPair{Signing: bytes.Repeat([]byte{1}, 32), Binding: bytes.Repeat([]byte{2}, 32)}
	next := KeyPair{Signing: bytes.Repeat([]byte{3}, 32), Binding: bytes.Repeat([]byte{4}, 32)}
	codec, err := New("one", map[string]KeyPair{"one": key}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	binding := Binding{Caller: "spiffe://backend", Kind: "OIDC", Issuer: "issuer", Subject: "private-subject", PageSize: 100}
	state := State{Epoch: [16]byte{1}, Revision: 7, LastID: [16]byte{2}}
	token, err := codec.Sign(state, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatal("cursor must have two encoded segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(binding.Subject)) || bytes.Contains(payload, []byte(binding.Issuer)) {
		t.Fatal("identity appears in cursor")
	}
	got, err := codec.Verify(token, binding, now)
	if err != nil || got != state {
		t.Fatalf("got %+v, %v", got, err)
	}
	mutations := []Binding{
		{Caller: "other", Kind: binding.Kind, Issuer: binding.Issuer, Subject: binding.Subject, PageSize: 100},
		{Caller: binding.Caller, Kind: binding.Kind, Issuer: binding.Issuer, Subject: "other", PageSize: 100},
		{Caller: binding.Caller, Kind: binding.Kind, Issuer: binding.Issuer, Subject: binding.Subject, PageSize: 101},
	}
	for _, changed := range mutations {
		if _, err := codec.Verify(token, changed, now); err == nil {
			t.Fatal("accepted incorrect binding")
		}
	}
	if _, err := codec.Verify(token+"a", binding, now); err == nil {
		t.Fatal("accepted modified token")
	}
	payload[len(payload)-1] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, err := codec.Verify(tampered, binding, now); err == nil {
		t.Fatal("accepted tampered payload")
	}
	if _, err := codec.Verify(token, binding, now.Add(65*time.Second)); err == nil {
		t.Fatal("accepted expired cursor")
	}
	if _, err := codec.Verify(token, binding, now.Add(-6*time.Second)); err == nil {
		t.Fatal("accepted cursor issued in the future")
	}
	rotated, err := New("two", map[string]KeyPair{"one": key, "two": next}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(token, binding, now); err != nil {
		t.Fatal("previous key must be accepted during rotation:", err)
	}
	removed, err := New("two", map[string]KeyPair{"two": next}, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := removed.Verify(token, binding, now); err == nil {
		t.Fatal("accepted removed key")
	}
	key.Signing[0] = 9
	if _, err := codec.Verify(token, binding, now); err != nil {
		t.Fatal("codec must own its key material:", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	same := bytes.Repeat([]byte{1}, 32)
	if _, err := New("one", map[string]KeyPair{"one": {Signing: same, Binding: same}}, time.Minute, 0); err == nil {
		t.Fatal("accepted identical signing and binding keys")
	}
	if _, err := New("missing", map[string]KeyPair{}, time.Minute, 0); err == nil {
		t.Fatal("accepted missing key")
	}
}
