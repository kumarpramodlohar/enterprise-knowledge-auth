package compatibility

import (
	"strings"
	"testing"

	"github.com/kumarpramodlohar/enterprise-knowledge-auth/internal/contract"
)

func TestCompatible(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		trust   contract.Trust
		subject string
		want    bool
	}{
		{"oidc", Config{Kind: "OIDC", Issuer: "issuer"}, contract.Trust{AllowedIssuers: map[string]struct{}{"issuer": {}}}, "user", true},
		{"local", Config{Kind: "LOCAL", Namespace: "dev"}, contract.Trust{LocalEnabled: true, LocalNamespace: "dev"}, "user", true},
		{"byte boundary", Config{Kind: "OIDC", Issuer: "issuer"}, contract.Trust{AllowedIssuers: map[string]struct{}{"issuer": {}}}, strings.Repeat("é", 512), true},
		{"over byte boundary", Config{Kind: "OIDC", Issuer: "issuer"}, contract.Trust{AllowedIssuers: map[string]struct{}{"issuer": {}}}, strings.Repeat("é", 513), false},
		{"empty", Config{Kind: "LOCAL", Namespace: "dev"}, contract.Trust{LocalEnabled: true, LocalNamespace: "dev"}, "", false},
		{"untrusted issuer", Config{Kind: "OIDC", Issuer: "other"}, contract.Trust{AllowedIssuers: map[string]struct{}{"issuer": {}}}, "user", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compatible(tt.subject, tt.config, tt.trust); got != tt.want {
				t.Fatalf("compatible = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	if !strings.HasPrefix((Result{}).Summary(), "inconclusive:") ||
		!strings.HasPrefix((Result{Total: 2, Incompatible: 1}).Summary(), "incompatible:") ||
		!strings.HasPrefix((Result{Total: 2}).Summary(), "field and request limits compatible") {
		t.Fatal("incorrect compatibility summaries")
	}
}
