package authserver

import (
	"testing"
)

func validConfig() Config {
	return Config{
		Address: "127.0.0.1:8443", DatabaseURL: "postgres://127.0.0.1:5432/eka_auth?sslmode=disable",
		ServerCertificate: "server.pem", ServerKey: "server.key", ClientCA: "client-ca.pem",
		SigningKeyID: "current", SigningKeyFile: "sign.key", BindingKeyFile: "bind.key",
		CallerURIs: []string{"spiffe://eka/backend"}, Issuers: []string{"https://issuer.example/realms/eka"},
		MaxPageSize: defaultMaxPage, ScopeLimit: defaultScopes,
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"valid", func(*Config) {}},
		{"missing TLS", func(c *Config) { c.ClientCA = "" }},
		{"missing URI caller", func(c *Config) { c.CallerURIs = []string{"spiffe:///backend"} }},
		{"caller query", func(c *Config) { c.CallerURIs = []string{"spiffe://eka/backend?role=admin"} }},
		{"duplicate caller", func(c *Config) { c.CallerURIs = []string{"spiffe://eka/backend", "spiffe://eka/backend"} }},
		{"issuer query", func(c *Config) { c.Issuers = []string{"https://issuer.example?x=1"} }},
		{"issuer without scheme", func(c *Config) { c.Issuers = []string{"//issuer.example/realm"} }},
		{"local identity enabled", func(c *Config) { c.LocalNamespace = "dev" }},
		{"invalid page size", func(c *Config) { c.MaxPageSize = 99 }},
		{"invalid scope", func(c *Config) { c.ScopeLimit = 0 }},
		{"partial previous cursor keys", func(c *Config) { c.PreviousSigningKeyID = "previous" }},
		{"duplicate key ID", func(c *Config) {
			c.PreviousSigningKeyID = "current"
			c.PreviousSigningKeyFile = "previous-sign.key"
			c.PreviousBindingKeyFile = "previous-bind.key"
		}},
		{"invalid bind address", func(c *Config) { c.Address = "localhost" }},
		{"zero port", func(c *Config) { c.Address = "127.0.0.1:0" }},
		{"invalid database URL", func(c *Config) { c.DatabaseURL = "postgres://" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.edit(&cfg)
			_, err := cfg.Validate()
			if (tt.name == "valid") != (err == nil) {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
}

func TestFromEnv(t *testing.T) {
	for key, value := range map[string]string{
		"EKA_AUTH_LISTEN": "127.0.0.1:8443", "EKA_AUTH_DATABASE_URL": "postgres://127.0.0.1:5432/eka_auth?sslmode=disable",
		"EKA_AUTH_SERVER_CERT": "server.pem", "EKA_AUTH_SERVER_KEY": "server.key", "EKA_AUTH_CLIENT_CA": "ca.pem",
		"EKA_AUTH_CURSOR_ACTIVE_KEY_ID": "current", "EKA_AUTH_CURSOR_SIGNING_KEY": "sign.key",
		"EKA_AUTH_CURSOR_BINDING_KEY": "bind.key", "EKA_AUTH_ALLOWED_CALLER_URIS": "spiffe://eka/backend",
		"EKA_AUTH_ALLOWED_OIDC_ISSUERS":   "https://issuer.example/realms/eka",
		"EKA_AUTH_CURSOR_PREVIOUS_KEY_ID": "", "EKA_AUTH_CURSOR_PREVIOUS_SIGNING_KEY": "",
		"EKA_AUTH_CURSOR_PREVIOUS_BINDING_KEY": "", "EKA_AUTH_LOCAL_NAMESPACE": "",
		"EKA_AUTH_SCOPE_LIMIT": "", "EKA_AUTH_MAX_PAGE_SIZE": "",
	} {
		t.Setenv(key, value)
	}
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EKA_AUTH_MAX_PAGE_SIZE", "bad")
	if _, err := FromEnv(); err == nil {
		t.Fatal("invalid numeric environment value accepted")
	}
}
