package localapp

import (
	"context"
	"testing"
)

func validConfig() Config {
	return Config{Address: "127.0.0.1:0", DatabaseURL: "postgres://test:secret@127.0.0.1:5432/eka_auth_test_local?sslmode=disable",
		ServerCertificate: "server.pem", ServerKey: "server.key", ClientCA: "ca.pem",
		SigningKeyFile: "sign.key", BindingKeyFile: "bind.key", CallerURI: "spiffe://test/backend", Issuer: "issuer"}
}

func TestValidateIsolation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"external listener", func(c *Config) { c.Address = "0.0.0.0:1234" }},
		{"hostname listener", func(c *Config) { c.Address = "localhost:1234" }},
		{"remote database", func(c *Config) { c.DatabaseURL = "postgres://test:secret@192.0.2.1/eka_auth_test_local" }},
		{"normal database", func(c *Config) { c.DatabaseURL = "postgres://test:secret@127.0.0.1/production" }},
		{"remote fallback", func(c *Config) { c.DatabaseURL = "postgres://test:secret@127.0.0.1,192.0.2.1/eka_auth_test_local" }},
		{"no database", func(c *Config) { c.DatabaseURL = "" }},
		{"no trust", func(c *Config) { c.Issuer = ""; c.LocalNamespace = "" }},
		{"no caller", func(c *Config) { c.CallerURI = "" }},
	}
	if _, err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validConfig()
			tt.edit(&config)
			if _, err := config.Validate(); err == nil {
				t.Fatal("accepted invalid test configuration")
			}
		})
	}
}

func TestDatabaseFailureDoesNotExposeURL(t *testing.T) {
	c := validConfig()
	c.DatabaseURL = "postgres://test:private-password@invalid:bad/eka_auth_test_local"
	_, err := c.Validate()
	if err == nil || err.Error() != "invalid local database configuration" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNilRunDependencies(t *testing.T) {
	if err := Run(context.Background(), validConfig(), nil, nil); err == nil {
		t.Fatal("accepted missing runtime dependencies")
	}
}
