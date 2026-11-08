// Package authserver configures the deployable mTLS HTTP process. Database
// schema installation and role provisioning remain separate operator tasks.
package authserver

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxPage = 500
	defaultScopes  = 10000
)

// Config contains runtime paths and trust policy. It never contains private
// key material or logs database connection values.
type Config struct {
	Address, DatabaseURL, ServerCertificate, ServerKey, ClientCA               string
	SigningKeyID, SigningKeyFile, PreviousSigningKeyID, PreviousSigningKeyFile string
	BindingKeyFile, PreviousBindingKeyFile                                     string
	CallerURIs, Issuers                                                        []string
	LocalNamespace                                                             string
	MaxPageSize, ScopeLimit                                                    int
}

// FromEnv reads deployment configuration without logging supplied values.
func FromEnv() (Config, error) {
	cfg := Config{
		Address: os.Getenv("EKA_AUTH_LISTEN"), DatabaseURL: os.Getenv("EKA_AUTH_DATABASE_URL"),
		ServerCertificate: os.Getenv("EKA_AUTH_SERVER_CERT"), ServerKey: os.Getenv("EKA_AUTH_SERVER_KEY"),
		ClientCA: os.Getenv("EKA_AUTH_CLIENT_CA"), SigningKeyID: os.Getenv("EKA_AUTH_CURSOR_ACTIVE_KEY_ID"),
		SigningKeyFile:         os.Getenv("EKA_AUTH_CURSOR_SIGNING_KEY"),
		PreviousSigningKeyID:   os.Getenv("EKA_AUTH_CURSOR_PREVIOUS_KEY_ID"),
		PreviousSigningKeyFile: os.Getenv("EKA_AUTH_CURSOR_PREVIOUS_SIGNING_KEY"),
		BindingKeyFile:         os.Getenv("EKA_AUTH_CURSOR_BINDING_KEY"),
		PreviousBindingKeyFile: os.Getenv("EKA_AUTH_CURSOR_PREVIOUS_BINDING_KEY"),
		CallerURIs:             splitExactList(os.Getenv("EKA_AUTH_ALLOWED_CALLER_URIS")),
		Issuers:                splitExactList(os.Getenv("EKA_AUTH_ALLOWED_OIDC_ISSUERS")),
		LocalNamespace:         os.Getenv("EKA_AUTH_LOCAL_NAMESPACE"),
		MaxPageSize:            defaultMaxPage, ScopeLimit: defaultScopes,
	}
	var err error
	if value := os.Getenv("EKA_AUTH_MAX_PAGE_SIZE"); value != "" {
		cfg.MaxPageSize, err = strconv.Atoi(value)
		if err != nil {
			return Config{}, errors.New("invalid EKA_AUTH_MAX_PAGE_SIZE")
		}
	}
	if value := os.Getenv("EKA_AUTH_SCOPE_LIMIT"); value != "" {
		cfg.ScopeLimit, err = strconv.Atoi(value)
		if err != nil {
			return Config{}, errors.New("invalid EKA_AUTH_SCOPE_LIMIT")
		}
	}
	return cfg, nil
}

// Validate checks required configuration and returns a parsed, unlogged
// PostgreSQL pool configuration.
func (c Config) Validate() (*pgxpool.Config, error) {
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil || host == "" {
		return nil, errors.New("EKA_AUTH_LISTEN must be a host and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("EKA_AUTH_LISTEN must use a valid nonzero port")
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("EKA_AUTH_DATABASE_URL is required")
	}
	db, err := pgxpool.ParseConfig(c.DatabaseURL)
	if err != nil || db.ConnConfig.Host == "" || db.ConnConfig.Database == "" {
		return nil, errors.New("invalid EKA_AUTH_DATABASE_URL")
	}
	if c.ServerCertificate == "" || c.ServerKey == "" || c.ClientCA == "" ||
		c.SigningKeyID == "" || c.SigningKeyFile == "" || c.BindingKeyFile == "" ||
		len(c.CallerURIs) == 0 || len(c.Issuers) == 0 {
		return nil, errors.New("server TLS, cursor keys, caller and OIDC issuer configuration are required")
	}
	if c.MaxPageSize < 100 || c.MaxPageSize > 10000 || c.ScopeLimit < 1 || c.ScopeLimit > 1000000 {
		return nil, errors.New("invalid page or scope limit")
	}
	if (c.PreviousSigningKeyID == "") != (c.PreviousSigningKeyFile == "") ||
		(c.PreviousSigningKeyID == "") != (c.PreviousBindingKeyFile == "") ||
		c.PreviousSigningKeyID == c.SigningKeyID {
		return nil, errors.New("previous cursor signing and binding keys require a distinct key ID and complete key pair")
	}
	if c.LocalNamespace != "" {
		return nil, errors.New("local identities are disabled in authd")
	}
	if len(c.CallerURIs) > 64 || len(c.Issuers) > 32 {
		return nil, errors.New("caller or issuer allowlist exceeds configured bounds")
	}
	for _, caller := range c.CallerURIs {
		parsed, err := url.ParseRequestURI(caller)
		if err != nil || strings.TrimSpace(caller) != caller || !strings.HasPrefix(caller, "spiffe://") ||
			parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(caller) > 2048 {
			return nil, errors.New("invalid backend caller URI")
		}
	}
	if !unique(c.CallerURIs) || !unique(c.Issuers) {
		return nil, errors.New("caller and issuer allowlists must not contain duplicates")
	}
	for _, issuer := range c.Issuers {
		parsed, err := url.ParseRequestURI(issuer)
		if err != nil || issuer == "" || strings.TrimSpace(issuer) != issuer || parsed.Scheme == "" ||
			parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(issuer) > 1024 {
			return nil, errors.New("invalid OIDC issuer")
		}
	}
	return db, nil
}

func unique(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func splitExactList(value string) []string {
	if value == "" {
		return nil
	}
	values := strings.Split(value, ",")
	seen := make(map[string]struct{}, len(values))
	for _, item := range values {
		if item == "" {
			return nil
		}
		if _, exists := seen[item]; exists {
			return nil
		}
		seen[item] = struct{}{}
	}
	return values
}

const (
	cursorLifetime = time.Minute
	clockSkew      = 5 * time.Second
)
