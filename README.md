# Enterprise Knowledge Assistant - Auth Service

This repository is intended to contain the Go authentication and authorization policy service for the Enterprise Knowledge Assistant (EKA). The service is planned to own application user provisioning, roles, collection grants, and authorization policy decisions. Keycloak remains the identity provider.

## Current implementation status

**Not production-ready:** Request validation, policy and pagination orchestration, signed cursors, an internal HTTP handler, mTLS transport, an experimental PostgreSQL store, a loopback-only test server, and a deployment-configurable mTLS daemon exist. Synthetic PostgreSQL and mTLS integration tests exercise both server compositions and fail-closed schema verification. There is no deployment migration or verified production schema, actual legacy-data mapping, environment-specific restore evidence, Java integration, or cutover approval. Do not deploy this service as an authority.

The existing Java backend continues to authenticate requests and enforce access using its current implementation. It must remain authoritative until the replacement is implemented, verified, and approved for cutover.

## Planned responsibilities

- Provision authenticated OIDC users as `MEMBER` with no collection grants by default.
- Own application roles and collection grants, retaining `ADMIN`, `MEMBER`, `READ`, and `MANAGE` semantics.
- Provide versioned internal HTTPS/JSON interfaces for permission checks and bounded, paged collection scopes.
- Accept user-subject assertions only from explicitly authorized, mutually authenticated backend clients after the backend authenticates the user.
- Store auth-owned data in a separate schema in the existing PostgreSQL deployment, with least-privilege access and a cross-schema reference to backend-owned collections.

The Go repository implements prototypes of these responsibilities, but has not assumed production authority. Request limits still require compatibility verification against actual data. Database privileges, migration procedures, certificate operations, and cross-service integration remain unfinished.

## Service boundaries

| Component | Responsibility |
|---|---|
| Keycloak | OIDC identity provider; retained in the target design. |
| Frontend | Browser sign-in and session experience; direct Keycloak PKCE sign-in is retained initially. |
| Java knowledge backend | Validates caller identity and enforces authorization before protected document operations, retrieval, citations, and AI-provider context. The existing `/api/v1/me` contract and local Basic sign-in remain initially. |
| Go auth service | Planned owner of user provisioning, application roles, grants, and authorization decisions. |

The frontend's displayed permissions are only an affordance, not an authorization control. An auth-service outage or invalid response must not grant access or be presented as an ordinary insufficient-evidence result.

## Security and migration direction

- Use mTLS for backend-to-auth communication, with deployment-managed certificates and a separate local-development CA. Keep private keys and credentials out of Git.
- Request fresh authorization for protected operations without an authorization-decision cache; recheck before sending protected context to an AI provider and before returning protected citations or content. These point-in-time checks do not eliminate every in-flight revocation race.
- Fail closed with a safe service error if authorization cannot be obtained. Inaccessible and nonexistent resources must remain indistinguishable as 404.
- Migrate with a single policy authority at each stage, a policy-write freeze, reconciliation, and a rehearsed rollback. Reconcile post-cutover changes before restoring the old authority.
- Do not remove existing backend protections until the replacement has been tested and separately approved for cutover.

New administration UI/API and expanded audit-event features are deferred; existing required audit behavior must be retained.

## Technology and setup

The module is `github.com/kumarpramodlohar/enterprise-knowledge-auth` and uses the pinned `pgx` PostgreSQL driver. The module requires Go 1.27.3; deployment compatibility and support must be checked before release. With that toolchain available, validate the current components using:

```sh
go test -race -cover ./...
go vet ./...
go build ./...
```

`go build ./...` checks that all packages compile; `go build ./cmd/auth-local` builds the experimental local executable. The GitHub Actions workflow configures a disposable PostgreSQL service and requires both synthetic integration tests alongside formatting, race-enabled tests, vet and package builds. The updated workflow has not yet been run on GitHub and does not include vulnerability checks.

The PostgreSQL store and local-server integration tests require **two separate, new, empty, disposable databases** whose names begin `eka_auth_test_`. They create tables and functions without cleaning them up; never use a project or production database. The store test also creates and removes a synthetic login role and therefore requires a disposable PostgreSQL instance and a test administrator able to create roles. The server test additionally requires a numeric loopback PostgreSQL address. For example, after creating the databases on a disposable local PostgreSQL instance:

```sh
export EKA_SYNTHETIC_POSTGRES_DSN='postgres://TEST_USER:TEST_PASSWORD@127.0.0.1:TEST_PORT/eka_auth_test_store?sslmode=disable'
export EKA_LOCALAPP_TEST_DSN='postgres://TEST_USER:TEST_PASSWORD@127.0.0.1:TEST_PORT/eka_auth_test_server?sslmode=disable'
EKA_REQUIRE_POSTGRES_TEST=1 go test -race -count=1 ./...
```

Replace the placeholders with credentials and port for the disposable instance. Without the respective DSN, each database integration test skips unless `EKA_REQUIRE_POSTGRES_TEST=1`, in which case it fails. Use new databases for each run.

### Experimental local executable

`go run ./cmd/auth-local` requires an already prepared **synthetic test schema**, not a project database. The fixture in the integration test is incomplete and is not a production migration or a supported development database setup. The automated test creates its own fixture, starts the server and shuts it down; a reusable standalone database setup is not yet provided.

The executable reads `EKA_LOCAL_LISTEN` (numeric loopback IP and port), `EKA_LOCAL_DATABASE_URL` (numeric loopback host and `eka_auth_test_*` database), `EKA_LOCAL_SERVER_CERT`, `EKA_LOCAL_SERVER_KEY`, `EKA_LOCAL_CLIENT_CA`, `EKA_LOCAL_SIGNING_KEY`, `EKA_LOCAL_BINDING_KEY`, `EKA_LOCAL_CALLER_URI`, and at least one of `EKA_LOCAL_OIDC_ISSUER` or `EKA_LOCAL_NAMESPACE`. The key settings are file paths to separate test-only cursor keys of 32–4096 bytes. Certificates and keys must be generated separately and kept outside Git. These checks do not prove a database is disposable or that required production controls are installed.

The HTTP handler requires TLS-verified client certificates and an allowlisted URI SAN; it must only be hosted behind an end-to-end TLS server configured to require and verify client certificates. The local listener uses the transport configuration to require verified client certificates. The handler rejects certificates with multiple URI SANs to avoid ambiguous caller binding. Integration tests do not establish production readiness. Routine certificate reload, revocation and connection termination remain unimplemented.

The experimental PostgreSQL store reads a repeatable-read scope snapshot and delegates first-time OIDC creation to `eka_auth.resolve_oidc`. Both server compositions call `Store.VerifySchema` before opening a listener and fail closed if expected guard/revision triggers, control state, function ownership or runtime grants are unsafe. This check is defense in depth, not proof that privileged owners or superusers cannot bypass controls.

### Deployment-configurable daemon (not production-ready)

`go run ./cmd/authd` starts the mTLS daemon only after validating its configuration, loading TLS and cursor keys, connecting with the configured database role, and verifying the expected schema controls. It does not install a schema, create roles, provide a health endpoint, or make an unverified database safe. Local identities are rejected; only explicitly configured OIDC issuers and mTLS caller URI SANs are accepted.

Required environment variables are `EKA_AUTH_LISTEN` (`host:port`), `EKA_AUTH_DATABASE_URL`, `EKA_AUTH_SERVER_CERT`, `EKA_AUTH_SERVER_KEY`, `EKA_AUTH_CLIENT_CA`, `EKA_AUTH_CURSOR_ACTIVE_KEY_ID`, `EKA_AUTH_CURSOR_SIGNING_KEY`, `EKA_AUTH_CURSOR_BINDING_KEY`, `EKA_AUTH_ALLOWED_CALLER_URIS` (comma-separated exact `spiffe://` URIs), and `EKA_AUTH_ALLOWED_OIDC_ISSUERS` (comma-separated exact issuer URLs). Optional cursor rotation variables are `EKA_AUTH_CURSOR_PREVIOUS_KEY_ID`, `EKA_AUTH_CURSOR_PREVIOUS_SIGNING_KEY`, and `EKA_AUTH_CURSOR_PREVIOUS_BINDING_KEY`; set all three or none. `EKA_AUTH_MAX_PAGE_SIZE` and `EKA_AUTH_SCOPE_LIMIT` default to 500 and 10,000 and are bounded by configuration validation. Do not set `EKA_AUTH_LOCAL_NAMESPACE`; local identity mode is unavailable in this daemon.

Certificate and cursor-key values are file paths; cursor keys must each contain 32–4096 bytes. Keep private keys and database credentials outside Git, limit file access to the service identity, and manage certificate/key rotation operationally. The daemon requires a verified client certificate and an allowlisted URI SAN, but routine certificate reload, revocation and connection termination are not implemented. Passing startup checks or synthetic tests is not deployment approval.

The store integration test uses a [guarded schema candidate](internal/postgres/testdata/guarded_schema.sql) in a disposable database. It exercises atomic provisioning, revision updates, freeze/drain with queued writes, legacy-table write blocking, overflow, cascading deletion and separately authenticated test roles. Its [test ownership setup](internal/postgres/testdata/guarded_ownership.sql) creates a non-login, non-superuser owner and a separate schema-installer login; an administrator temporarily grants database creation, cross-schema references and trigger rights so the installer can install the fixture while assuming the owner. The test removes these temporary privileges and membership, checks function ownership and default public execution, and verifies runtime cannot assume the owner. This is not a deployable role setup: actual platform ownership, inherited privileges and administrator operations remain unverified. The candidate uses synthetic legacy and collection tables; it does not implement manifest-controlled migration or allocate deployment locks. The legacy Java filter's no-op insert is blocked by its statement guard even for an existing user; backend work is required before such a guard could be enabled. Neither fixture is a deployable migration; the store cannot establish that production guards or revision triggers are present and effective. Certificate and key operations, actual legacy-data compatibility, restore procedures and deployment controls remain unverified.

### Legacy compatibility check

`go run ./cmd/auth-compat` scans `public.app_users.subject` under a read-only repeatable-read transaction and tests the actual Go request validators. Configure `EKA_COMPAT_DATABASE_URL` with a read-only identity authorized to read every legacy subject, set `EKA_COMPAT_IDENTITY_KIND` to `OIDC` or `LOCAL`, and set only the matching `EKA_COMPAT_ISSUER` or `EKA_COMPAT_LOCAL_NAMESPACE`. Protect the connection credentials and resulting aggregate counts. The command prints only aggregate results, exits nonzero for invalid configuration, a failed or filtered scan, an empty table or incompatible values, and does not change policy data. It requires a UTF-8 database and a base table; active row-level filtering is rejected.

The check applies **one candidate interpretation to every stored subject**. It does not infer which users are local or OIDC, establish issuer provenance, validate identity-provider evidence, detect mapping collisions or perform migration reconciliation. A pass establishes only that the scanned values and supplied configuration fit current request shapes and limits, not that the configuration is the approved deployment configuration. Run it only with authorization and with complete table visibility; mixed identities need independently verified mappings. No existing environment has been checked by this repository's synthetic tests.

### Restore safety direction

The test fixture's `test_restore_epoch` only demonstrates rejecting an unfrozen restore and changing the epoch before invalidating an old cursor, including when counters are equal. It is not a production restore procedure. A real procedure must fence all application traffic and writers independently of restored data, restore and validate the approved schema and controls, establish a verified freeze, select a fresh epoch not previously issued using an independently protected source, rotate it under restricted authority, verify old cursors fail and policy state is reconciled, then resume traffic only under the approved recovery process. A restored freeze flag, an in-database random value alone, or the test helper cannot prove those conditions. Platform-specific ownership, credentials, backup/restore and rehearsals remain to be designed and verified.

## Specifications and project records

When the repositories are checked out as siblings, consult the canonical specification repository:

- [Auth extraction specification](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/spec.md)
- [Implementation plan](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/plan.md)
- [Implementation tasks and remaining decisions](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/tasks.md)
- [Product and architecture decisions, including DEC-013](../enterprise-knowledge-assistant-spec/docs/implementation/product-decisions.md)
- [Implementation backlog](../enterprise-knowledge-assistant-spec/docs/implementation/Implementation_Backlog_v2.md)

The sibling links require the specification repository to be available in the same workspace. Detailed contracts, security procedures, migration and rollback mechanics, and live Keycloak verification remain outstanding before cutover.
