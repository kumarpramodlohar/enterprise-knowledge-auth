# Enterprise Knowledge Assistant - Auth Service

This repository is intended to contain the Go authentication and authorization policy service for the Enterprise Knowledge Assistant (EKA). The service is planned to own application user provisioning, roles, collection grants, and authorization policy decisions. Keycloak remains the identity provider.

## Current implementation status

**Experimental local testing only:** Request validation, policy and pagination orchestration, signed cursors, an internal HTTP handler, mTLS configuration, an experimental PostgreSQL store and a loopback-only test server exist. A synthetic PostgreSQL and mTLS integration test exercises the server wiring. There is no deployable schema or migration, production configuration, or Java integration yet. This executable is not a production authority and must not be deployed as a service.

The existing Java backend continues to authenticate requests and enforce access using its current implementation. It must remain authoritative until the replacement is implemented, verified, and approved for cutover.

## Planned responsibilities

- Provision authenticated OIDC users as `MEMBER` with no collection grants by default.
- Own application roles and collection grants, retaining `ADMIN`, `MEMBER`, `READ`, and `MANAGE` semantics.
- Provide versioned internal HTTPS/JSON interfaces for permission checks and bounded, paged collection scopes.
- Accept user-subject assertions only from explicitly authorized, mutually authenticated backend clients after the backend authenticates the user.
- Store auth-owned data in a separate schema in the existing PostgreSQL deployment, with least-privilege access and a cross-schema reference to backend-owned collections.

These are target responsibilities, not a running implementation. The initial request limits require compatibility verification against existing data. Database privileges, migration procedures, and certificate operations remain unfinished.

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

The PostgreSQL store and local-server integration tests require **two separate, new, empty, disposable databases** whose names begin `eka_auth_test_`. They create tables and functions without cleaning them up; never use a project or production database. The server test additionally requires a numeric loopback PostgreSQL address. For example, after creating the databases on a disposable local PostgreSQL instance:

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

The experimental PostgreSQL store reads a repeatable-read scope snapshot and delegates first-time OIDC creation to `eka_auth.resolve_oidc`. The actual guarded function, schema, revision triggers, freeze controls and production privileges are **not implemented**; the integration test's simplified fixture is not suitable for deployment. The store cannot establish that production guard or revision triggers are present and effective. Certificate and key operations, legacy-data compatibility and deployment controls remain unverified.

## Specifications and project records

When the repositories are checked out as siblings, consult the canonical specification repository:

- [Auth extraction specification](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/spec.md)
- [Implementation plan](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/plan.md)
- [Implementation tasks and remaining decisions](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/tasks.md)
- [Product and architecture decisions, including DEC-013](../enterprise-knowledge-assistant-spec/docs/implementation/product-decisions.md)
- [Implementation backlog](../enterprise-knowledge-assistant-spec/docs/implementation/Implementation_Backlog_v2.md)

The sibling links require the specification repository to be available in the same workspace. Detailed contracts, security procedures, migration and rollback mechanics, and live Keycloak verification remain outstanding before cutover.
