# Enterprise Knowledge Assistant - Auth Service

This repository is intended to contain the Go authentication and authorization policy service for the Enterprise Knowledge Assistant (EKA). The service is planned to own application user provisioning, roles, collection grants, and authorization policy decisions. Keycloak remains the identity provider.

## Current implementation status

**Implementation started; not a runnable service:** This repository contains a Go module and tested internal components for strict request decoding, policy evaluation, and signed pagination cursors. There is no server, PostgreSQL store, migration, or Java integration yet. These components do not provide authorization to any application and must not be deployed as a service.

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

The module is `github.com/kumarpramodlohar/enterprise-knowledge-auth` and currently uses only the Go standard library. The module requires Go 1.27.3; deployment compatibility and support must be checked before release. With that toolchain available, validate the current components using:

```sh
go test -race -cover ./...
go vet ./...
go build ./...
```

`go build ./...` builds packages only; it does not produce a server executable. No configuration, database setup, service run command, or CI pipeline exists yet. The cursor codec is not connected to a database snapshot or revision comparison, and its key lifecycle is not operationally implemented. The policy evaluator must only be supplied with freshly and successfully loaded state; it is not an enforcement point.

## Specifications and project records

When the repositories are checked out as siblings, consult the canonical specification repository:

- [Auth extraction specification](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/spec.md)
- [Implementation plan](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/plan.md)
- [Implementation tasks and remaining decisions](../enterprise-knowledge-assistant-spec/specs/013-auth-service-extraction/tasks.md)
- [Product and architecture decisions, including DEC-013](../enterprise-knowledge-assistant-spec/docs/implementation/product-decisions.md)
- [Implementation backlog](../enterprise-knowledge-assistant-spec/docs/implementation/Implementation_Backlog_v2.md)

The sibling links require the specification repository to be available in the same workspace. Detailed contracts, security procedures, migration and rollback mechanics, and live Keycloak verification remain outstanding before cutover.
