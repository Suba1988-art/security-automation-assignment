# Remediation plan

## Completed in this change

1. **SQL injection / cross-tenant search (high):** replaced string-interpolated SQL with bound parameters and restricted search to the authenticated user's `owner_id`.
2. **Broken object-level authorization (high):** the single-scan read endpoint now filters by both scan ID and owner ID.
3. **Credential exposure in logs (high):** removed password values from login logs.
4. **JWT algorithm allow-list (high):** removed `none` from the allowed algorithms.
5. **Exception disclosure (medium):** clients receive a generic 500 response; logs contain only the path and exception class.
6. **Overly permissive CORS (medium):** only origins listed in `ALLOWED_ORIGINS` receive CORS headers.
7. **Shared report links (new feature):** high-entropy random token, only SHA-256 token digest stored in the database, 24-hour expiration, optional bcrypt password, owner check on link creation, and `Cache-Control: no-store` on public report responses.

## Residual risks and deferred work

| Risk | Why not fully remediated here | Residual risk | Compensating control | Effort |
|---|---|---|---|---|
| Secrets and local configuration | The prototype needs local development defaults; production secrets must be injected at deployment. | A deployment that omits `SECRET_KEY` still uses a known development fallback. | Helm reads secrets through External Secrets Operator from AWS Secrets Manager; production release must reject the fallback value. | Low–medium: add startup validation and secret rotation procedure. |
| Notification service trust and webhook SSRF | The assignment says the notify service requires no changes; its webhook registration and dispatch are outside this API-focused patch. | Unauthenticated webhook management and arbitrary destination URLs can permit abuse or server-side request forgery. | Keep service private, restrict egress, authenticate service-to-service calls, and allow-list webhook destinations. | Medium–high: authorization, URL/IP validation including DNS rebinding protection, and tests. |
| Dependency/container vulnerabilities | Scanner execution requires external tools and a Docker daemon not available in this editing environment. | Known CVEs may remain in pinned Python and Node packages or base image layers. | Run the supplied scan script and CI before release; block high/critical findings pending triage. | Low–medium: upgrade compatible dependencies and rebuild, then regression test. |
| Shared-link lifecycle | This prototype does not provide revocation or per-link access audit history. | A recipient can access the report until expiry if the link is disclosed. | Treat links as bearer credentials; share over approved channels and keep expiry short. | Medium: add revocation, access audit events, and rate limiting. |
| SQLite storage in Kubernetes | SQLite is used by the starter project and is not a robust multi-replica production database. | Concurrent writes and persistent-volume behavior can be unreliable across replicas. | Helm is a deployment example only; use a managed PostgreSQL database before production and configure network access and backups. | Medium–high: migration, backup/restore, and load tests. |

## Release gates

- Run Python and Node tests on Python 3.11 and Node 20.
- Run all four scanner categories and commit their raw JSON outputs.
- Review each high/critical scanner result; document accepted risk with an owner and deadline.
- Verify that production `SECRET_KEY` is not the development fallback.
- Validate Helm manifests and test ingress, network policy, probes, persistence, and secret retrieval in a staging cluster.
