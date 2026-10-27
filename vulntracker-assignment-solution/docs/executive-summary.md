# Executive summary

VulnTracker started as an internal prototype and was not ready to hold sensitive vulnerability reports in a shared environment. A user could potentially search outside their own records, read another user's scan by guessing its ID, and expose passwords through logs. Error responses also revealed internal details. This change addresses those application-level weaknesses and adds a controlled way to share a single report for up to 24 hours.

## Posture before and after

**Before:** The service had several serious access-control and information-disclosure weaknesses. Its security had not been validated through a complete set of scans.

**After this change:** Search and individual scan reads are scoped to the authenticated owner; login passwords are not logged; token validation is stricter; browser origins are explicitly allow-listed; and shared reports use high-entropy links, expiration, optional password protection, and cache protections. A non-root container and a restricted Helm deployment example are included.

The improved design is not the same as a production security certification. The four required scans must be run and their results reviewed before the security posture can be considered verified.

## Top three remaining risks

1. **Notification service exposure:** Its webhook administration endpoints are unauthenticated and accept arbitrary callback URLs. A reachable service could be abused to send requests to internal destinations. It was left unchanged because the brief says no notification-service changes are required; production deployment should isolate it, authenticate callers, and restrict destinations.
2. **Dependency and image vulnerabilities:** Current findings are unknown until SAST, dependency, container, and IaC scans have been run. The next step is to scan, upgrade affected packages, and retest.
3. **Prototype storage and shared-link lifecycle:** SQLite and non-revocable links are suitable only for a limited prototype. Use managed PostgreSQL, add revocation and access auditing, and define retention and backup controls before production.

## Recommended next steps

1. Run the test suites and all four security scans; preserve the raw JSON and assign owners to high/critical findings.
2. Deploy to a staging environment using secrets from the cloud secrets manager, TLS, least-privilege network rules, and monitoring.
3. Move to managed PostgreSQL with encrypted backups and a tested recovery process.
4. Secure the notification service and add rate limits, audit logging, and webhook destination controls.
5. Add shared-link revocation and access auditing, and review the design with the security team before external use.
