# Prioritised security findings

**Evidence status:** The items marked `manual` below come from source review. Tool findings must be confirmed by running `scripts/run-scans.sh` in an environment with Docker and the named tools. No scanner output has been fabricated or represented as a completed scan.

| ID | Source / scan type | Severity and rationale | Business impact to VulnTracker | Origin | Status |
|---|---|---|---|---|---|
| F-01 | Manual — `app/database.py` SQL construction | High: user-controlled search text was interpolated into SQL. | An authenticated user could manipulate search SQL and potentially read or alter data depending on the database/driver. | Starter | Fixed with bound parameters and owner scope. |
| F-02 | Manual — `app/main.py` scan access | High: `GET /scans/{scan_id}` did not check scan ownership. | One customer could retrieve another customer's vulnerability details, components, and remediation notes by guessing IDs. | Starter | Fixed with owner filter. |
| F-03 | Manual — `app/main.py` login logging | High: raw passwords were written to application logs on login attempts. | Log access could expose user credentials and lead to account compromise. | Starter | Fixed; passwords are no longer logged. |
| F-04 | Manual — `app/auth.py` JWT validation | High: the decoder allowed the `none` algorithm in its allow-list. | Weak token validation can undermine authentication assumptions. | Starter | Fixed by allowing only configured HS256. |
| F-05 | Manual — `app/main.py` exception handler | Medium: raw exception details and traceback were returned to clients. | Internal paths, implementation details, and sensitive exception values could be disclosed. | Starter | Fixed; generic client error response. |
| F-06 | Manual — CORS middleware | Medium: arbitrary request origins were reflected with credentials enabled. | A malicious website could potentially make credentialed browser requests in affected deployments. | Starter | Fixed to allow only explicitly configured origins. |
| F-07 | Manual — shared report links | High if token handling is weak: shared reports intentionally bypass login. | A leaked link could disclose sensitive vulnerability data. | New feature | Random 256-bit token, hash-at-rest, 24-hour expiry, optional bcrypt password, no-store response headers. |
| F-08 | SCA — `pip-audit` / `npm audit` | Pending execution | Vulnerable libraries could expose the API or notification service to known attacks. | Starter | Run scanners and record results before submission. |
| F-09 | SAST — Bandit | Pending execution | Unsafe Python patterns may introduce injection, weak crypto, or debug leakage. | Starter + new feature | Run scanner and interpret results. |
| F-10 | Container — Trivy | Pending execution | Vulnerable OS and Python packages could be exploited after deployment. | Deployment artifact | Build image and scan it. |
| F-11 | IaC — Checkov | Pending execution | Deployment misconfiguration could expose the API or grant excess privileges. | Deployment artifact | Scan Helm chart and review findings. |

## Scan commands and report files

Run `bash scripts/run-scans.sh` from the repository root. It writes raw JSON files under `reports/`. The container scan requires Docker. Scanner output and findings should be reviewed before describing the posture as verified.
