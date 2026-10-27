# Scan report status

Raw JSON scan reports are intentionally not pre-populated with invented results. Run `bash scripts/run-scans.sh` in an environment with Bandit, pip-audit, Trivy, Checkov, Node.js/npm, and a working Docker daemon. The script creates the four required scan categories as JSON under this directory (plus a separate npm audit JSON report). Review and commit the generated reports before submission.
