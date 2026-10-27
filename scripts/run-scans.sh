#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports

# SAST: Bandit JSON output for Python application source.
bandit -r app -f json -o reports/sast.bandit.json

# SCA: pip-audit emits JSON; scan pinned Python requirements.
pip-audit -r requirements.txt -f json > reports/sca.pip-audit.json

# Node.js dependency audit.
( cd notify && npm audit --json > ../reports/sca.npm-audit.json ) || true

# Container: requires a working Docker daemon and Trivy installed.
docker build -t vulntracker-api:assignment .
trivy image --format json --output reports/container.trivy.json vulntracker-api:assignment

# IaC: Checkov JSON output for the Helm deployment configuration.
checkov -d helm --framework kubernetes --output json > reports/iac.checkov.json

echo "Raw reports written to reports/. Review findings before submission."
