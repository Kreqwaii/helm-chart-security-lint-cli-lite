# Helm Chart & Values Security Lint CLI (Lite)

**Zero-dependency Python 3.9+ static security linter for Helm charts (`Chart.yaml`, `values.yaml`, and `templates/*.yaml`).**

Catch Kubernetes & Helm misconfigurations in CI/CD before deployment: unpinned `:latest` image tags, privileged containers, root execution, host namespace sharing, missing CPU/memory limits, missing health probes, hardcoded secrets, and wildcard RBAC permissions.

---

## Key Features

- **100% Python 3.9+ Stdlib**: Zero third-party dependencies (`pip install` not required to run).
- **13 Built-in Security Rules (`HCL001`–`HCL013`)**: Covers `Chart.yaml`, `values.yaml`, and `templates/*.yaml`.
- **Security Scoring & Grading**: 0–100 score with `A`–`F` grade and `--min-score` CI gate.
- **Multiple Output Formats**: Human-readable `text`, machine-readable `json`, and `markdown` reports.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/helm-chart-security-lint-cli-lite.git
cd helm-chart-security-lint-cli-lite

# Run against the included example chart
python -m helm_lint.cli examples --format text

# Output JSON report
python -m helm_lint.cli examples --format json

# Output Markdown report and enforce minimum score in CI
python -m helm_lint.cli examples --format markdown --min-score 80
```

---

## Security Rules

| Rule ID | Severity | Target | Description |
| --- | --- | --- | --- |
| `HCL001` | HIGH / MEDIUM | `values.yaml`, `templates/` | Detects `:latest` or empty/unpinned container image tags |
| `HCL002` | CRITICAL | `values.yaml`, `templates/` | Detects `privileged: true` in container `securityContext` |
| `HCL003` | HIGH | `values.yaml`, `templates/` | Detects `runAsNonRoot: false` or `runAsUser: 0` |
| `HCL004` | HIGH | `values.yaml`, `templates/` | Detects `allowPrivilegeEscalation: true` |
| `HCL005` | CRITICAL | `values.yaml`, `templates/` | Detects `hostNetwork`, `hostPID`, or `hostIPC` set to `true` |
| `HCL006` | MEDIUM | `values.yaml`, `templates/` | Detects missing CPU/memory `resources.limits` |
| `HCL007` | LOW | `values.yaml`, `templates/` | Detects missing `livenessProbe` / `readinessProbe` |
| `HCL008` | CRITICAL | `values.yaml`, `templates/` | Detects hardcoded passwords, API keys, tokens, and secrets |
| `HCL009` | CRITICAL | `templates/` | Detects wildcard `*` in RBAC `Role` / `ClusterRole` rules |
| `HCL010` | MEDIUM | `values.yaml`, `templates/` | Detects `readOnlyRootFilesystem: false` |
| `HCL011` | HIGH | `values.yaml`, `templates/` | Detects `hostPath` volume mounts |
| `HCL012` | LOW | `Chart.yaml` | Validates `apiVersion: v2` and `appVersion` presence |
| `HCL013` | MEDIUM | `values.yaml`, `templates/` | Detects `automountServiceAccountToken: true` |

---

## Lite vs Pro Studio

| Feature | Lite (Open Source) | Pro Studio |
| --- | --- | --- |
| Zero-dependency Python 3.9+ CLI | Included | Included |
| 13 Core Helm Security Rules | Included | Included |
| Text, JSON & Markdown Reports | Included | Included |
| Full Helm Template Rendering (`helm template` + AST) | — | Included |
| 50+ CIS Kubernetes & NSA/CISA Hardening Rules | — | Included |
| Custom OPA / Rego & Policy-as-Code Packs | — | Included |
| SARIF v2.1 Export for GitHub Code Scanning | — | Included |
| Automated PR Remediation & Fix Suggestions | — | Included |

Upgrade to **Pro Studio** on FunPay: [https://funpay.com/users/20096179/](https://funpay.com/users/20096179/)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
