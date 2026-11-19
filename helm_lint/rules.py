"""Security audit rules for Helm Chart.yaml, values.yaml, and templates/*.yaml."""

from dataclasses import dataclass
import re
from typing import Dict, List, Tuple

from .parser import HelmChart


SEVERITY_PENALTIES: Dict[str, int] = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
        }


def _find_line(content: str, pattern: str) -> int:
    rx = re.compile(pattern, re.IGNORECASE)
    for idx, line in enumerate(content.splitlines(), start=1):
        if rx.search(line):
            return idx
    return 1


def _all_sources(chart: HelmChart) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    for fname, content in chart.raw_files.items():
        items.append((fname, content))
    return items


def check_unpinned_or_latest_image(chart: HelmChart) -> List[Finding]:
    """HCL001: Detect :latest or unpinned image tags in values.yaml and templates."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        if fname.lower() == "chart.yaml":
            continue
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"\btag\s*:\s*['\"]?latest['\"]?\b", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL001",
                        severity="HIGH",
                        file=fname,
                        line=idx,
                        message="Image tag is set to 'latest', which breaks reproducibility and supply-chain integrity.",
                        remediation="Pin an immutable semantic version tag or SHA256 digest.",
                    )
                )
            elif re.search(r"\bimage\s*:\s*['\"]?[a-zA-Z0-9._/-]+:latest['\"]?", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL001",
                        severity="HIGH",
                        file=fname,
                        line=idx,
                        message="Container image uses ':latest' tag.",
                        remediation="Use an explicit immutable version tag or digest.",
                    )
                )
            elif re.search(r"\btag\s*:\s*(['\"]\s*['\"])?\s*$", stripped) and "tag:" in stripped:
                findings.append(
                    Finding(
                        rule_id="HCL001",
                        severity="MEDIUM",
                        file=fname,
                        line=idx,
                        message="Image tag is empty or unpinned.",
                        remediation="Set a specific version tag in values.yaml.",
                    )
                )
    return findings


def check_privileged_container(chart: HelmChart) -> List[Finding]:
    """HCL002: Detect privileged: true in securityContext."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"\bprivileged\s*:\s*true\b", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL002",
                        severity="CRITICAL",
                        file=fname,
                        line=idx,
                        message="Container runs in privileged mode (privileged: true).",
                        remediation="Set 'privileged: false' and grant only minimal Linux capabilities.",
                    )
                )
    return findings


def check_run_as_root(chart: HelmChart) -> List[Finding]:
    """HCL003: Detect runAsNonRoot: false or runAsUser: 0."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"\brunAsNonRoot\s*:\s*false\b", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL003",
                        severity="HIGH",
                        file=fname,
                        line=idx,
                        message="Pod or container sets 'runAsNonRoot: false', allowing root execution.",
                        remediation="Set 'runAsNonRoot: true' in pod/container securityContext.",
                    )
                )
            if re.search(r"\brunAsUser\s*:\s*0\b", line):
                findings.append(
                    Finding(
                        rule_id="HCL003",
                        severity="HIGH",
                        file=fname,
                        line=idx,
                        message="Container explicitly runs as UID 0 (root).",
                        remediation="Use a non-zero UID (e.g. runAsUser: 10001).",
                    )
                )
    return findings


def check_allow_privilege_escalation(chart: HelmChart) -> List[Finding]:
    """HCL004: Detect allowPrivilegeEscalation: true."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"\ballowPrivilegeEscalation\s*:\s*true\b", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL004",
                        severity="HIGH",
                        file=fname,
                        line=idx,
                        message="allowPrivilegeEscalation is enabled.",
                        remediation="Set 'allowPrivilegeEscalation: false' in container securityContext.",
                    )
                )
    return findings


def check_host_namespaces(chart: HelmChart) -> List[Finding]:
    """HCL005: Detect hostNetwork, hostPID, or hostIPC set to true."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            m = re.search(r"\b(hostNetwork|hostPID|hostIPC)\s*:\s*true\b", line, re.IGNORECASE)
            if m:
                findings.append(
                    Finding(
                        rule_id="HCL005",
                        severity="CRITICAL",
                        file=fname,
                        line=idx,
                        message=f"Host namespace sharing enabled ({m.group(1)}: true).",
                        remediation=f"Disable '{m.group(1)}: false' to isolate pod from host.",
                    )
                )
    return findings


def check_missing_resource_limits(chart: HelmChart) -> List[Finding]:
    """HCL006: Detect missing CPU/memory limits in values.yaml or workload templates."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        lower = fname.lower()
        is_values = lower in ("values.yaml", "values.yml")
        is_workload = any(k in content for k in ("kind: Deployment", "kind: StatefulSet", "kind: DaemonSet"))
        if not (is_values or is_workload):
            continue
        has_limits = bool(re.search(r"\blimits\s*:", content))
        has_cpu = bool(re.search(r"\bcpu\s*:", content))
        has_memory = bool(re.search(r"\bmemory\s*:", content))
        if not (has_limits and has_cpu and has_memory):
            findings.append(
                Finding(
                    rule_id="HCL006",
                    severity="MEDIUM",
                    file=fname,
                    line=_find_line(content, r"resources\s*:"),
                    message="Missing or incomplete CPU/memory resource limits.",
                    remediation="Define both 'resources.limits.cpu' and 'resources.limits.memory'.",
                )
            )
    return findings


def check_missing_probes(chart: HelmChart) -> List[Finding]:
    """HCL007: Detect missing livenessProbe / readinessProbe in workload templates or values."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        lower = fname.lower()
        is_values = lower in ("values.yaml", "values.yml")
        is_workload = any(k in content for k in ("kind: Deployment", "kind: StatefulSet", "kind: DaemonSet"))
        if not (is_values or is_workload):
            continue
        has_liveness = bool(re.search(r"\blivenessProbe\s*:", content))
        has_readiness = bool(re.search(r"\breadinessProbe\s*:", content))
        if not (has_liveness and has_readiness):
            findings.append(
                Finding(
                    rule_id="HCL007",
                    severity="LOW",
                    file=fname,
                    line=1,
                    message="Missing livenessProbe and/or readinessProbe configuration.",
                    remediation="Configure both livenessProbe and readinessProbe for reliable health checks.",
                )
            )
    return findings


def check_hardcoded_secrets(chart: HelmChart) -> List[Finding]:
    """HCL008: Detect hardcoded secrets/passwords/tokens/API keys in values.yaml or templates."""
    findings: List[Finding] = []
    secret_key_rx = re.compile(
        r"^\s*([a-zA-Z0-9_.-]*(password|passwd|secret|api[_-]?key|token|private[_-]?key|access[_-]?key)[a-zA-Z0-9_.-]*)\s*:\s*['\"]?([^'\"\s#]+)['\"]?",
        re.IGNORECASE,
    )
    placeholder_rx = re.compile(r"^(\{\{|\$\{|changeme|replace[_-]?me|example|dummy|null|none|true|false)$", re.IGNORECASE)
    for fname, content in _all_sources(chart):
        if fname.lower() == "chart.yaml":
            continue
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = secret_key_rx.match(line)
            if m:
                key_name, _, val = m.group(1), m.group(2), m.group(3)
                if not placeholder_rx.match(val) and len(val) >= 4:
                    findings.append(
                        Finding(
                            rule_id="HCL008",
                            severity="CRITICAL",
                            file=fname,
                            line=idx,
                            message=f"Potential hardcoded secret in '{key_name}'.",
                            remediation="Use Kubernetes Secrets, ExternalSecrets, or empty/templated references instead of plaintext values.",
                        )
                    )
    return findings


def check_wildcard_rbac(chart: HelmChart) -> List[Finding]:
    """HCL009: Detect wildcard '*' in RBAC rules (verbs, resources, apiGroups)."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        if not any(k in content for k in ("Role", "ClusterRole", "rbac")):
            continue
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"(verbs|resources|apiGroups)\s*:\s*\[?\s*['\"]?\*['\"]?", line) or re.search(
                r"^\s*-\s*['\"]?\*['\"]?\s*$", line
            ):
                findings.append(
                    Finding(
                        rule_id="HCL009",
                        severity="CRITICAL",
                        file=fname,
                        line=idx,
                        message="Wildcard '*' detected in RBAC permissions.",
                        remediation="Follow least-privilege by specifying exact apiGroups, resources, and verbs.",
                    )
                )
    return findings


def check_writable_root_fs(chart: HelmChart) -> List[Finding]:
    """HCL010: Detect readOnlyRootFilesystem: false."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"\breadOnlyRootFilesystem\s*:\s*false\b", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL010",
                        severity="MEDIUM",
                        file=fname,
                        line=idx,
                        message="Container root filesystem is writable (readOnlyRootFilesystem: false).",
                        remediation="Set 'readOnlyRootFilesystem: true' and mount emptyDir for writable paths.",
                    )
                )
    return findings


def check_host_path_mount(chart: HelmChart) -> List[Finding]:
    """HCL011: Detect hostPath volume mounts."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"\bhostPath\s*:", line):
                findings.append(
                    Finding(
                        rule_id="HCL011",
                        severity="HIGH",
                        file=fname,
                        line=idx,
                        message="hostPath volume mount exposes host filesystem to container.",
                        remediation="Replace hostPath with PersistentVolumeClaim or emptyDir.",
                    )
                )
    return findings


def check_chart_metadata(chart: HelmChart) -> List[Finding]:
    """HCL012: Validate Chart.yaml apiVersion, version, and appVersion."""
    findings: List[Finding] = []
    if "Chart.yaml" not in chart.raw_files:
        return findings
    meta = chart.chart_meta
    if str(meta.get("apiVersion", "")).strip() != "v2":
        findings.append(
            Finding(
                rule_id="HCL012",
                severity="LOW",
                file="Chart.yaml",
                line=_find_line(chart.raw_files["Chart.yaml"], r"apiVersion\s*:"),
                message="Chart.yaml should use 'apiVersion: v2' (Helm 3+).",
                remediation="Upgrade Chart.yaml apiVersion to 'v2'.",
            )
        )
    if not meta.get("appVersion"):
        findings.append(
            Finding(
                rule_id="HCL012",
                severity="LOW",
                file="Chart.yaml",
                line=1,
                message="Chart.yaml is missing 'appVersion'.",
                remediation="Specify 'appVersion' in Chart.yaml for release traceability.",
            )
        )
    return findings


def check_automount_service_account_token(chart: HelmChart) -> List[Finding]:
    """HCL013: Detect automountServiceAccountToken: true."""
    findings: List[Finding] = []
    for fname, content in _all_sources(chart):
        for idx, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if re.search(r"\bautomountServiceAccountToken\s*:\s*true\b", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HCL013",
                        severity="MEDIUM",
                        file=fname,
                        line=idx,
                        message="automountServiceAccountToken is explicitly enabled.",
                        remediation="Set 'automountServiceAccountToken: false' unless Kubernetes API access is required.",
                    )
                )
    return findings


ALL_RULES = [
    check_unpinned_or_latest_image,
    check_privileged_container,
    check_run_as_root,
    check_allow_privilege_escalation,
    check_host_namespaces,
    check_missing_resource_limits,
    check_missing_probes,
    check_hardcoded_secrets,
    check_wildcard_rbac,
    check_writable_root_fs,
    check_host_path_mount,
    check_chart_metadata,
    check_automount_service_account_token,
]


def run_audit(chart: HelmChart) -> Dict[str, object]:
    """Run all security rules against a parsed HelmChart and compute security score."""
    findings: List[Finding] = []
    for rule_fn in ALL_RULES:
        findings.extend(rule_fn(chart))

    penalty = sum(SEVERITY_PENALTIES.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1

    return {
        "target": str(chart.root),
        "score": score,
        "grade": _score_to_grade(score),
        "total_findings": len(findings),
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
