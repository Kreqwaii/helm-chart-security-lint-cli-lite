"""Comprehensive unit tests for helm_lint (28+ tests, stdlib unittest)."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from helm_lint.cli import main
from helm_lint.parser import HelmChart, load_helm_chart, parse_simple_yaml
from helm_lint.rules import (
    check_allow_privilege_escalation,
    check_automount_service_account_token,
    check_chart_metadata,
    check_hardcoded_secrets,
    check_host_namespaces,
    check_host_path_mount,
    check_missing_probes,
    check_missing_resource_limits,
    check_privileged_container,
    check_run_as_root,
    check_unpinned_or_latest_image,
    check_wildcard_rbac,
    check_writable_root_fs,
    run_audit,
)


def _make_chart(raw_files: dict, chart_meta: dict = None) -> HelmChart:
    return HelmChart(
        root=Path("."),
        chart_meta=chart_meta or {},
        values={},
        raw_files=raw_files,
        templates={},
    )


class TestParser(unittest.TestCase):
    def test_parse_simple_yaml_nested(self):
        data = parse_simple_yaml("image:\n  repository: nginx\n  tag: '1.25.0'\n  pullPolicy: IfNotPresent\n")
        self.assertEqual(data["image"]["repository"], "nginx")
        self.assertEqual(data["image"]["tag"], "1.25.0")

    def test_parse_simple_yaml_booleans_and_numbers(self):
        data = parse_simple_yaml("enabled: true\nreplicas: 3\nratio: 0.5\nempty: null\n")
        self.assertIs(data["enabled"], True)
        self.assertEqual(data["replicas"], 3)
        self.assertEqual(data["ratio"], 0.5)
        self.assertIsNone(data["empty"])

    def test_parse_simple_yaml_skips_helm_directives(self):
        data = parse_simple_yaml("{{- if .Values.enabled }}\nname: app\n{{- end }}\n")
        self.assertEqual(data["name"], "app")

    def test_load_helm_chart_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Chart.yaml").write_text("apiVersion: v2\nname: test\nappVersion: '1.0.0'\n", encoding="utf-8")
            (root / "values.yaml").write_text("replicaCount: 1\n", encoding="utf-8")
            (root / "templates").mkdir()
            (root / "templates" / "deploy.yaml").write_text("kind: Deployment\n", encoding="utf-8")

            chart = load_helm_chart(root)
            self.assertIn("Chart.yaml", chart.raw_files)
            self.assertIn("values.yaml", chart.raw_files)
            self.assertIn("templates/deploy.yaml", chart.raw_files)
            self.assertEqual(chart.chart_meta["apiVersion"], "v2")

    def test_load_single_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "values.yaml"
            p.write_text("image:\n  tag: latest\n", encoding="utf-8")
            chart = load_helm_chart(p)
            self.assertIn("values.yaml", chart.raw_files)


class TestRules(unittest.TestCase):
    def test_hcl001_latest_tag(self):
        chart = _make_chart({"values.yaml": "image:\n  tag: latest\n"})
        findings = check_unpinned_or_latest_image(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL001")

    def test_hcl001_image_colon_latest(self):
        chart = _make_chart({"templates/deploy.yaml": "image: nginx:latest\n"})
        findings = check_unpinned_or_latest_image(chart)
        self.assertEqual(len(findings), 1)

    def test_hcl001_empty_tag(self):
        chart = _make_chart({"values.yaml": "image:\n  tag: \"\"\n"})
        findings = check_unpinned_or_latest_image(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_hcl001_pinned_tag_passes(self):
        chart = _make_chart({"values.yaml": "image:\n  tag: 1.25.3\n"})
        self.assertEqual(check_unpinned_or_latest_image(chart), [])

    def test_hcl002_privileged_true(self):
        chart = _make_chart({"values.yaml": "securityContext:\n  privileged: true\n"})
        findings = check_privileged_container(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_hcl003_run_as_non_root_false(self):
        chart = _make_chart({"values.yaml": "podSecurityContext:\n  runAsNonRoot: false\n"})
        findings = check_run_as_root(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL003")

    def test_hcl003_run_as_user_zero(self):
        chart = _make_chart({"templates/deploy.yaml": "runAsUser: 0\n"})
        findings = check_run_as_root(chart)
        self.assertEqual(len(findings), 1)

    def test_hcl004_allow_privilege_escalation(self):
        chart = _make_chart({"values.yaml": "allowPrivilegeEscalation: true\n"})
        findings = check_allow_privilege_escalation(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL004")

    def test_hcl005_host_network(self):
        chart = _make_chart({"templates/deploy.yaml": "hostNetwork: true\n"})
        findings = check_host_namespaces(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_hcl005_host_pid_and_ipc(self):
        chart = _make_chart({"templates/deploy.yaml": "hostPID: true\nhostIPC: true\n"})
        findings = check_host_namespaces(chart)
        self.assertEqual(len(findings), 2)

    def test_hcl006_missing_resource_limits(self):
        chart = _make_chart({"values.yaml": "resources: {}\n"})
        findings = check_missing_resource_limits(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL006")

    def test_hcl006_complete_resource_limits_passes(self):
        chart = _make_chart({"values.yaml": "resources:\n  limits:\n    cpu: 100m\n    memory: 128Mi\n"})
        self.assertEqual(check_missing_resource_limits(chart), [])

    def test_hcl007_missing_probes(self):
        chart = _make_chart({"templates/deploy.yaml": "kind: Deployment\n"})
        findings = check_missing_probes(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL007")

    def test_hcl007_probes_present_passes(self):
        chart = _make_chart({"templates/deploy.yaml": "kind: Deployment\nlivenessProbe:\nreadinessProbe:\n"})
        self.assertEqual(check_missing_probes(chart), [])

    def test_hcl008_hardcoded_secret(self):
        chart = _make_chart({"values.yaml": "dbPassword: \"MySecretPass123\"\n"})
        findings = check_hardcoded_secrets(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_hcl008_templated_secret_passes(self):
        chart = _make_chart({"values.yaml": "dbPassword: \"{{ .Values.secret }}\"\n"})
        self.assertEqual(check_hardcoded_secrets(chart), [])

    def test_hcl009_wildcard_rbac(self):
        chart = _make_chart({"templates/rbac.yaml": "kind: ClusterRole\nrules:\n- apiGroups: [\"*\"]\n  verbs: [\"*\"]\n"})
        findings = check_wildcard_rbac(chart)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].rule_id, "HCL009")

    def test_hcl010_writable_root_fs(self):
        chart = _make_chart({"values.yaml": "readOnlyRootFilesystem: false\n"})
        findings = check_writable_root_fs(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL010")

    def test_hcl011_host_path_mount(self):
        chart = _make_chart({"templates/deploy.yaml": "volumes:\n- name: host\n  hostPath:\n    path: /var/log\n"})
        findings = check_host_path_mount(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL011")

    def test_hcl012_chart_metadata_v1_and_missing_appversion(self):
        chart = _make_chart(
            {"Chart.yaml": "apiVersion: v1\nname: demo\n"},
            chart_meta={"apiVersion": "v1", "name": "demo"},
        )
        findings = check_chart_metadata(chart)
        self.assertEqual(len(findings), 2)

    def test_hcl013_automount_service_account_token(self):
        chart = _make_chart({"values.yaml": "automountServiceAccountToken: true\n"})
        findings = check_automount_service_account_token(chart)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HCL013")

    def test_run_audit_scoring_clean_chart(self):
        chart = _make_chart(
            {
                "Chart.yaml": "apiVersion: v2\nname: clean\nappVersion: 1.0.0\n",
                "values.yaml": (
                    "image:\n  tag: 1.0.0\n"
                    "resources:\n  limits:\n    cpu: 100m\n    memory: 128Mi\n"
                    "livenessProbe:\n  httpGet:\n    path: /healthz\n"
                    "readinessProbe:\n  httpGet:\n    path: /ready\n"
                ),
            },
            chart_meta={"apiVersion": "v2", "name": "clean", "appVersion": "1.0.0"},
        )
        report = run_audit(chart)
        self.assertEqual(report["score"], 100)
        self.assertEqual(report["grade"], "A")
        self.assertEqual(report["total_findings"], 0)


class TestCLI(unittest.TestCase):
    def test_cli_json_output_on_examples(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["examples", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("score", data)
        self.assertGreater(data["total_findings"], 0)

    def test_cli_markdown_output(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["examples", "--format", "markdown"])
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn("# Helm Chart Security Audit Report", out)
        self.assertIn("## Severity Summary", out)

    def test_cli_min_score_failure(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["examples", "--min-score", "95"])
        self.assertEqual(code, 1)

    def test_cli_missing_path_returns_2(self):
        err = io.StringIO()
        with patch("sys.stderr", err):
            code = main(["non_existent_path_xyz"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
