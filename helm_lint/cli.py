"""CLI entrypoint for Helm Chart & Values Security Lint CLI (Lite)."""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .parser import load_helm_chart
from .rules import run_audit


def format_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = [
        "# Helm Chart Security Audit Report",
        "",
        f"- **Target**: `{report['target']}`",
        f"- **Security Score**: **{report['score']}/100** (Grade: **{report['grade']}**)",
        f"- **Total Findings**: {report['total_findings']}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {sev} | {report['summary'][sev]} |")

    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not report["findings"]:
        lines.append("No security issues detected.")
    else:
        lines.append("| Rule | Severity | File:Line | Message | Remediation |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in report["findings"]:
            lines.append(
                f"| `{f['rule_id']}` | {f['severity']} | `{f['file']}:{f['line']}` | {f['message']} | {f['remediation']} |"
            )

    return "\n".join(lines) + "\n"


def format_text(report: Dict[str, Any]) -> str:
    lines: List[str] = [
        f"Helm Chart Security Lint (v{__version__})",
        f"Target: {report['target']}",
        f"Score : {report['score']}/100 (Grade {report['grade']})",
        f"Issues: {report['total_findings']} "
        f"(CRITICAL={report['summary']['CRITICAL']}, HIGH={report['summary']['HIGH']}, "
        f"MEDIUM={report['summary']['MEDIUM']}, LOW={report['summary']['LOW']})",
        "-" * 72,
    ]
    for f in report["findings"]:
        lines.append(f"[{f['severity']}] {f['rule_id']} {f['file']}:{f['line']} - {f['message']}")
        lines.append(f"  Fix: {f['remediation']}")
    if not report["findings"]:
        lines.append("No security issues detected.")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="helm-lint",
        description="Zero-dependency static security linter for Helm Chart.yaml, values.yaml, and templates/*.yaml.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to Helm chart directory or YAML file (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output report format (default: text).",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Fail with exit code 1 if security score is below this threshold (0-100).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional file path to write the report.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: target path '{target_path}' does not exist.", file=sys.stderr)
        return 2

    chart = load_helm_chart(target_path)
    if not chart.raw_files:
        print(f"Error: no Helm chart files found in '{target_path}'.", file=sys.stderr)
        return 2

    report = run_audit(chart)

    if args.format == "json":
        rendered = json.dumps(report, indent=2) + "\n"
    elif args.format == "markdown":
        rendered = format_markdown(report)
    else:
        rendered = format_text(report)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    if report["score"] < args.min_score:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
