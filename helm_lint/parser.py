"""Zero-dependency Helm chart & YAML-like static parser (Python 3.9+ stdlib)."""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class HelmChart:
    """Represents a parsed Helm chart directory or single file."""

    root: Path
    chart_meta: Dict[str, Any] = field(default_factory=dict)
    values: Dict[str, Any] = field(default_factory=dict)
    raw_files: Dict[str, str] = field(default_factory=dict)
    templates: Dict[str, str] = field(default_factory=dict)


def _strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx]
    return line


def _parse_scalar(val: str) -> Any:
    v = val.strip()
    if not v or v in ("null", "~", "Null", "NULL"):
        return None
    if v in ("true", "True", "TRUE"):
        return True
    if v in ("false", "False", "FALSE"):
        return False
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item) for item in inner.split(",")]
    if re.fullmatch(r"-?\d+", v):
        try:
            return int(v)
        except ValueError:
            return v
    if re.fullmatch(r"-?\d+\.\d+", v):
        try:
            return float(v)
        except ValueError:
            return v
    return v


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """
    Lightweight indentation-based YAML subset parser using only Python stdlib.
    Handles nested mappings, simple lists, and scalar types.
    """
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any]] = [(-1, root)]

    for raw_line in text.splitlines():
        cleaned = _strip_inline_comment(raw_line).rstrip()
        if not cleaned.strip() or cleaned.strip() in ("---", "..."):
            continue
        # Skip Helm template directives
        stripped = cleaned.lstrip()
        if stripped.startswith("{{"):
            continue

        indent = len(cleaned) - len(stripped)

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]

        if stripped.startswith("- "):
            item_text = stripped[2:].strip()
            if isinstance(parent, list):
                if ":" in item_text and not item_text.startswith(("'", '"')):
                    k, _, v = item_text.partition(":")
                    entry: Dict[str, Any] = {k.strip(): _parse_scalar(v) if v.strip() else {}}
                    parent.append(entry)
                    stack.append((indent, entry))
                else:
                    parent.append(_parse_scalar(item_text))
            continue

        if ":" not in stripped:
            continue

        key, _, rest = stripped.partition(":")
        key = key.strip().strip("'\"")
        val_str = rest.strip()

        if isinstance(parent, dict):
            if not val_str:
                # Peek next structure: default to dict; list items will be attached if needed
                new_container: Any = {}
                parent[key] = new_container
                stack.append((indent, new_container))
            else:
                parent[key] = _parse_scalar(val_str)

    return root


def load_helm_chart(target: Path) -> HelmChart:
    """Load Chart.yaml, values.yaml, and templates/*.yaml from a directory or file."""
    target = Path(target)
    chart = HelmChart(root=target)

    if target.is_file():
        content = target.read_text(encoding="utf-8", errors="replace")
        rel = target.name
        chart.raw_files[rel] = content
        if target.name.lower() == "chart.yaml":
            chart.chart_meta = parse_simple_yaml(content)
        elif target.name.lower() in ("values.yaml", "values.yml"):
            chart.values = parse_simple_yaml(content)
        else:
            chart.templates[rel] = content
        return chart

    chart_yaml = target / "Chart.yaml"
    if chart_yaml.is_file():
        content = chart_yaml.read_text(encoding="utf-8", errors="replace")
        chart.raw_files["Chart.yaml"] = content
        chart.chart_meta = parse_simple_yaml(content)

    for vname in ("values.yaml", "values.yml"):
        vpath = target / vname
        if vpath.is_file():
            content = vpath.read_text(encoding="utf-8", errors="replace")
            chart.raw_files[vname] = content
            chart.values = parse_simple_yaml(content)
            break

    templates_dir = target / "templates"
    if templates_dir.is_dir():
        for tfile in sorted(templates_dir.rglob("*")):
            if tfile.is_file() and tfile.suffix.lower() in (".yaml", ".yml", ".tpl"):
                rel = str(tfile.relative_to(target)).replace("\\", "/")
                content = tfile.read_text(encoding="utf-8", errors="replace")
                chart.raw_files[rel] = content
                chart.templates[rel] = content

    return chart
