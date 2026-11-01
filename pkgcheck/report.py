"""Report generation for pkgcheck findings."""

import json
from pkgcheck.models import Finding, Status, Severity


def render_findings(findings: list[Finding], format: str = "table") -> str:
    """Render findings as a table or JSON string."""
    if format not in ("table", "json"):
        raise ValueError(f"Unsupported format: {format}. Use 'table' or 'json'.")

    if not findings:
        return "No differences found." if format == "table" else "[]"

    if format == "table":
        return _render_table(findings)
    else:
        return _render_json(findings)


def _render_table(findings: list[Finding]) -> str:
    """Render findings as an aligned terminal table."""
    # Prepare rows
    rows = []
    for f in findings:
        status = f.status.value
        severity = f.severity.value
        reason = f.reason
        file = f.file
        snippet = f.snippet if f.snippet is not None else ""
        # Truncate snippet for table readability
        if len(snippet) > 50:
            snippet = snippet[:47] + "..."
        rows.append((status, severity, reason, file, snippet))

    # Calculate column widths
    headers = ("STATUS", "SEVERITY", "REASON", "FILE", "SNIPPET")
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    # Build table lines
    lines = []
    # Header
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    lines.append(header_line)
    # Separator
    sep_line = "-+-".join("-" * w for w in col_widths)
    lines.append(sep_line)
    # Data rows
    for row in rows:
        line = " | ".join(row[i].ljust(col_widths[i]) for i in range(5))
        lines.append(line)

    return "\n".join(lines)


def _render_json(findings: list[Finding]) -> str:
    """Render findings as a JSON array."""
    output = []
    for f in findings:
        item = {
            "file": f.file,
            "status": f.status.value,
            "severity": f.severity.value,
            "reason": f.reason,
        }
        if f.snippet is not None:
            item["snippet"] = f.snippet
        if f.line is not None:
            item["line"] = f.line
        if f.explanation is not None:
            item["explanation"] = f.explanation
        if f.evidence:
            item["evidence"] = [
                {
                    "rule": ev.rule,
                    "evidence_type": ev.evidence_type,
                    "file": ev.file,
                    "description": ev.description,
                    "weight": ev.weight,
                }
                for ev in f.evidence
            ]
        output.append(item)
    return json.dumps(output, indent=2)


def exit_code_for_findings(findings: list[Finding]) -> int:
    """Return exit code: 0 if all EXPECTED or empty, 1 if any SUSPICIOUS."""
    if not findings:
        return 0
    for f in findings:
        if f.status == Status.SUSPICIOUS:
            return 1
    return 0