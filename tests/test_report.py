"""Tests for report.py."""

import json
from pkgcheck.models import Finding, Status
from pkgcheck.report import render_findings, exit_code_for_findings


def test_empty_table_output():
    """Empty findings list returns friendly message for table format."""
    result = render_findings([], format="table")
    assert result == "No differences found."


def test_empty_json_output():
    """Empty findings list returns empty array for JSON format."""
    result = render_findings([], format="json")
    assert result == "[]"


def test_all_expected_findings_table():
    """Table output for all EXPECTED findings."""
    findings = [
        Finding(file="index.js", status=Status.EXPECTED, reason="matched"),
        Finding(file="package.json", status=Status.EXPECTED, reason="matched"),
    ]
    result = render_findings(findings, format="table")
    assert "Expected" in result
    assert "matched" in result
    assert "index.js" in result
    assert "package.json" in result
    assert "|" in result  # table separators


def test_suspicious_exit_code():
    """Exit code 1 when any finding is SUSPICIOUS."""
    findings = [
        Finding(file="index.js", status=Status.EXPECTED, reason="matched"),
        Finding(file="evil.js", status=Status.SUSPICIOUS, reason="unknown-file"),
    ]
    assert exit_code_for_findings(findings) == 1


def test_clean_exit_code():
    """Exit code 0 when all findings are EXPECTED."""
    findings = [
        Finding(file="index.js", status=Status.EXPECTED, reason="matched"),
        Finding(file="package.json", status=Status.EXPECTED, reason="matched"),
    ]
    assert exit_code_for_findings(findings) == 0


def test_empty_findings_exit_code():
    """Exit code 0 for empty findings list."""
    assert exit_code_for_findings([]) == 0


def test_json_structure_and_keys():
    """JSON output includes all Finding fields."""
    findings = [
        Finding(
            file="test.js",
            status=Status.SUSPICIOUS,
            reason="obfuscation",
            snippet="eval(...)",
            line=10,
            explanation="Obfuscated code detected",
        )
    ]
    result = render_findings(findings, format="json")
    data = json.loads(result)
    assert len(data) == 1
    item = data[0]
    assert item["file"] == "test.js"
    assert item["status"] == "Suspicious"
    assert item["reason"] == "obfuscation"
    assert item["snippet"] == "eval(...)"
    assert item["line"] == 10
    assert item["explanation"] == "Obfuscated code detected"


def test_json_optional_fields():
    """JSON output omits None optional fields."""
    findings = [
        Finding(file="a.js", status=Status.EXPECTED, reason="matched"),
    ]
    result = render_findings(findings, format="json")
    data = json.loads(result)
    item = data[0]
    assert "snippet" not in item
    assert "line" not in item
    assert "explanation" not in item


def test_long_snippet_truncation_in_table():
    """Long snippets are truncated in table output."""
    long_snippet = "x" * 100
    findings = [
        Finding(file="big.js", status=Status.SUSPICIOUS, reason="unknown-file", snippet=long_snippet),
    ]
    result = render_findings(findings, format="table")
    assert "..." in result
    # Verify snippet column is truncated (not the full 100 chars)
    assert "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in result


def test_full_snippet_preserved_in_json():
    """Full snippets are preserved in JSON output."""
    long_snippet = "x" * 100
    findings = [
        Finding(file="big.js", status=Status.SUSPICIOUS, reason="unknown-file", snippet=long_snippet),
    ]
    result = render_findings(findings, format="json")
    data = json.loads(result)
    assert data[0]["snippet"] == long_snippet


def test_table_column_alignment():
    """Table columns are properly aligned."""
    findings = [
        Finding(file="a.js", status=Status.EXPECTED, reason="matched"),
        Finding(file="very_long_filename.js", status=Status.SUSPICIOUS, reason="unknown-file"),
    ]
    result = render_findings(findings, format="table")
    lines = result.split("\n")
    # Check header and separator exist
    assert "STATUS" in lines[0]
    assert "REASON" in lines[0]
    assert "FILE" in lines[0]
    assert "SNIPPET" in lines[0]
    assert "-+-" in lines[1]  # separator line


def test_invalid_format_raises_error():
    """Unsupported format raises ValueError with clear message."""
    findings = [Finding(file="a.js", status=Status.EXPECTED, reason="matched")]
    try:
        render_findings(findings, format="xml")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unsupported format" in str(e)
        assert "xml" in str(e)


def test_snippet_none_handled_in_table():
    """None snippet is handled gracefully in table."""
    findings = [
        Finding(file="a.js", status=Status.EXPECTED, reason="matched", snippet=None),
    ]
    result = render_findings(findings, format="table")
    assert "a.js" in result
    assert "Expected" in result