"""Tests for models.py."""

from pkgcheck.models import Finding, Status


def test_status_enum_values():
    assert Status.EXPECTED.value == "Expected"
    assert Status.SUSPICIOUS.value == "Suspicious"


def test_finding_creation():
    f = Finding(
        file="test.js",
        status=Status.SUSPICIOUS,
        reason="obfuscation",
        snippet="eval(...)",
        line=1,
        explanation="Obfuscated code detected"
    )
    assert f.file == "test.js"
    assert f.status == Status.SUSPICIOUS
    assert f.reason == "obfuscation"
    assert f.snippet == "eval(...)"
    assert f.line == 1
    assert f.explanation == "Obfuscated code detected"


def test_finding_defaults():
    f = Finding(file="a.js", status=Status.EXPECTED, reason="identical")
    assert f.snippet is None
    assert f.line is None
    assert f.explanation is None


def test_finding_explanation_field():
    f = Finding(file="b.js", status=Status.SUSPICIOUS, reason="unknown-file")
    assert f.explanation is None
    f.explanation = "File not in source"
    assert f.explanation == "File not in source"