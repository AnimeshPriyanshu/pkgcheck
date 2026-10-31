"""Tests validating test fixtures in fixtures/."""

import json
from pathlib import Path

from pkgcheck.compare import list_package_files, list_source_files, match_files
from pkgcheck.models import Status
from pkgcheck.rules import INSTALL_SCRIPTS, apply_rules

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_clean_fixture_directories_and_files_exist():
    """Verify clean fixture directories and required files exist."""
    clean_src = FIXTURES_DIR / "clean" / "source"
    clean_pkg = FIXTURES_DIR / "clean" / "package"

    assert clean_src.is_dir()
    assert clean_pkg.is_dir()

    for path in (
        clean_src / "package.json",
        clean_src / "index.js",
        clean_src / "README.md",
        clean_pkg / "package.json",
        clean_pkg / "index.js",
        clean_pkg / "README.md",
    ):
        assert path.is_file(), f"Expected file missing: {path}"


def test_clean_fixture_valid_json_and_matching_sets():
    """Verify clean fixture package.json files are valid JSON and file sets match."""
    clean_src = FIXTURES_DIR / "clean" / "source"
    clean_pkg = FIXTURES_DIR / "clean" / "package"

    src_json = json.loads((clean_src / "package.json").read_text(encoding="utf-8"))
    pkg_json = json.loads((clean_pkg / "package.json").read_text(encoding="utf-8"))

    assert src_json == pkg_json
    assert "name" in src_json

    # Verify no install lifecycle scripts
    for script_name in INSTALL_SCRIPTS:
        assert script_name not in src_json.get("scripts", {})
        assert script_name not in pkg_json.get("scripts", {})

    # File sets must be identical
    src_files = list_source_files(clean_src)
    pkg_files = list_package_files(clean_pkg)
    assert src_files == pkg_files
    assert "package.json" in src_files
    assert "index.js" in src_files
    assert "README.md" in src_files


def test_poisoned_fixture_directories_and_files_exist():
    """Verify poisoned fixture directories and expected files exist."""
    poisoned_src = FIXTURES_DIR / "poisoned" / "source"
    poisoned_pkg = FIXTURES_DIR / "poisoned" / "package"

    assert poisoned_src.is_dir()
    assert poisoned_pkg.is_dir()

    assert (poisoned_src / "package.json").is_file()
    assert (poisoned_src / "index.js").is_file()

    assert (poisoned_pkg / "package.json").is_file()
    assert (poisoned_pkg / "setup.js").is_file()

    # setup.js must exist only in package, not in source
    assert not (poisoned_src / "setup.js").exists()


def test_poisoned_fixture_package_json_and_install_script():
    """Verify poisoned package.json introduces an install lifecycle script absent in source."""
    poisoned_src = FIXTURES_DIR / "poisoned" / "source"
    poisoned_pkg = FIXTURES_DIR / "poisoned" / "package"

    src_json = json.loads((poisoned_src / "package.json").read_text(encoding="utf-8"))
    pkg_json = json.loads((poisoned_pkg / "package.json").read_text(encoding="utf-8"))

    # Source must not have postinstall
    assert "postinstall" not in src_json.get("scripts", {})

    # Package must contain postinstall
    assert "postinstall" in pkg_json.get("scripts", {})
    assert pkg_json["scripts"]["postinstall"] == "node setup.js"


def test_integration_clean_fixture_produces_no_suspicious_findings():
    """Clean fixture through compare and rules pipeline produces no SUSPICIOUS findings."""
    clean_src = FIXTURES_DIR / "clean" / "source"
    clean_pkg = FIXTURES_DIR / "clean" / "package"

    src_files = list_source_files(clean_src)
    pkg_files = list_package_files(clean_pkg)

    findings = match_files(pkg_files, src_files)
    enriched = apply_rules(clean_pkg, clean_src, findings)

    suspicious = [f for f in enriched if f.status == Status.SUSPICIOUS]
    assert len(suspicious) == 0

    # All findings must be Status.EXPECTED
    for f in enriched:
        assert f.status == Status.EXPECTED
        assert f.reason == "matched"


def test_integration_poisoned_fixture_triggers_expected_rules():
    """Poisoned fixture produces both install-script and unknown-file SUSPICIOUS findings."""
    poisoned_src = FIXTURES_DIR / "poisoned" / "source"
    poisoned_pkg = FIXTURES_DIR / "poisoned" / "package"

    src_files = list_source_files(poisoned_src)
    pkg_files = list_package_files(poisoned_pkg)

    findings = match_files(pkg_files, src_files)
    enriched = apply_rules(poisoned_pkg, poisoned_src, findings)

    by_file = {f.file: f for f in enriched}

    # Signal 1: package.json has install-script
    assert "package.json" in by_file
    pkg_finding = by_file["package.json"]
    assert pkg_finding.status == Status.SUSPICIOUS
    assert pkg_finding.reason == "install-script"
    assert '"postinstall"' in pkg_finding.snippet

    # Signal 2: setup.js is unknown-file with snippet
    assert "setup.js" in by_file
    setup_finding = by_file["setup.js"]
    assert setup_finding.status == Status.SUSPICIOUS
    assert setup_finding.reason == "unknown-file"
    assert setup_finding.snippet is not None
    assert "harmless setup script" in setup_finding.snippet
