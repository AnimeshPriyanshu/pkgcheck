"""Tests for compare.py."""

from pathlib import Path
from pkgcheck.compare import list_package_files, list_source_files, match_files
from pkgcheck.models import Finding, Status


def test_list_package_files_nested(tmp_path: Path):
    """Test listing files with nested folders."""
    (tmp_path / "index.js").write_text("console.log(1)")
    (tmp_path / "package.json").write_text('{"name":"test"}')
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "util.js").write_text("export const x = 1")
    (tmp_path / "lib" / "deep").mkdir(parents=True)
    (tmp_path / "lib" / "deep" / "nested.js").write_text("export const y = 2")

    files = list_package_files(tmp_path)
    assert files == [
        "index.js",
        "lib/deep/nested.js",
        "lib/util.js",
        "package.json"
    ]


def test_list_source_files_skips_git_only(tmp_path: Path):
    """Test that .git is skipped but .github and .gitignore are kept."""
    (tmp_path / "src" / "main.js").parent.mkdir(parents=True)
    (tmp_path / "src" / "main.js").write_text("console.log(2)")
    (tmp_path / ".github" / "workflows" / "ci.yml").parent.mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI")
    (tmp_path / ".gitignore").write_text("node_modules/\n")
    (tmp_path / ".git" / "config").parent.mkdir(parents=True)
    (tmp_path / ".git" / "config").write_text("[core]\n")

    files = list_source_files(tmp_path)
    assert files == [
        ".github/workflows/ci.yml",
        ".gitignore",
        "src/main.js"
    ]


def test_list_source_files_keeps_other_dotfiles(tmp_path: Path):
    """Test that other dot-files like .npmrc are kept."""
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/")
    (tmp_path / "src" / "index.js").parent.mkdir(parents=True)
    (tmp_path / "src" / "index.js").write_text("")

    files = list_source_files(tmp_path)
    assert ".npmrc" in files


def test_match_files_unknown_file(tmp_path: Path):
    """Files only in package get unknown-file reason."""
    pkg = ["index.js", "package.json", "evil.js"]
    src = ["index.js", "package.json", "README.md"]
    findings = match_files(pkg, src)

    evil = next(f for f in findings if f.file == "evil.js")
    assert evil.reason == "unknown-file"
    assert evil.status == Status.SUSPICIOUS


def test_match_files_matched(tmp_path: Path):
    """Files in both get matched reason."""
    pkg = ["index.js", "package.json"]
    src = ["index.js", "package.json", "README.md"]
    findings = match_files(pkg, src)

    for f in findings:
        if f.file in ("index.js", "package.json"):
            assert f.reason == "matched"
            assert f.status == Status.EXPECTED


def test_match_files_missing_in_package(tmp_path: Path):
    """Files only in source get missing-in-package reason."""
    pkg = ["index.js"]
    src = ["index.js", "README.md", "src/main.js"]
    findings = match_files(pkg, src)

    missing = [f for f in findings if f.reason == "missing-in-package"]
    assert {f.file for f in missing} == {"README.md", "src/main.js"}
    for f in missing:
        assert f.status == Status.EXPECTED


def test_match_files_sorted_output(tmp_path: Path):
    """Output is sorted by file name."""
    pkg = ["z.js", "a.js"]
    src = ["a.js"]
    findings = match_files(pkg, src)
    files = [f.file for f in findings]
    assert files == ["a.js", "z.js"]


def test_list_package_files_empty_dir(tmp_path: Path):
    """Empty directory returns empty list."""
    assert list_package_files(tmp_path) == []


def test_list_source_files_empty_dir(tmp_path: Path):
    """Empty directory returns empty list."""
    assert list_source_files(tmp_path) == []