"""Tests for CLI wiring in pkgcheck/cli.py."""

import json
from pathlib import Path
import subprocess
import sys

from pkgcheck.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
CLEAN_PKG = FIXTURES_DIR / "clean" / "package"
CLEAN_SRC = FIXTURES_DIR / "clean" / "source"
POISONED_PKG = FIXTURES_DIR / "poisoned" / "package"
POISONED_SRC = FIXTURES_DIR / "poisoned" / "source"


def test_cli_help(capsys):
    """main(['--help']) prints usage and returns 0."""
    exit_code = main(["--help"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower() or "pkgcheck" in captured.out


def test_cli_version(capsys):
    """main(['--version']) prints version and returns 0."""
    exit_code = main(["--version"])
    assert exit_code == 0
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "pkgcheck v" in output


def test_cli_no_args(capsys):
    """main() with no arguments prints help and returns 0."""
    exit_code = main([])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower() or "pkgcheck" in captured.out

    # Direct invocation without args
    assert main() == 0


def test_cli_missing_one_argument(capsys):
    """Supplying only --package without --source returns 2."""
    exit_code = main(["-p", str(CLEAN_PKG)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Both --package and --source are required" in captured.err


def test_cli_nonexistent_package(capsys):
    """Nonexistent package directory produces error and returns 2."""
    exit_code = main(["-p", "nonexistent/pkg/dir", "-s", str(CLEAN_SRC)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Package path does not exist" in captured.err


def test_cli_nonexistent_source(capsys):
    """Nonexistent source directory produces error and returns 2."""
    exit_code = main(["-p", str(CLEAN_PKG), "-s", "nonexistent/src/dir"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Source path does not exist" in captured.err


def test_cli_package_is_file(tmp_path: Path, capsys):
    """File path instead of directory produces error and returns 2."""
    file_path = tmp_path / "not_a_dir.txt"
    file_path.write_text("hello")
    exit_code = main(["-p", str(file_path), "-s", str(CLEAN_SRC)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Package path is not a directory" in captured.err


def test_cli_source_is_file(tmp_path: Path, capsys):
    """File path instead of directory produces error and returns 2."""
    file_path = tmp_path / "not_a_dir.txt"
    file_path.write_text("hello")
    exit_code = main(["-p", str(CLEAN_PKG), "-s", str(file_path)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Source path is not a directory" in captured.err


def test_cli_clean_fixture_table(capsys):
    """Clean fixture returns 0 and displays Expected findings in table format."""
    exit_code = main(["-p", str(CLEAN_PKG), "-s", str(CLEAN_SRC)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Expected" in captured.out
    assert "Suspicious" not in captured.out
    assert "|" in captured.out  # Table separator


def test_cli_poisoned_fixture_table(capsys):
    """Poisoned fixture returns 1 and displays Suspicious findings in table format."""
    exit_code = main(["-p", str(POISONED_PKG), "-s", str(POISONED_SRC)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Suspicious" in captured.out
    assert "install-script" in captured.out
    assert "unknown-file" in captured.out


def test_cli_clean_fixture_json(capsys):
    """Clean fixture with --json returns 0 and valid JSON output."""
    exit_code = main(["-p", str(CLEAN_PKG), "-s", str(CLEAN_SRC), "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) > 0
    for item in data:
        assert item["status"] == "Expected"


def test_cli_poisoned_fixture_json(capsys):
    """Poisoned fixture with --json returns 1 and valid JSON with suspicious items."""
    exit_code = main(["-p", str(POISONED_PKG), "-s", str(POISONED_SRC), "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    statuses = {item["status"] for item in data}
    assert "Suspicious" in statuses
    reasons = {item["reason"] for item in data}
    assert "install-script" in reasons
    assert "unknown-file" in reasons


def test_cli_explain_flag(capsys):
    """--explain flag populates explanations on suspicious findings."""
    exit_code = main(["-p", str(POISONED_PKG), "-s", str(POISONED_SRC), "--json", "--explain"])
    assert exit_code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    suspicious_items = [item for item in data if item["status"] == "Suspicious"]
    assert len(suspicious_items) > 0
    for item in suspicious_items:
        assert "explanation" in item
        assert len(item["explanation"]) > 0


def test_cli_subprocess_help():
    """python -m pkgcheck --help executes successfully via subprocess."""
    res = subprocess.run(
        [sys.executable, "-m", "pkgcheck", "--help"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "usage:" in res.stdout.lower() or "pkgcheck" in res.stdout


def test_cli_subprocess_clean_and_poisoned():
    """python -m pkgcheck executes end-to-end on clean and poisoned fixtures."""
    # Clean fixture exits 0
    res_clean = subprocess.run(
        [
            sys.executable,
            "-m",
            "pkgcheck",
            "-p",
            str(CLEAN_PKG),
            "-s",
            str(CLEAN_SRC),
        ],
        capture_output=True,
        text=True,
    )
    assert res_clean.returncode == 0
    assert "Expected" in res_clean.stdout
    assert "Suspicious" not in res_clean.stdout

    # Poisoned fixture exits 1
    res_poisoned = subprocess.run(
        [
            sys.executable,
            "-m",
            "pkgcheck",
            "-p",
            str(POISONED_PKG),
            "-s",
            str(POISONED_SRC),
        ],
        capture_output=True,
        text=True,
    )
    assert res_poisoned.returncode == 1
    assert "Suspicious" in res_poisoned.stdout
