"""Smoke tests for pkgcheck."""

from pkgcheck.cli import main


def test_main_returns_zero():
    """Test that main() runs and returns exit code 0."""
    assert main() == 0