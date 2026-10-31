"""Tests for check_pr_models.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from scripts.check_pr_models import (
    parse_pr_body,
    is_empty_or_placeholder,
    MODELS_HEADING,
    ASSISTANTS_HEADING,
)


VALID_BODY = f"""## What this PR does

Adds a new feature.

{MODELS_HEADING}

Gemma 2B via LM Studio

{ASSISTANTS_HEADING}

opencode (nemotron-3-ultra)
"""

BODY_WITH_NONE = f"""## What this PR does

Fixes a bug.

{MODELS_HEADING}

none

{ASSISTANTS_HEADING}

none
"""

MISSING_MODELS_SECTION = f"""## What this PR does

Test.

{ASSISTANTS_HEADING}

opencode
"""

MISSING_ASSISTANTS_SECTION = f"""## What this PR does

Test.

{MODELS_HEADING}

Gemma
"""

EMPTY_MODELS_SECTION = f"""## What this PR does

Test.

{MODELS_HEADING}


{ASSISTANTS_HEADING}

opencode
"""

EMPTY_ASSISTANTS_SECTION = f"""## What this PR does

Test.

{MODELS_HEADING}

Gemma

{ASSISTANTS_HEADING}


"""

PLACEHOLDER_MODELS = f"""## What this PR does

Test.

{MODELS_HEADING}

(e.g. Gemma 2B, GPT-4)

{ASSISTANTS_HEADING}

opencode
"""

PLACEHOLDER_ASSISTANTS = f"""## What this PR does

Test.

{MODELS_HEADING}

Gemma

{ASSISTANTS_HEADING}

<!-- AI coding assistant -->
"""

HTML_COMMENT_ONLY = f"""## What this PR does

Test.

{MODELS_HEADING}

<!-- TODO: fill in models -->

{ASSISTANTS_HEADING}

opencode
"""


def test_valid_body():
    models, assistants = parse_pr_body(VALID_BODY)
    assert models == "Gemma 2B via LM Studio"
    assert assistants == "opencode (nemotron-3-ultra)"


def test_body_with_none():
    models, assistants = parse_pr_body(BODY_WITH_NONE)
    assert models == "none"
    assert assistants == "none"
    assert not is_empty_or_placeholder(models)
    assert not is_empty_or_placeholder(assistants)


def test_missing_models_section():
    with pytest.raises(ValueError, match=f'"{MODELS_HEADING}"'):
        parse_pr_body(MISSING_MODELS_SECTION)


def test_missing_assistants_section():
    with pytest.raises(ValueError, match=f'"{ASSISTANTS_HEADING}"'):
        parse_pr_body(MISSING_ASSISTANTS_SECTION)


def test_empty_models_section():
    models, assistants = parse_pr_body(EMPTY_MODELS_SECTION)
    assert models == ""
    assert is_empty_or_placeholder(models)
    assert not is_empty_or_placeholder(assistants)


def test_empty_assistants_section():
    models, assistants = parse_pr_body(EMPTY_ASSISTANTS_SECTION)
    assert assistants == ""
    assert is_empty_or_placeholder(assistants)
    assert not is_empty_or_placeholder(models)


def test_placeholder_models_section():
    models, assistants = parse_pr_body(PLACEHOLDER_MODELS)
    assert is_empty_or_placeholder(models)
    assert not is_empty_or_placeholder(assistants)


def test_placeholder_assistants_section():
    models, assistants = parse_pr_body(PLACEHOLDER_ASSISTANTS)
    assert is_empty_or_placeholder(assistants)
    assert not is_empty_or_placeholder(models)


def test_html_comment_only():
    models, assistants = parse_pr_body(HTML_COMMENT_ONLY)
    assert is_empty_or_placeholder(models)
    assert not is_empty_or_placeholder(assistants)


def test_is_empty_or_placeholder():
    assert is_empty_or_placeholder("")
    assert is_empty_or_placeholder("   ")
    assert is_empty_or_placeholder("(e.g. Gemma)")
    assert is_empty_or_placeholder("<!-- comment -->")
    assert is_empty_or_placeholder("  (e.g. test)  ")
    assert not is_empty_or_placeholder("none")
    assert not is_empty_or_placeholder("NONE")
    assert not is_empty_or_placeholder("None")
    assert not is_empty_or_placeholder("Gemma 2B")
    assert not is_empty_or_placeholder("opencode")