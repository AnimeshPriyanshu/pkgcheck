"""Tests for explain.py."""

import json
from unittest.mock import patch, MagicMock
from pkgcheck.models import Finding, Status
from pkgcheck.explain import (
    explain_finding,
    explain_findings,
    _build_prompt,
    _fallback_explanation,
    _call_gemma,
    FALLBACK_EXPLANATIONS,
)


class TestBuildPrompt:
    """Tests for _build_prompt helper."""

    def test_prompt_includes_all_fields(self):
        """Prompt includes file, reason, status, and snippet."""
        finding = Finding(
            file="test.js",
            status=Status.SUSPICIOUS,
            reason="obfuscation",
            snippet="eval('bad')",
        )
        prompt = _build_prompt(finding)
        assert "test.js" in prompt
        assert "obfuscation" in prompt
        assert "Suspicious" in prompt
        assert "eval('bad')" in prompt

    def test_prompt_handles_missing_snippet(self):
        """Prompt handles None snippet gracefully."""
        finding = Finding(
            file="test.js",
            status=Status.SUSPICIOUS,
            reason="unknown-file",
            snippet=None,
        )
        prompt = _build_prompt(finding)
        assert "(no snippet available)" in prompt


class TestFallbackExplanation:
    """Tests for deterministic fallback explanations."""

    def test_install_script_fallback(self):
        finding = Finding(file="package.json", status=Status.SUSPICIOUS, reason="install-script")
        result = _fallback_explanation(finding)
        assert "install lifecycle script" in result
        assert "malicious code" in result

    def test_unknown_file_fallback(self):
        finding = Finding(file="evil.js", status=Status.SUSPICIOUS, reason="unknown-file")
        result = _fallback_explanation(finding)
        assert "not in the source repository" in result

    def test_obfuscation_fallback(self):
        finding = Finding(file="bundle.js", status=Status.SUSPICIOUS, reason="obfuscation")
        result = _fallback_explanation(finding)
        assert "obfuscated code patterns" in result

    def test_build_output_fallback(self):
        finding = Finding(file="dist/app.min.js", status=Status.EXPECTED, reason="build-output")
        result = _fallback_explanation(finding)
        assert "build artifact" in result

    def test_content_diff_fallback(self):
        finding = Finding(file="index.js", status=Status.SUSPICIOUS, reason="content-diff")
        result = _fallback_explanation(finding)
        assert "contents differ" in result

    def test_missing_in_package_fallback(self):
        finding = Finding(file="README.md", status=Status.EXPECTED, reason="missing-in-package")
        result = _fallback_explanation(finding)
        assert "missing from the published package" in result

    def test_matched_fallback(self):
        finding = Finding(file="index.js", status=Status.EXPECTED, reason="matched")
        result = _fallback_explanation(finding)
        assert "identical content" in result

    def test_unknown_reason_fallback(self):
        finding = Finding(file="test.js", status=Status.SUSPICIOUS, reason="custom-reason")
        result = _fallback_explanation(finding)
        assert "custom-reason" in result


class TestCallGemma:
    """Tests for _call_gemma with mocked HTTP responses."""

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_successful_response(self, mock_urlopen):
        """Successful Gemma response returns message content."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [
                {"message": {"content": "This file is obfuscated to hide malicious behavior."}}
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = _call_gemma("test prompt")
        assert result == "This file is obfuscated to hide malicious behavior."

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_model_identifier_in_request(self, mock_urlopen):
        """Request includes correct model identifier."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": "OK"}}]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        _call_gemma("test prompt")

        # Verify the request was made with correct model
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        payload = json.loads(request.data.decode("utf-8"))
        assert payload["model"] == "google/gemma-4-e4b"

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_prompt_construction_in_request(self, mock_urlopen):
        """Request includes the constructed prompt."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": "OK"}}]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        _call_gemma("test prompt here")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        payload = json.loads(request.data.decode("utf-8"))
        assert payload["messages"][1]["content"] == "test prompt here"

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_connection_error_raises(self, mock_urlopen):
        """Connection error raises ConnectionError."""
        mock_urlopen.side_effect = ConnectionError("Connection refused")

        try:
            _call_gemma("test")
            assert False, "Should have raised ConnectionError"
        except ConnectionError:
            pass

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_timeout_raises(self, mock_urlopen):
        """Timeout raises TimeoutError."""
        mock_urlopen.side_effect = TimeoutError("Request timed out")

        try:
            _call_gemma("test")
            assert False, "Should have raised TimeoutError"
        except TimeoutError:
            pass

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_invalid_json_raises(self, mock_urlopen):
        """Invalid JSON response raises ValueError."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not valid json"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        try:
            _call_gemma("test")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_missing_choices_raises(self, mock_urlopen):
        """Response missing choices raises ValueError."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        try:
            _call_gemma("test")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_empty_content_raises(self, mock_urlopen):
        """Response with empty content raises ValueError."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": ""}}]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        try:
            _call_gemma("test")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestExplainFinding:
    """Tests for explain_finding main function."""

    def test_expected_finding_returns_empty(self):
        """EXPECTED findings return empty string (no explanation needed)."""
        finding = Finding(file="index.js", status=Status.EXPECTED, reason="matched")
        result = explain_finding(finding)
        assert result == ""

    @patch("pkgcheck.explain._call_gemma")
    def test_successful_gemma_explanation(self, mock_call):
        """Successful Gemma call returns model explanation."""
        mock_call.return_value = "This file contains obfuscated code to hide malicious logic."
        finding = Finding(file="test.js", status=Status.SUSPICIOUS, reason="obfuscation")
        result = explain_finding(finding)
        assert result == "This file contains obfuscated code to hide malicious logic."

    @patch("pkgcheck.explain._call_gemma")
    def test_connection_failure_uses_fallback(self, mock_call):
        """Connection failure falls back to deterministic explanation."""
        mock_call.side_effect = ConnectionError("LM Studio not running")
        finding = Finding(file="test.js", status=Status.SUSPICIOUS, reason="obfuscation")
        result = explain_finding(finding)
        assert "obfuscated code patterns" in result

    @patch("pkgcheck.explain._call_gemma")
    def test_timeout_falls_back(self, mock_call):
        """Timeout falls back to deterministic explanation."""
        mock_call.side_effect = TimeoutError("Request timed out")
        finding = Finding(file="test.js", status=Status.SUSPICIOUS, reason="unknown-file")
        result = explain_finding(finding)
        assert "not in the source repository" in result

    @patch("pkgcheck.explain._call_gemma")
    def test_invalid_response_falls_back(self, mock_call):
        """Invalid response falls back to deterministic explanation."""
        mock_call.side_effect = ValueError("Invalid response")
        finding = Finding(file="test.js", status=Status.SUSPICIOUS, reason="install-script")
        result = explain_finding(finding)
        assert "install lifecycle script" in result

    @patch("pkgcheck.explain._call_gemma")
    def test_empty_response_falls_back(self, mock_call):
        """Empty response falls back to deterministic explanation."""
        mock_call.side_effect = ValueError("Empty content")
        finding = Finding(file="test.js", status=Status.SUSPICIOUS, reason="content-diff")
        result = explain_finding(finding)
        assert "contents differ" in result


class TestExplainFindings:
    """Tests for explain_findings batch function."""

    def test_only_suspicious_get_explanation(self):
        """Only SUSPICIOUS findings get explanations."""
        findings = [
            Finding(file="good.js", status=Status.EXPECTED, reason="matched"),
            Finding(file="bad.js", status=Status.SUSPICIOUS, reason="obfuscation"),
        ]
        with patch("pkgcheck.explain.explain_finding", return_value="Suspicious explanation"):
            explain_findings(findings)
        assert findings[0].explanation == ""
        assert findings[1].explanation == "Suspicious explanation"

    def test_returns_same_list(self):
        """Function returns the same list for chaining."""
        findings = [Finding(file="bad.js", status=Status.SUSPICIOUS, reason="unknown-file")]
        with patch("pkgcheck.explain.explain_finding", return_value="Fallback"):
            result = explain_findings(findings)
        assert result is findings

    def test_empty_list_handled(self):
        """Empty list is handled gracefully."""
        result = explain_findings([])
        assert result == []


class TestReasoningContentNotExposed:
    """Ensure reasoning_content from LM Studio is never exposed."""

    @patch("pkgcheck.explain.urllib.request.urlopen")
    def test_reasoning_content_ignored(self, mock_urlopen):
        """If LM Studio returns reasoning_content, it is not included in output."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{
                "message": {
                    "content": "Safe explanation.",
                    "reasoning_content": "Internal chain of thought that should not be exposed."
                }
            }]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = _call_gemma("test prompt")
        assert result == "Safe explanation."
        assert "reasoning_content" not in result
        assert "chain of thought" not in result