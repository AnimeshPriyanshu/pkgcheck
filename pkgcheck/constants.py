"""Shared constants for pkgcheck."""

import re

# Install script names to monitor
INSTALL_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
}

# JavaScript/TypeScript file extensions
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts"}

# Obfuscation detection thresholds
HUGE_LINE_THRESHOLD = 500
HEX_ESCAPE_PATTERN = re.compile(r"\\x[0-9a-fA-F]{2}")
EVAL_PATTERN = re.compile(r"\beval\s*\(")

# Build output directories
BUILD_DIRS = {"dist"}

# Build output file extensions
BUILD_EXTENSIONS = {
    ".min.js",
    ".min.css",
    ".d.ts",
    ".map",
}

# Source file extensions
SOURCE_EXTENSIONS = {".ts", ".js", ".tsx", ".jsx"}

# Executable file extensions
EXECUTABLE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".sh", ".py", ".exe", ".bin", ".ps1", ".bat", ".cmd"}