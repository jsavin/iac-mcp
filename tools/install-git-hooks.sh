#!/bin/bash
#
# Install git hooks for iac-mcp
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

echo "Installing git hooks..."

# Copy pre-commit hook
cp "${SCRIPT_DIR}/hooks/pre-commit" "${GIT_HOOKS_DIR}/pre-commit"
chmod +x "${GIT_HOOKS_DIR}/pre-commit"

echo "✓ Git hooks installed successfully!"
echo
echo "Installed hooks:"
echo "  - pre-commit: TypeScript compilation, linting, tests"
