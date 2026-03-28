#!/usr/bin/env bash
# Setup git hooks for slip development
# Run this once after cloning the repo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="$SCRIPT_DIR/.githooks"

echo "Setting up git hooks..."

# Make hooks executable
chmod +x "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-push"

# Configure git to use .githooks directory
git config core.hooksPath .githooks

echo "✅ Git hooks installed!"
echo ""
echo "Pre-commit: runs cargo fmt --check and cargo clippy"
echo "Pre-push:   runs cargo test"
echo ""
echo "To bypass hooks temporarily, use:"
echo "  git commit --no-verify"
echo "  git push --no-verify"
