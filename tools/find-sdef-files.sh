#!/bin/bash
#
# Find all SDEF files on the system
# Useful for discovering scriptable applications during development
#

set -euo pipefail

echo "Searching for SDEF files..."
echo

echo "=== System Applications ==="
find /System/Library/CoreServices -name "*.sdef" 2>/dev/null || true

echo
echo "=== User Applications ==="
find /Applications -name "*.sdef" 2>/dev/null || true

echo
echo "=== Home Applications ==="
find ~/Applications -name "*.sdef" 2>/dev/null || true

echo
echo "Done!"
