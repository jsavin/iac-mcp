#!/bin/bash
#
# Test JXA execution with a simple command
# Usage: ./tools/test-jxa.sh [app-name]
#

set -euo pipefail

APP_NAME="${1:-Finder}"

echo "Testing JXA execution with ${APP_NAME}..."
echo

# Test basic JXA execution
osascript -l JavaScript -e "Application('${APP_NAME}').name()"

echo
echo "JXA test successful!"
