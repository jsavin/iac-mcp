#!/bin/bash
# Simple test queue to prevent multiple test runs from exhausting memory
# Usage: ./tools/test-queue.sh <test-command>
# Example: ./tools/test-queue.sh "npm test"
#          ./tools/test-queue.sh "npm run test:unit"

set -e

LOCK_DIR="${TMPDIR:-/tmp}/iac-mcp-test-locks"
LOCK_FILE="$LOCK_DIR/test.lock"
QUEUE_FILE="$LOCK_DIR/test.queue"
MAX_WAIT_SECONDS=600  # 10 minutes max wait in queue
MAX_RUN_SECONDS=300   # 5 minutes max test execution time
POLL_INTERVAL=5       # Check every 5 seconds

# Create lock directory if it doesn't exist
mkdir -p "$LOCK_DIR"

# Generate unique ID for this test run
RUN_ID="$$-$(date +%s)"

# Function to clean up on exit
cleanup() {
    # Remove ourselves from queue
    if [[ -f "$QUEUE_FILE" ]]; then
        grep -v "^$RUN_ID$" "$QUEUE_FILE" > "$QUEUE_FILE.tmp" 2>/dev/null || true
        mv "$QUEUE_FILE.tmp" "$QUEUE_FILE" 2>/dev/null || true
    fi
    # Release lock if we hold it
    if [[ -f "$LOCK_FILE" ]] && [[ "$(cat "$LOCK_FILE" 2>/dev/null)" == "$RUN_ID" ]]; then
        rm -f "$LOCK_FILE"
    fi
}
trap cleanup EXIT

# Add ourselves to the queue
echo "$RUN_ID" >> "$QUEUE_FILE"

# Function to check if we're first in queue
is_first_in_queue() {
    local first=$(head -n1 "$QUEUE_FILE" 2>/dev/null)
    [[ "$first" == "$RUN_ID" ]]
}

# Function to try to acquire lock
try_acquire_lock() {
    # Check if lock exists and is held by a running process
    if [[ -f "$LOCK_FILE" ]]; then
        local holder=$(cat "$LOCK_FILE" 2>/dev/null)
        local holder_pid=$(echo "$holder" | cut -d'-' -f1)
        # Check if holding process is still alive
        if kill -0 "$holder_pid" 2>/dev/null; then
            return 1  # Lock is held by active process
        else
            # Stale lock, remove it
            rm -f "$LOCK_FILE"
        fi
    fi

    # Try to acquire lock (atomic via redirect)
    if is_first_in_queue; then
        echo "$RUN_ID" > "$LOCK_FILE"
        # Verify we got it (handle race condition)
        if [[ "$(cat "$LOCK_FILE" 2>/dev/null)" == "$RUN_ID" ]]; then
            return 0  # Got the lock
        fi
    fi
    return 1  # Failed to acquire
}

# Wait for our turn
waited=0
while ! try_acquire_lock; do
    if [[ $waited -ge $MAX_WAIT_SECONDS ]]; then
        echo "ERROR: Timed out waiting for test queue after ${MAX_WAIT_SECONDS}s" >&2
        exit 1
    fi

    # Show queue status
    queue_length=$(wc -l < "$QUEUE_FILE" 2>/dev/null | tr -d ' ')
    position=$(grep -n "^$RUN_ID$" "$QUEUE_FILE" 2>/dev/null | cut -d: -f1 || echo "?")
    holder=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")

    if [[ $((waited % 30)) -eq 0 ]]; then  # Print every 30 seconds
        echo "⏳ Waiting for test queue (position $position of $queue_length, holder: $holder)..." >&2
    fi

    sleep $POLL_INTERVAL
    waited=$((waited + POLL_INTERVAL))
done

echo "🔒 Acquired test lock (queue position was $(grep -n "^$RUN_ID$" "$QUEUE_FILE" 2>/dev/null | cut -d: -f1 || echo "1"))" >&2

# Run the actual test command with timeout to prevent deadlocks
echo "🧪 Running: $* (timeout: ${MAX_RUN_SECONDS}s)" >&2

# Use timeout command if available, otherwise run directly
if command -v timeout &> /dev/null; then
    timeout --signal=SIGTERM --kill-after=10 "$MAX_RUN_SECONDS" "$@"
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        echo "⚠️ Test timed out after ${MAX_RUN_SECONDS}s" >&2
    fi
elif command -v gtimeout &> /dev/null; then
    # macOS with coreutils installed via Homebrew
    gtimeout --signal=SIGTERM --kill-after=10 "$MAX_RUN_SECONDS" "$@"
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        echo "⚠️ Test timed out after ${MAX_RUN_SECONDS}s" >&2
    fi
else
    # Fallback: run without timeout (macOS default)
    # Note: Install coreutils via 'brew install coreutils' for timeout support
    "$@"
    exit_code=$?
fi

echo "✅ Test complete (exit code: $exit_code)" >&2
exit $exit_code
