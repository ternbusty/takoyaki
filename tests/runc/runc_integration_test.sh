#!/bin/bash -u
#
# Run runc's bats integration tests against the takoyaki binary.
#
# Usage:
#   ./tests/runc/runc_integration_test.sh [/path/to/takoyaki]
#
# The runc repository is expected as a git submodule at
# tests/runc/src/github.com/opencontainers/runc. If it is missing, run:
#   git submodule update --init --recursive

RUNTIME=${1:?usage: $0 /path/to/takoyaki}
ROOT=$(git rev-parse --show-toplevel)
RUNC_DIR="${ROOT}/tests/runc/src/github.com/opencontainers/runc"
PATTERN_FILE="${ROOT}/${2:-tests/runc/runc_test_pattern}"

if [[ ! -f "$RUNC_DIR/Makefile" ]]; then
    echo "error: runc submodule not found at $RUNC_DIR" >&2
    echo "run: git submodule update --init --recursive" >&2
    exit 1
fi

if [[ ! -x "$RUNTIME" ]]; then
    echo "error: $RUNTIME not found or not executable" >&2
    exit 1
fi

# Copy the takoyaki binary into the runc tree as "runc" so that
# helpers.bash's default RUNC path (../../runc relative to
# tests/integration/) resolves to it without any code changes.
cp "$RUNTIME" "$RUNC_DIR/runc"
chmod +x "$RUNC_DIR/runc"

cd "$RUNC_DIR" || exit 1

# Build runc's Go test helper binaries (recvtty, seccompagent, etc.)
sudo make test-binaries

PASS=0
FAIL=0
SKIP=0
ERRORS=""

readarray -t TEST_NAMES < "$PATTERN_FILE"

for name in "${TEST_NAMES[@]}"; do
    # Blank lines and comments
    [[ -z "$name" || "$name" == \#* ]] && continue

    # Lines prefixed with [skip] are skipped
    if [[ $name =~ ^\[skip\] ]]; then
        SKIP=$((SKIP + 1))
        echo "SKIP  $name"
        continue
    fi

    # Escape regex special characters for bats -f
    TEST_CASE=$(echo "$name" | sed \
        's/\\/\\\\/g; s/\[/\\[/g; s/\]/\\]/g; s/(/\\(/g; s/)/\\)/g; s/\./\\./g; s/\*/\\*/g; s/\+/\\+/g; s/\?/\\?/g; s/{/\\{/g; s/}/\\}/g; s/\^/\\^/g; s/\$/\\$/g; s/|/\\|/g')

    echo "--- $name ---"

    # Use script(1) to wrap bats in a pseudo-terminal, avoiding hangs
    # that occur when bats tests use the terminal for console-socket tests
    # in a non-TTY CI environment.
    # timeout(1) kills the test if it takes longer than 60 seconds,
    # preventing a single hanging test from consuming the entire CI budget.
    sudo -E PATH="$PATH" timeout 60 script -q -e -c \
        "bats -f \"^$TEST_CASE\$\" -t tests/integration" /dev/null
    rc=$?

    if [[ $rc -eq 0 ]]; then
        PASS=$((PASS + 1))
        echo "PASS  $name"
    else
        FAIL=$((FAIL + 1))
        ERRORS="${ERRORS}\n  - $name"
        echo "FAIL  $name (rc=$rc)"
    fi

    # Clean up stale notify sockets left by crashed tests. Without this,
    # the next test using the same container name would fail with
    # "Address already in use".
    sudo rm -f /tmp/takoyaki-*.sock 2>/dev/null || true

    # Clean up stale state directories.
    sudo rm -rf /run/takoyaki/* 2>/dev/null || true

    # Clean up stale cgroups left by timed-out or crashed tests. When
    # timeout(1) kills the bats process tree, teardown_bundle never runs,
    # leaving the cgroup directory (with processes) behind. The next test
    # would fail with "container's cgroup is not empty".
    for _cgdir in /sys/fs/cgroup/takoyaki/*/; do
        [ -d "$_cgdir" ] || continue
        sudo bash -c '
            echo 1 > "'"$_cgdir"'cgroup.kill" 2>/dev/null || true
            sleep 0.2
            for sub in "'"$_cgdir"'"/*/; do
                [ -d "$sub" ] || continue
                rmdir "$sub" 2>/dev/null || true
            done
            rmdir "'"$_cgdir"'" 2>/dev/null || true
        '
    done
done

echo ""
echo "=== SUMMARY ==="
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\nFailing tests:$ERRORS"
    exit 1
fi
