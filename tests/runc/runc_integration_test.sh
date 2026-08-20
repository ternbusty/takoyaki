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
# Kill stale processes holding the old binary before copying.
if ! cp "$RUNTIME" "$RUNC_DIR/runc" 2>/dev/null; then
    fuser -k "$RUNC_DIR/runc" 2>/dev/null || true
    sleep 0.5
    cp "$RUNTIME" "$RUNC_DIR/runc"
fi
chmod +x "$RUNC_DIR/runc"

cd "$RUNC_DIR" || exit 1

# Ubuntu 24.04 sets kernel.apparmor_restrict_unprivileged_userns=1. Without
# an AppArmor profile that allows "userns," the kernel grants zero
# capabilities inside user namespaces created by processes lacking
# CAP_SYS_ADMIN. The system ships /etc/apparmor.d/runc with the rule.
# Rewrite the path to match the copied binary, just as runc's own CI does.
if [ -f /etc/apparmor.d/runc ]; then
    sed "s;^profile runc /usr/sbin/runc;profile takoyaki-test $PWD/runc;" \
        < /etc/apparmor.d/runc | sudo apparmor_parser -r 2>/dev/null || true
fi

# Build runc's Go test helper binaries (recvtty, seccompagent, etc.)
sudo make test-binaries

PASS=0
FAIL=0
SKIP=0
ERRORS=""

# Clean up stale state left by timed-out or crashed tests.
cleanup_stale_state() {
    sudo rm -f /tmp/takoyaki-*.sock 2>/dev/null || true
    sudo rm -rf /run/takoyaki/* 2>/dev/null || true
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
}

# Escape ERE special characters for bats -f regex.
escape_ere() {
    sed 's/[][\\.*^$()|+?{}]/\\&/g' <<< "$1"
}

# ── Build per-file filter regexes from the pattern file ──────────────
#
# 1. Map every @test declaration to its .bats file.
# 2. Read the pattern file; skip [skip] lines; look up each enabled
#    test name in the map and group it under its file.
# 3. Result: FILE_FILTER[file] = "^test1$|^test2$|..."

declare -A NAME_TO_FILE
while IFS= read -r mapping; do
    file="${mapping%%	*}"
    tname="${mapping#*	}"
    # Trim trailing whitespace (some bats tests have names like 'name " {').
    tname="${tname%"${tname##*[! ]}"}"
    NAME_TO_FILE["$tname"]="$file"
done < <(grep -rH '@test "' tests/integration/*.bats \
    | sed -n 's/^\(.*\.bats\):.*@test "\(.*\)" {.*$/\1\t\2/p')

declare -A FILE_FILTER
declare -A FILE_TEST_COUNT

while IFS= read -r name; do
    [[ -z "$name" || "$name" == \#* ]] && continue

    if [[ $name =~ ^\[skip\] ]]; then
        SKIP=$((SKIP + 1))
        continue
    fi

    file="${NAME_TO_FILE[$name]:-}"
    if [[ -z "$file" ]]; then
        echo "WARN: test not found in any .bats file: $name" >&2
        continue
    fi

    escaped=$(escape_ere "$name")
    # Use " *$" instead of "$" to tolerate trailing spaces in bats
    # test names (some runc tests have names like 'name " {').
    if [[ -z "${FILE_FILTER[$file]:-}" ]]; then
        FILE_FILTER[$file]="^${escaped} *$"
        FILE_TEST_COUNT[$file]=1
    else
        FILE_FILTER[$file]="${FILE_FILTER[$file]}|^${escaped} *$"
        FILE_TEST_COUNT[$file]=$(( ${FILE_TEST_COUNT[$file]} + 1 ))
    fi
done < "$PATTERN_FILE"

echo ">>> Running tests from ${#FILE_FILTER[@]} bats files (${SKIP} skipped)"
echo ""

# ── Run bats per file ────────────────────────────────────────────────
FILE_INDEX=0
FILE_TOTAL=${#FILE_FILTER[@]}

for file in $(printf '%s\n' "${!FILE_FILTER[@]}" | sort); do
    FILE_INDEX=$((FILE_INDEX + 1))
    filter="${FILE_FILTER[$file]}"
    fname=$(basename "$file")
    expected=${FILE_TEST_COUNT[$file]}

    echo "=== [$FILE_INDEX/$FILE_TOTAL] $fname ($expected tests) ==="

    TMPOUT=$(mktemp)

    # Pass the filter via an environment variable to avoid quoting
    # issues with apostrophes, $, and | in test names and regex.
    run_bats() {
        sudo -E PATH="$PATH" _BATS_FILTER="$filter" \
            timeout 300 script -q -e -c \
            'exec bats -f "$_BATS_FILTER" -t '"$file" /dev/null > "$TMPOUT" 2>&1
    }

    # Use script(1) for a PTY (needed for console-socket tests in CI).
    # Per-file timeout of 300s.
    run_bats
    rc=$?

    # Retry once on timeout.
    if [[ $rc -eq 124 ]]; then
        echo "  TIMEOUT ($fname), retrying..."
        cleanup_stale_state
        run_bats
        rc=$?
    fi

    # Parse TAP output for individual results.
    file_pass=0
    file_fail=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^ok\ [0-9]+\ (.+) ]]; then
            tname="${BASH_REMATCH[1]}"
            if [[ "$tname" =~ \#\ skip ]]; then
                # bats-internal skip (e.g. "requires root")
                echo "  SKIP  ${tname%% \# skip*}"
            else
                file_pass=$((file_pass + 1))
                echo "  PASS  $tname"
            fi
        elif [[ "$line" =~ ^not\ ok\ [0-9]+\ (.+) ]]; then
            tname="${BASH_REMATCH[1]}"
            file_fail=$((file_fail + 1))
            echo "  FAIL  $tname"
            ERRORS="${ERRORS}\n  - $tname"
        fi
    done < "$TMPOUT"

    # If bats itself crashed (no TAP output at all), count as file-level failure.
    if [[ $rc -ne 0 && $file_pass -eq 0 && $file_fail -eq 0 ]]; then
        file_fail=$expected
        echo "  FAIL  $fname (bats exited with rc=$rc, no TAP output)"
        ERRORS="${ERRORS}\n  - $fname (rc=$rc)"
    fi

    PASS=$((PASS + file_pass))
    FAIL=$((FAIL + file_fail))

    rm -f "$TMPOUT"
    cleanup_stale_state
done

echo ""
echo "=== SUMMARY ==="
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\nFailing tests:$ERRORS"
    exit 1
fi
