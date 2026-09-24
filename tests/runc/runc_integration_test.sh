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
# Kill stale processes holding the old binary before copying; they run as
# root, so fuser needs sudo. Refuse to go on with anything but a fresh copy:
# testing a stale binary silently is worse than failing.
if ! cp "$RUNTIME" "$RUNC_DIR/runc" 2>/dev/null; then
    sudo fuser -k -KILL "$RUNC_DIR/runc" 2>/dev/null || true
    sleep 0.5
    cp "$RUNTIME" "$RUNC_DIR/runc"
fi
if ! cmp -s "$RUNTIME" "$RUNC_DIR/runc"; then
    echo "error: could not copy $RUNTIME to $RUNC_DIR/runc" >&2
    exit 1
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
    # A runtime left hanging by a timed-out test survives the timeout (it is
    # not in the killed process group once bats is gone) and keeps the
    # binary busy; kill whatever still executes it.
    sudo fuser -k -KILL "$RUNC_DIR/runc" >/dev/null 2>&1 || true
    sudo rm -f /tmp/takoyaki-*.sock 2>/dev/null || true
    sudo rm -rf /run/takoyaki/* 2>/dev/null || true
    # Remove leftover dummy network devices (netdev.bats).
    sudo ip link del dev dummy0 2>/dev/null || true
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

# All descendants of a pid, the pid itself first.
descendants() {
    local c
    echo "$1"
    for c in $(ps -o pid= --ppid "$1" 2>/dev/null); do
        descendants "$c"
    done
}

# Print what every process under $1 is doing, for a bats run that is about
# to hit its timeout: per-thread state, wait channel, current syscall and
# kernel stack, and each process's open fds. Once timeout kills the run
# there is nothing left to look at.
dump_hang_diagnostics() {
    local p t exe
    echo "  --- hang diagnostics ($fname, $(date -u +%T)) ---"
    for p in $(descendants "$1"); do
        [[ -d /proc/$p ]] || continue
        exe=$(sudo readlink "/proc/$p/exe")
        echo "  [pid $p ppid $(ps -o ppid= -p "$p" | tr -d ' ')] exe=$exe"
        echo "    cmd: $(sudo cat "/proc/$p/cmdline" 2>/dev/null | tr '\0' ' ' | cut -c1-300)"
        # The test harness itself (sudo, timeout, script, bats' shells) only
        # gets the lines above; the runtime and container processes get the
        # per-thread detail.
        case "${exe##*/}" in
            sudo|timeout|script|bash|cat) continue ;;
        esac
        for t in /proc/"$p"/task/*; do
            echo "    tid ${t##*/} comm=$(cat "$t/comm" 2>/dev/null) state=$(awk '{print $3}' "$t/stat" 2>/dev/null)" \
                "wchan=$(cat "$t/wchan" 2>/dev/null) syscall=$(sudo cat "$t/syscall" 2>/dev/null | cut -d' ' -f1-4)"
            sudo cat "$t/stack" 2>/dev/null | head -12 | sed 's/^/        /'
        done
        echo "    fds: $(sudo ls -l "/proc/$p/fd" 2>/dev/null | awk 'NR > 1 {print $9 "->" $11}' | tr '\n' ' ' | cut -c1-800)"
    done
    echo "  --- end hang diagnostics ---"
}

# ── Build per-file filter regexes from the pattern file ──────────────
#
# 1. Map every @test declaration to its .bats file(s). A few names exist
#    in more than one file (e.g. "runc run"); such a name runs in each.
# 2. Read the pattern file; skip [skip] lines and repeated names; look up
#    each enabled test name in the map and group it under its file(s).
# 3. Result: FILE_FILTER[file] = "^test1$|^test2$|..." and
#    FILE_NAMES[file] = the names, one per line.

declare -A NAME_TO_FILES
while IFS= read -r mapping; do
    file="${mapping%%	*}"
    tname="${mapping#*	}"
    # Trim trailing whitespace (some bats tests have names like 'name " {').
    tname="${tname%"${tname##*[! ]}"}"
    NAME_TO_FILES["$tname"]+="$file"$'\n'
done < <(grep -rH '@test "' tests/integration/*.bats \
    | sed -n 's/^\(.*\.bats\):.*@test "\(.*\)" {.*$/\1\t\2/p')

declare -A FILE_FILTER
declare -A FILE_TEST_COUNT
declare -A FILE_NAMES
declare -A SEEN_NAMES

while IFS= read -r name; do
    [[ -z "$name" || "$name" == \#* ]] && continue

    if [[ $name =~ ^\[skip\] ]]; then
        SKIP=$((SKIP + 1))
        continue
    fi

    if [[ -n "${SEEN_NAMES[$name]:-}" ]]; then
        echo "WARN: test listed twice in the pattern file: $name" >&2
        continue
    fi
    SEEN_NAMES[$name]=1

    files="${NAME_TO_FILES[$name]:-}"
    if [[ -z "$files" ]]; then
        echo "WARN: test not found in any .bats file: $name" >&2
        continue
    fi

    escaped=$(escape_ere "$name")
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        # Use " *$" instead of "$" to tolerate trailing spaces in bats
        # test names (some runc tests have names like 'name " {').
        if [[ -z "${FILE_FILTER[$file]:-}" ]]; then
            FILE_FILTER[$file]="^${escaped} *$"
            FILE_TEST_COUNT[$file]=1
        else
            FILE_FILTER[$file]="${FILE_FILTER[$file]}|^${escaped} *$"
            FILE_TEST_COUNT[$file]=$(( ${FILE_TEST_COUNT[$file]} + 1 ))
        fi
        FILE_NAMES[$file]+="$name"$'\n'
    done <<< "$files"
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

    # Scale timeout by test count. GitHub arm runners are ~20x slower
    # for mount/idmap operations, so use 60s/test on aarch64 vs 30s on
    # x86_64. Floor 180s either way.
    if [[ "$(uname -m)" == "aarch64" ]]; then
        timeout_secs=$(( expected * 60 ))
    else
        timeout_secs=$(( expected * 30 ))
    fi
    (( timeout_secs < 180 )) && timeout_secs=180

    echo "=== [$FILE_INDEX/$FILE_TOTAL] $fname ($expected tests, ${timeout_secs}s) ==="

    TMPOUT=$(mktemp)

    # Pass the filter via an environment variable to avoid quoting
    # issues with apostrophes, $, and | in test names and regex.
    # A watchdog records hang diagnostics shortly before the timeout.
    run_bats() {
        local bats_pid watchdog rc
        sudo -E PATH="$PATH" _BATS_FILTER="$filter" \
            timeout "$timeout_secs" script -q -e -c \
            'exec bats -f "$_BATS_FILTER" -t '"$file" /dev/null > "$TMPOUT" 2>&1 <&0 &
        bats_pid=$!
        (
            sleep $(( timeout_secs - 10 ))
            kill -0 "$bats_pid" 2>/dev/null && dump_hang_diagnostics "$bats_pid"
        ) &
        watchdog=$!
        wait "$bats_pid"
        rc=$?
        kill "$watchdog" 2>/dev/null
        wait "$watchdog" 2>/dev/null
        return $rc
    }

    # Use script(1) for a PTY (needed for console-socket tests in CI).
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
    declare -A reported=()
    while IFS= read -r line; do
        # script(1) runs bats on a PTY, so lines end in CR LF.
        line="${line%$'\r'}"
        if [[ "$line" =~ ^ok\ [0-9]+\ (.+) ]]; then
            tname="${BASH_REMATCH[1]}"
            if [[ "$tname" =~ \#\ skip ]]; then
                # bats-internal skip (e.g. "requires root")
                tname="${tname%% \# skip*}"
                echo "  SKIP  $tname"
            else
                file_pass=$((file_pass + 1))
                echo "  PASS  $tname"
            fi
            reported["${tname%"${tname##*[! ]}"}"]=1
        elif [[ "$line" =~ ^not\ ok\ [0-9]+\ (.+) ]]; then
            tname="${BASH_REMATCH[1]}"
            reported["${tname%"${tname##*[! ]}"}"]=1
            file_fail=$((file_fail + 1))
            echo "  FAIL  $tname"
            ERRORS="${ERRORS}\n  - $tname"
            in_fail=1
        elif [[ ${in_fail:-0} -eq 1 && "$line" =~ ^#\  ]]; then
            # TAP diagnostic lines (comments) following a failed test
            echo "        ${line#\# }"
        else
            in_fail=0
        fi
    done < "$TMPOUT"

    # A test with no result at all (bats crashed, or the run hung and was
    # killed by timeout even after the retry) is a failure too.
    while IFS= read -r tname; do
        [[ -z "$tname" || -n "${reported[$tname]:-}" ]] && continue
        file_fail=$((file_fail + 1))
        echo "  FAIL  $tname (no result, bats rc=$rc)"
        ERRORS="${ERRORS}\n  - $tname (no result, $fname rc=$rc)"
    done <<< "${FILE_NAMES[$file]}"
    unset reported

    # Dump full bats output for failing test files to aid CI debugging.
    if [[ $file_fail -gt 0 ]]; then
        echo "  --- full bats output ($fname) ---"
        cat "$TMPOUT"
        echo "  --- end ---"
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
