#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 1 ]]; then
    printf 'error: missing stress driver path\n' >&2
    exit 2
fi

STRESS_BIN="$1"
shift
DURATION_SECONDS=900
SEED_TEXT="1751547392"
PEER="internal"

usage() {
    cat >&2 <<'EOF'
usage: zig build soak -Doptimize=ReleaseSafe -- \
  [--duration-seconds 900] [--seed 1751547392] \
  [--peer internal|openssh|dropbear|libssh|all]
EOF
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --duration-seconds)
            [[ "$#" -ge 2 ]] || { usage; exit 2; }
            DURATION_SECONDS="$2"
            shift 2
            ;;
        --seed)
            [[ "$#" -ge 2 ]] || { usage; exit 2; }
            SEED_TEXT="$2"
            shift 2
            ;;
        --peer)
            [[ "$#" -ge 2 ]] || { usage; exit 2; }
            PEER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown soak argument: %s\n' "$1" >&2
            usage
            exit 2
            ;;
    esac
done

[[ "$DURATION_SECONDS" =~ ^[1-9][0-9]*$ ]] || {
    printf 'error: duration must be a positive integer\n' >&2
    exit 2
}
[[ "$SEED_TEXT" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] || {
    printf 'error: seed must be an unsigned decimal or hexadecimal integer\n' >&2
    exit 2
}
case "$PEER" in
    internal|openssh|dropbear|libssh|all) ;;
    *)
        printf 'error: unsupported peer: %s\n' "$PEER" >&2
        exit 2
        ;;
esac
[[ -x "$STRESS_BIN" ]] || {
    printf 'error: stress driver is not executable: %s\n' "$STRESS_BIN" >&2
    exit 2
}

if [[ "$SEED_TEXT" == 0[xX]* ]]; then
    SEED=$((16#${SEED_TEXT:2}))
else
    SEED=$((10#$SEED_TEXT))
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT_ROOT="${SSHZ_SOAK_ARTIFACTS:-$ROOT/.zig-cache/sshz-soak}"
mkdir -p "$ARTIFACT_ROOT"

started="$(date +%s)"
iteration=0

resource_heartbeat() {
    local now elapsed rss_kib fd_count
    local -a fd_paths
    now="$(date +%s)"
    elapsed="$((now - started))"
    rss_kib="unavailable"
    fd_count="unavailable"
    if [[ -r "/proc/$$/status" ]]; then
        rss_kib="$(awk '$1 == "VmHWM:" { print $2 }' "/proc/$$/status")"
    fi
    if [[ -d "/proc/$$/fd" ]]; then
        fd_paths=("/proc/$$/fd/"*)
        fd_count="${#fd_paths[@]}"
    fi
    printf 'soak heartbeat peer=%s iteration=%d elapsed_seconds=%d shell_peak_rss_kib=%s shell_fd_count=%s\n' \
        "$PEER" "$iteration" "$elapsed" "${rss_kib:-unavailable}" "$fd_count"
}

run_measured() {
    local label="$1"
    shift
    if [[ -x /usr/bin/time ]]; then
        /usr/bin/time -f "resource label=$label elapsed_seconds=%e max_rss_kib=%M exit=%x" "$@"
    else
        "$@"
    fi
}

run_internal() {
    local iteration_seed="$1"
    run_measured internal-stress "$STRESS_BIN" --seed "$iteration_seed"
}

run_peer() {
    local iteration_seed="$1"
    local peer_artifacts="$ARTIFACT_ROOT/${PEER}-${iteration}-${iteration_seed}"
    local -a env_args=(
        "MSSH_INTEROP_ARTIFACTS=$peer_artifacts"
        "MSSH_INTEROP_TIMEOUT=30"
    )
    case "$PEER" in
        openssh) ;;
        dropbear) env_args+=("MSSH_INTEROP_REQUIRE_DROPBEAR=1") ;;
        libssh) env_args+=("MSSH_INTEROP_REQUIRE_LIBSSH=1") ;;
        all)
            env_args+=(
                "MSSH_INTEROP_REQUIRE_DROPBEAR=1"
                "MSSH_INTEROP_REQUIRE_LIBSSH=1"
            )
            ;;
        internal) return ;;
    esac
    run_measured "interop-$PEER" env "${env_args[@]}" bash "$ROOT/interop/run.sh"
}

printf 'sshz soak seed=%s duration_seconds=%s peer=%s\n' "$SEED" "$DURATION_SECONDS" "$PEER"
printf 'rerun: zig build soak -Doptimize=ReleaseSafe -- --duration-seconds %s --seed %s --peer %s\n' \
    "$DURATION_SECONDS" "$SEED" "$PEER"
printf 'artifacts: only */logs directories are safe for CI upload\n'

while :; do
    now="$(date +%s)"
    elapsed="$((now - started))"
    if [[ "$iteration" -gt 0 && "$elapsed" -ge "$DURATION_SECONDS" ]]; then
        break
    fi

    iteration_seed="$(( (SEED + iteration * 6364136223846793005) & 0x7fffffffffffffff ))"
    if [[ "$PEER" == "internal" || "$iteration" -eq 0 ]]; then
        run_internal "$iteration_seed"
    fi
    run_peer "$iteration_seed"
    iteration="$((iteration + 1))"
    resource_heartbeat
done

elapsed="$(( $(date +%s) - started ))"
printf 'soak PASS seed=%s peer=%s iterations=%d elapsed_seconds=%d\n' \
    "$SEED" "$PEER" "$iteration" "$elapsed"
