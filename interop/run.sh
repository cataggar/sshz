#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${MSSH_INTEROP_ARTIFACTS:-$(mktemp -d "${TMPDIR:-/tmp}/misshod-interop.XXXXXX")}"
KEEP_ARTIFACTS="${MSSH_INTEROP_KEEP_ARTIFACTS:-}"
TIMEOUT="${MSSH_INTEROP_TIMEOUT:-25}"

PIDS=()

log() {
    printf '==> %s\n' "$*"
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [[ -n "$KEEP_ARTIFACTS" || "$status" -ne 0 ]]; then
        printf 'interop artifacts: %s\n' "$WORK" >&2
    else
        rm -rf "$WORK"
    fi

    exit "$status"
}
trap cleanup EXIT

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

pick_port() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
    else
        printf '%d\n' "$((30000 + (RANDOM % 20000)))"
    fi
}

wait_for_ssh() {
    local port="$1"
    local pid="$2"
    local log_file="$3"
    local scan_file="$WORK/ssh-keyscan-${port}.out"

    for _ in $(seq 1 80); do
        if ssh-keyscan -T 1 -t ed25519 -p "$port" 127.0.0.1 >"$scan_file" 2>/dev/null && [[ -s "$scan_file" ]]; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            sed -n '1,160p' "$log_file" >&2 || true
            fail "SSH peer on port $port exited before becoming ready"
        fi
        sleep 0.25
    done

    sed -n '1,160p' "$log_file" >&2 || true
    fail "timed out waiting for SSH peer on port $port"
}

wait_for_log() {
    local pid="$1"
    local log_file="$2"
    local text="$3"

    for _ in $(seq 1 80); do
        if grep -Fq "$text" "$log_file" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            sed -n '1,160p' "$log_file" >&2 || true
            fail "process exited before writing readiness log: $text"
        fi
        sleep 0.25
    done

    sed -n '1,160p' "$log_file" >&2 || true
    fail "timed out waiting for readiness log: $text"
}

wait_with_timeout() {
    local pid="$1"
    local timeout="$2"
    local watchdog status
    status=0

    (
        sleep "$timeout"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    ) &
    watchdog=$!

    wait "$pid" || status=$?
    kill "$watchdog" 2>/dev/null || true
    wait "$watchdog" 2>/dev/null || true

    if [[ "$status" -eq 143 || "$status" -eq 137 ]]; then
        return 124
    fi
    return "$status"
}

run_capture() {
    local timeout="$1"
    local out_file="$2"
    local err_file="$3"
    shift 3

    "$@" >"$out_file" 2>"$err_file" &
    local pid=$!
    wait_with_timeout "$pid" "$timeout"
}

run_mssh_command() {
    local timeout="$1"
    local out_file="$2"
    local err_file="$3"
    local command="$4"
    shift 4

    (
        if [[ -n "$command" ]]; then
            printf '%s\nexit\n' "$command"
        fi | "$@"
    ) >"$out_file" 2>"$err_file" &
    local pid=$!
    wait_with_timeout "$pid" "$timeout"
}

assert_contains() {
    local file="$1"
    local text="$2"
    grep -Fq "$text" "$file" || {
        printf 'expected %s to contain: %s\n' "$file" "$text" >&2
        sed -n '1,160p' "$file" >&2 || true
        return 1
    }
}

assert_matches() {
    local file="$1"
    local pattern="$2"
    grep -Eq "$pattern" "$file" || {
        printf 'expected %s to match: %s\n' "$file" "$pattern" >&2
        sed -n '1,200p' "$file" >&2 || true
        return 1
    }
}

require_cmd zig
require_cmd ssh
require_cmd sshd
require_cmd ssh-keygen
require_cmd ssh-keyscan

mkdir -p "$WORK"

SSHD_BIN="$(command -v sshd)"
SSH_BIN="$(command -v ssh)"
USER_NAME="${MSSH_INTEROP_USER:-$(id -un)}"
HOST="127.0.0.1"
KEY_PASSWORDLESS="$ROOT/testserver/id_ed25519_passwordless"
KEY_ENCRYPTED="$ROOT/testserver/id_ed25519_passworded"
KEY_PASSPHRASE="${MSSH_INTEROP_KEY_PASSPHRASE:-secretpassword}"
OPENSSH_PASSWORD="${MSSH_INTEROP_OPENSSH_PASSWORD:-}"

log "building mssh and msshd"
(cd "$ROOT/mssh" && zig build)
(cd "$ROOT/msshd" && zig build)

MSSH_BIN="$ROOT/mssh/zig-out/bin/mssh"
MSSHD_BIN="$ROOT/msshd/zig-out/bin/msshd"
[[ -x "$MSSH_BIN" ]] || fail "missing built mssh binary"
[[ -x "$MSSHD_BIN" ]] || fail "missing built msshd binary"

log "starting isolated OpenSSH sshd"
OPENSSH_DIR="$WORK/openssh-sshd"
mkdir -p "$OPENSSH_DIR"
chmod 700 "$OPENSSH_DIR"
ssh-keygen -q -t ed25519 -N '' -f "$OPENSSH_DIR/ssh_host_ed25519_key"
cat "$KEY_PASSWORDLESS.pub" "$KEY_ENCRYPTED.pub" >"$OPENSSH_DIR/authorized_keys"
chmod 600 "$OPENSSH_DIR/authorized_keys"

OPENSSH_PORT="$(pick_port)"
OPENSSH_PASSWORD_AUTH="no"
if [[ -n "$OPENSSH_PASSWORD" ]]; then
    OPENSSH_PASSWORD_AUTH="yes"
fi

cat >"$OPENSSH_DIR/sshd_config" <<EOF
Port $OPENSSH_PORT
ListenAddress $HOST
Protocol 2
HostKey $OPENSSH_DIR/ssh_host_ed25519_key
PidFile $OPENSSH_DIR/sshd.pid
AuthorizedKeysFile $OPENSSH_DIR/authorized_keys
AllowUsers $USER_NAME
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication $OPENSSH_PASSWORD_AUTH
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no
PermitTTY yes
PrintMotd no
PrintLastLog no
ForceCommand printf misshod-openssh-forced
LogLevel DEBUG3
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519
Ciphers aes256-ctr
MACs hmac-sha2-256
Subsystem sftp internal-sftp
EOF

"$SSHD_BIN" -t -f "$OPENSSH_DIR/sshd_config" >"$OPENSSH_DIR/config-test.out" 2>"$OPENSSH_DIR/config-test.err" || {
    sed -n '1,120p' "$OPENSSH_DIR/config-test.err" >&2 || true
    fail "OpenSSH sshd rejected generated config"
}
"$SSHD_BIN" -D -e -f "$OPENSSH_DIR/sshd_config" >"$OPENSSH_DIR/sshd.out" 2>"$OPENSSH_DIR/sshd.err" &
OPENSSH_SSHD_PID=$!
PIDS+=("$OPENSSH_SSHD_PID")
wait_for_ssh "$OPENSSH_PORT" "$OPENSSH_SSHD_PID" "$OPENSSH_DIR/sshd.err"

log "testing mssh pubkey auth against OpenSSH sshd"
run_mssh_command "$TIMEOUT" "$WORK/mssh-openssh-pubkey.out" "$WORK/mssh-openssh-pubkey.err" \
    '' \
    "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT" "$KEY_PASSWORDLESS"
assert_contains "$WORK/mssh-openssh-pubkey.out" "misshod-openssh-forced"
assert_contains "$WORK/mssh-openssh-pubkey.err" "Connected!"

log "testing mssh encrypted-key auth against OpenSSH sshd"
run_mssh_command "$TIMEOUT" "$WORK/mssh-openssh-encrypted-key.out" "$WORK/mssh-openssh-encrypted-key.err" \
    '' \
    env MSSH_KEY_PASSPHRASE="$KEY_PASSPHRASE" \
    "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT" "$KEY_ENCRYPTED"
assert_contains "$WORK/mssh-openssh-encrypted-key.out" "misshod-openssh-forced"

if [[ -n "$OPENSSH_PASSWORD" ]]; then
    log "testing mssh password auth against OpenSSH sshd"
    run_mssh_command "$TIMEOUT" "$WORK/mssh-openssh-password.out" "$WORK/mssh-openssh-password.err" \
        '' \
        env MSSH_AUTH_PASSWORD="$OPENSSH_PASSWORD" \
        "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT"
    assert_contains "$WORK/mssh-openssh-password.out" "misshod-openssh-forced"
else
    log "skipping OpenSSH password-auth lane; set MSSH_INTEROP_OPENSSH_PASSWORD to enable it for the current user"
fi

log "testing mssh auth failure against OpenSSH sshd"
if run_mssh_command "$TIMEOUT" "$WORK/mssh-openssh-auth-failure.out" "$WORK/mssh-openssh-auth-failure.err" \
    '' \
    env MSSH_AUTH_PASSWORD="definitely-not-the-password" \
    "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT"; then
    fail "mssh auth-failure case unexpectedly succeeded"
fi
assert_contains "$WORK/mssh-openssh-auth-failure.err" "AuthFailure"

log "starting msshd"
MSSHD_PORT="$(pick_port)"
"$MSSHD_BIN" "$MSSHD_PORT" "$KEY_PASSWORDLESS" >"$WORK/msshd.out" 2>"$WORK/msshd.err" &
MSSHD_PID=$!
PIDS+=("$MSSHD_PID")
wait_for_log "$MSSHD_PID" "$WORK/msshd.err" "Server listening on port $MSSHD_PORT"

OPENSSH_CLIENT_KEY="$WORK/openssh-client-id_ed25519"
cp "$KEY_PASSWORDLESS" "$OPENSSH_CLIENT_KEY"
chmod 600 "$OPENSSH_CLIENT_KEY"

SSH_COMMON=(
    -F none
    -p "$MSSHD_PORT"
    -o "BatchMode=yes"
    -o "ConnectTimeout=5"
    -o "ConnectionAttempts=1"
    -o "ServerAliveInterval=1"
    -o "ServerAliveCountMax=5"
    -o "StrictHostKeyChecking=no"
    -o "UserKnownHostsFile=$WORK/known_hosts"
    -o "GlobalKnownHostsFile=/dev/null"
    -o "IdentitiesOnly=yes"
    -o "KexAlgorithms=curve25519-sha256"
    -o "HostKeyAlgorithms=ssh-ed25519"
    -o "PubkeyAcceptedAlgorithms=ssh-ed25519"
    -o "Ciphers=aes256-ctr"
    -o "MACs=hmac-sha2-256"
    -i "$OPENSSH_CLIENT_KEY"
)

run_openssh_client_to_msshd() {
    local out_file="$1"
    local err_file="$2"
    shift 2

    (
        {
            printf 'misshod-openssh-client\n'
            sleep 1
        } | "$SSH_BIN" "$@" "${SSH_COMMON[@]}" "interop@$HOST"
    ) >"$out_file" 2>"$err_file" &
    local pid=$!

    for _ in $(seq 1 "$((TIMEOUT * 4))"); do
        if grep -Fq "You said 'misshod-openssh-client" "$out_file" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            return $?
        fi
        sleep 0.25
    done

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 124
}

log "testing OpenSSH ssh client against msshd"
run_openssh_client_to_msshd "$WORK/openssh-msshd.out" "$WORK/openssh-msshd.err" -vvv
assert_contains "$WORK/openssh-msshd.out" "You said 'misshod-openssh-client"

log "checking OpenSSH negotiated algorithms against msshd"
assert_matches "$WORK/openssh-msshd.err" "kex: algorithm: curve25519-sha256"
assert_matches "$WORK/openssh-msshd.err" "host key algorithm: ssh-ed25519"
assert_matches "$WORK/openssh-msshd.err" "cipher: aes256-ctr.*MAC: hmac-sha2-256"

if [[ "${MSSH_INTEROP_ENABLE_LIBSSH:-}" == "1" || "${MSSH_INTEROP_REQUIRE_LIBSSH:-}" == "1" ]]; then
    if ! pkg-config --exists libssh 2>/dev/null; then
        fail "pkg-config could not find libssh"
    fi

    log "testing libssh client against msshd"
    cc "$ROOT/interop/libssh_probe.c" -o "$WORK/libssh_probe" $(pkg-config --cflags --libs libssh)
    if ! run_capture "$TIMEOUT" "$WORK/libssh-msshd.out" "$WORK/libssh-msshd.err" \
        "$WORK/libssh_probe" "$HOST" "$MSSHD_PORT" "interop" "interop"
    then
        sed -n '1,160p' "$WORK/libssh-msshd.err" >&2 || true
        fail "libssh probe failed"
    fi
    assert_contains "$WORK/libssh-msshd.out" "You said 'misshod-libssh-probe"
else
    log "skipping libssh lane; set MSSH_INTEROP_ENABLE_LIBSSH=1 to run it or MSSH_INTEROP_REQUIRE_LIBSSH=1 to require it"
fi

log "interop tests passed"
