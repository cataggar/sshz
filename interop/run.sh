#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${MSSH_INTEROP_ARTIFACTS:-}" ]]; then
    WORK="$MSSH_INTEROP_ARTIFACTS"
else
    mkdir -p "$ROOT/.zig-cache"
    WORK="$(mktemp -d "$ROOT/.zig-cache/misshod-interop.XXXXXX")"
fi
KEEP_ARTIFACTS="${MSSH_INTEROP_KEEP_ARTIFACTS:-}"
TIMEOUT="${MSSH_INTEROP_TIMEOUT:-25}"
LOG_DIR="$WORK/logs"
RUNTIME_DIR="$WORK/runtime"
PRIVATE_DIR="$RUNTIME_DIR/private"

PIDS=()
ROOT_CMD=()
DROPBEAR_USER=""
DROPBEAR_USER_CREATED=0
DROPBEAR_LAUNCH_PID=""
DROPBEAR_PID_FILE=""
DROPBEAR_HOME=""

log() {
    printf '==> %s\n' "$*"
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    local dropbear_pid=""

    if [[ -n "$DROPBEAR_LAUNCH_PID" ]] &&
        kill -0 "$DROPBEAR_LAUNCH_PID" 2>/dev/null &&
        [[ -r "$DROPBEAR_PID_FILE" ]]; then
        dropbear_pid="$(cat "$DROPBEAR_PID_FILE" 2>/dev/null || true)"
        if [[ "$dropbear_pid" =~ ^[0-9]+$ ]]; then
            "${ROOT_CMD[@]}" kill "$dropbear_pid" 2>/dev/null || true
        fi
    fi

    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [[ "$DROPBEAR_USER_CREATED" == "1" ]]; then
        "${ROOT_CMD[@]}" chown -R "$(id -u):$(id -g)" "$DROPBEAR_HOME" >/dev/null 2>&1 || true
        "${ROOT_CMD[@]}" "$USERDEL_BIN" "$DROPBEAR_USER" >/dev/null 2>&1 || {
            printf 'warning: could not remove Dropbear interop account %s\n' "$DROPBEAR_USER" >&2
        }
    fi
    if [[ "$DROPBEAR_HOME" == /tmp/misshod-dropbear-home.* ]]; then
        rm -rf -- "$DROPBEAR_HOME"
    fi

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
    local scan_file="$RUNTIME_DIR/ssh-keyscan-${port}.out"

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

assert_not_contains() {
    local file="$1"
    local text="$2"
    if grep -Fq "$text" "$file"; then
        printf 'expected %s not to contain: %s\n' "$file" "$text" >&2
        sed -n '1,160p' "$file" >&2 || true
        return 1
    fi
}

require_cmd zig
require_cmd ssh
require_cmd sshd
require_cmd ssh-keygen
require_cmd ssh-keyscan

mkdir -p "$LOG_DIR" "$RUNTIME_DIR" "$PRIVATE_DIR"
chmod 700 "$LOG_DIR" "$PRIVATE_DIR"

SSHD_BIN="$(command -v sshd)"
SSH_BIN="$(command -v ssh)"
USER_NAME="${MSSH_INTEROP_USER:-$(id -un)}"
HOST="127.0.0.1"
KEY_PASSWORDLESS="$PRIVATE_DIR/id_ed25519_passwordless"
KEY_ENCRYPTED="$PRIVATE_DIR/id_ed25519_passworded"
KEY_PASSPHRASE="${MSSH_INTEROP_KEY_PASSPHRASE:-secretpassword}"
OPENSSH_PASSWORD="${MSSH_INTEROP_OPENSSH_PASSWORD:-}"

cp "$ROOT/testserver/id_ed25519_passwordless" "$KEY_PASSWORDLESS"
cp "$ROOT/testserver/id_ed25519_passworded" "$KEY_ENCRYPTED"
chmod 600 "$KEY_PASSWORDLESS" "$KEY_ENCRYPTED"
ssh-keygen -y -f "$KEY_PASSWORDLESS" >"$KEY_PASSWORDLESS.pub"
ssh-keygen -y -P "$KEY_PASSPHRASE" -f "$KEY_ENCRYPTED" >"$KEY_ENCRYPTED.pub"

log "building mssh and msshd"
(cd "$ROOT/mssh" && zig build)
(cd "$ROOT/msshd" && zig build)

MSSH_BIN="$ROOT/mssh/zig-out/bin/mssh"
MSSHD_BIN="$ROOT/msshd/zig-out/bin/msshd"
[[ -x "$MSSH_BIN" ]] || fail "missing built mssh binary"
[[ -x "$MSSHD_BIN" ]] || fail "missing built msshd binary"

log "starting isolated OpenSSH sshd"
OPENSSH_DIR="$RUNTIME_DIR/openssh-sshd"
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

"$SSHD_BIN" -t -f "$OPENSSH_DIR/sshd_config" >"$LOG_DIR/openssh-config-test.out" 2>"$LOG_DIR/openssh-config-test.err" || {
    sed -n '1,120p' "$LOG_DIR/openssh-config-test.err" >&2 || true
    fail "OpenSSH sshd rejected generated config"
}
"$SSHD_BIN" -D -e -f "$OPENSSH_DIR/sshd_config" >"$LOG_DIR/openssh-sshd.out" 2>"$LOG_DIR/openssh-sshd.err" &
OPENSSH_SSHD_PID=$!
PIDS+=("$OPENSSH_SSHD_PID")
wait_for_ssh "$OPENSSH_PORT" "$OPENSSH_SSHD_PID" "$LOG_DIR/openssh-sshd.err"

log "testing mssh pubkey auth against OpenSSH sshd"
run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-openssh-pubkey.out" "$LOG_DIR/mssh-openssh-pubkey.err" \
    '' \
    "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT" --insecure-demo "$KEY_PASSWORDLESS"
assert_contains "$LOG_DIR/mssh-openssh-pubkey.out" "misshod-openssh-forced"
assert_contains "$LOG_DIR/mssh-openssh-pubkey.err" "Connected!"

log "testing mssh encrypted-key auth against OpenSSH sshd"
run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-openssh-encrypted-key.out" "$LOG_DIR/mssh-openssh-encrypted-key.err" \
    '' \
    env MSSH_KEY_PASSPHRASE="$KEY_PASSPHRASE" \
    "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT" --insecure-demo "$KEY_ENCRYPTED"
assert_contains "$LOG_DIR/mssh-openssh-encrypted-key.out" "misshod-openssh-forced"

if [[ -n "$OPENSSH_PASSWORD" ]]; then
    log "testing mssh password auth against OpenSSH sshd"
    run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-openssh-password.out" "$LOG_DIR/mssh-openssh-password.err" \
        '' \
        env MSSH_AUTH_PASSWORD="$OPENSSH_PASSWORD" \
        "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT" --insecure-demo
    assert_contains "$LOG_DIR/mssh-openssh-password.out" "misshod-openssh-forced"
else
    log "skipping OpenSSH password-auth lane; set MSSH_INTEROP_OPENSSH_PASSWORD to enable it for the current user"
fi

log "testing mssh auth failure against OpenSSH sshd"
if run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-openssh-auth-failure.out" "$LOG_DIR/mssh-openssh-auth-failure.err" \
    '' \
    env MSSH_AUTH_PASSWORD="definitely-not-the-password" \
    "$MSSH_BIN" "$USER_NAME@$HOST" "$OPENSSH_PORT" --insecure-demo; then
    fail "mssh auth-failure case unexpectedly succeeded"
fi
assert_contains "$LOG_DIR/mssh-openssh-auth-failure.err" "AuthFailure"

if [[ "${MSSH_INTEROP_ENABLE_DROPBEAR:-}" == "1" || "${MSSH_INTEROP_REQUIRE_DROPBEAR:-}" == "1" ]]; then
    DROPBEAR_BIN="${MSSH_INTEROP_DROPBEAR_BIN:-$(command -v dropbear || true)}"
    DROPBEARKEY_BIN="${MSSH_INTEROP_DROPBEARKEY_BIN:-$(command -v dropbearkey || true)}"
    DBCLIENT_BIN="${MSSH_INTEROP_DBCLIENT_BIN:-$(command -v dbclient || true)}"
    DROPBEARCONVERT_BIN="${MSSH_INTEROP_DROPBEARCONVERT_BIN:-$(command -v dropbearconvert || true)}"
    USERADD_BIN="$(command -v useradd || true)"
    USERDEL_BIN="$(command -v userdel || true)"

    missing_dropbear_commands=()
    [[ -n "$DROPBEAR_BIN" && -x "$DROPBEAR_BIN" ]] || missing_dropbear_commands+=(dropbear)
    [[ -n "$DROPBEARKEY_BIN" && -x "$DROPBEARKEY_BIN" ]] || missing_dropbear_commands+=(dropbearkey)
    [[ -n "$DBCLIENT_BIN" && -x "$DBCLIENT_BIN" ]] || missing_dropbear_commands+=(dbclient)
    [[ -n "$DROPBEARCONVERT_BIN" && -x "$DROPBEARCONVERT_BIN" ]] || missing_dropbear_commands+=(dropbearconvert)
    [[ -n "$USERADD_BIN" && -x "$USERADD_BIN" ]] || missing_dropbear_commands+=(useradd)
    [[ -n "$USERDEL_BIN" && -x "$USERDEL_BIN" ]] || missing_dropbear_commands+=(userdel)

    if [[ "${#missing_dropbear_commands[@]}" -ne 0 ]]; then
        if [[ "${MSSH_INTEROP_REQUIRE_DROPBEAR:-}" == "1" ]]; then
            fail "required Dropbear lane is missing commands: ${missing_dropbear_commands[*]}"
        fi
        log "skipping Dropbear lane; missing commands: ${missing_dropbear_commands[*]}"
    else
        if [[ "$(id -u)" -ne 0 ]]; then
            if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then
                if [[ "${MSSH_INTEROP_REQUIRE_DROPBEAR:-}" == "1" ]]; then
                    fail "required Dropbear lane needs non-interactive sudo to create its isolated account"
                fi
                log "skipping Dropbear lane; non-interactive sudo is unavailable"
                DROPBEAR_BIN=""
            else
                ROOT_CMD=(sudo -n)
            fi
        fi
    fi

    if [[ -n "$DROPBEAR_BIN" && "${#missing_dropbear_commands[@]}" -eq 0 ]]; then
        DROPBEAR_DIR="$RUNTIME_DIR/dropbear"
        DROPBEAR_HOME="$(mktemp -d /tmp/misshod-dropbear-home.XXXXXX)"
        DROPBEAR_PID_FILE="$DROPBEAR_DIR/dropbear.pid"
        DROPBEAR_HOST_KEY="$DROPBEAR_DIR/dropbear_ed25519_host_key"
        DROPBEAR_AUTHORIZED_KEYS="$DROPBEAR_HOME/.ssh/authorized_keys"
        DROPBEAR_BANNER="$DROPBEAR_DIR/banner"
        DROPBEAR_REJECTED_KEY="$PRIVATE_DIR/dropbear-rejected-id_ed25519"
        DROPBEAR_CLIENT_KEY="$PRIVATE_DIR/dropbear-client-id_ed25519"
        DROPBEAR_PORT="$(pick_port)"
        DROPBEAR_USER="msshdi$$"
        while id "$DROPBEAR_USER" >/dev/null 2>&1; do
            DROPBEAR_USER="msshdi$RANDOM"
        done
        mkdir -p "$DROPBEAR_DIR" "$DROPBEAR_HOME/.ssh"
        mkdir -p "$DROPBEAR_HOME/.ssh"
        chmod 700 "$DROPBEAR_DIR"
        chmod 700 "$DROPBEAR_HOME" "$DROPBEAR_HOME/.ssh"
        ssh-keygen -y -f "$KEY_PASSWORDLESS" >"$DROPBEAR_AUTHORIZED_KEYS"
        ssh-keygen -y -P "$KEY_PASSPHRASE" -f "$KEY_ENCRYPTED" >>"$DROPBEAR_AUTHORIZED_KEYS"
        chmod 600 "$DROPBEAR_AUTHORIZED_KEYS"
        printf '%s\n' "misshod-dropbear-auth-banner" >"$DROPBEAR_BANNER"
        "$DROPBEARKEY_BIN" -t ed25519 -f "$DROPBEAR_HOST_KEY" \
            >"$LOG_DIR/dropbear-host-key.out" 2>"$LOG_DIR/dropbear-host-key.err"
        ssh-keygen -q -t ed25519 -N '' -f "$DROPBEAR_REJECTED_KEY"
        chmod 600 "$DROPBEAR_REJECTED_KEY"

        {
            "$DROPBEAR_BIN" -V
            "$DBCLIENT_BIN" -V
            printf 'dropbearkey=%s\n' "$DROPBEARKEY_BIN"
            printf 'dropbearconvert=%s\n' "$DROPBEARCONVERT_BIN"
        } >"$LOG_DIR/dropbear-versions.txt" 2>&1

        cat >"$LOG_DIR/dropbear-config.txt" <<EOF
listen=$HOST:$DROPBEAR_PORT
user=$DROPBEAR_USER
host_key_type=ed25519
password_auth=disabled
root_login=disabled
banner=misshod-dropbear-auth-banner
authorized_fixture_keys=passwordless-ed25519,encrypted-ed25519
EOF

        "${ROOT_CMD[@]}" "$USERADD_BIN" --home-dir "$DROPBEAR_HOME" --shell /bin/sh \
            --no-create-home --user-group "$DROPBEAR_USER"
        DROPBEAR_USER_CREATED=1
        "${ROOT_CMD[@]}" chown -R "$DROPBEAR_USER:$DROPBEAR_USER" "$DROPBEAR_HOME"

        log "starting isolated Dropbear server"
        "${ROOT_CMD[@]}" "$DROPBEAR_BIN" -F -E -s -w \
            -P "$DROPBEAR_PID_FILE" \
            -r "$DROPBEAR_HOST_KEY" \
            -p "$HOST:$DROPBEAR_PORT" \
            -b "$DROPBEAR_BANNER" \
            >"$LOG_DIR/dropbear-server.out" 2>"$LOG_DIR/dropbear-server.err" &
        DROPBEAR_LAUNCH_PID=$!
        PIDS+=("$DROPBEAR_LAUNCH_PID")
        wait_for_ssh "$DROPBEAR_PORT" "$DROPBEAR_LAUNCH_PID" "$LOG_DIR/dropbear-server.err"

        log "testing mssh passwordless Ed25519 auth and shell data against Dropbear"
        run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-dropbear-pubkey.out" "$LOG_DIR/mssh-dropbear-pubkey.err" \
            "printf 'misshod-dropbear-shell:%s\\n' 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'" \
            "$MSSH_BIN" "$DROPBEAR_USER@$HOST" "$DROPBEAR_PORT" --insecure-demo "$KEY_PASSWORDLESS"
        assert_contains "$LOG_DIR/mssh-dropbear-pubkey.out" \
            "misshod-dropbear-shell:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        assert_contains "$LOG_DIR/mssh-dropbear-pubkey.err" "misshod-dropbear-auth-banner"
        assert_contains "$LOG_DIR/mssh-dropbear-pubkey.err" "Connected!"

        log "testing mssh encrypted Ed25519 key auth against Dropbear"
        run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-dropbear-encrypted-key.out" "$LOG_DIR/mssh-dropbear-encrypted-key.err" \
            "printf 'misshod-dropbear-encrypted-key\\n'" \
            env MSSH_KEY_PASSPHRASE="$KEY_PASSPHRASE" \
            "$MSSH_BIN" "$DROPBEAR_USER@$HOST" "$DROPBEAR_PORT" --insecure-demo "$KEY_ENCRYPTED"
        assert_contains "$LOG_DIR/mssh-dropbear-encrypted-key.out" "misshod-dropbear-encrypted-key"
        assert_contains "$LOG_DIR/mssh-dropbear-encrypted-key.err" "Connected!"

        log "testing mssh auth rejection against Dropbear"
        if run_mssh_command "$TIMEOUT" "$LOG_DIR/mssh-dropbear-auth-failure.out" "$LOG_DIR/mssh-dropbear-auth-failure.err" \
            '' \
            "$MSSH_BIN" "$DROPBEAR_USER@$HOST" "$DROPBEAR_PORT" --insecure-demo "$DROPBEAR_REJECTED_KEY"; then
            fail "mssh Dropbear auth-failure case unexpectedly succeeded"
        fi
        assert_contains "$LOG_DIR/mssh-dropbear-auth-failure.err" "AuthFailure"
        assert_not_contains "$LOG_DIR/mssh-dropbear-auth-failure.err" "Connected!"

        log "converting fixture key for Dropbear dbclient"
        if ! run_capture "$TIMEOUT" "$LOG_DIR/dropbearconvert.out" "$LOG_DIR/dropbearconvert.err" \
            "$DROPBEARCONVERT_BIN" openssh dropbear "$KEY_PASSWORDLESS" "$DROPBEAR_CLIENT_KEY"
        then
            sed -n '1,160p' "$LOG_DIR/dropbearconvert.err" >&2 || true
            fail "Dropbear tooling could not convert the passwordless Ed25519 fixture"
        fi
        chmod 600 "$DROPBEAR_CLIENT_KEY"
    fi
else
    log "skipping Dropbear lane; set MSSH_INTEROP_ENABLE_DROPBEAR=1 to run it or MSSH_INTEROP_REQUIRE_DROPBEAR=1 to require it"
fi

log "starting msshd"
MSSHD_PORT="$(pick_port)"
"$MSSHD_BIN" "$MSSHD_PORT" "$KEY_PASSWORDLESS" --insecure-demo-auth >"$LOG_DIR/msshd.out" 2>"$LOG_DIR/msshd.err" &
MSSHD_PID=$!
PIDS+=("$MSSHD_PID")
wait_for_log "$MSSHD_PID" "$LOG_DIR/msshd.err" "Server listening on port $MSSHD_PORT"

OPENSSH_CLIENT_KEY="$RUNTIME_DIR/openssh-client-id_ed25519"
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
    -o "UserKnownHostsFile=$RUNTIME_DIR/known_hosts"
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
run_openssh_client_to_msshd "$LOG_DIR/openssh-msshd.out" "$LOG_DIR/openssh-msshd.err" -vvv
assert_contains "$LOG_DIR/openssh-msshd.out" "You said 'misshod-openssh-client"

log "checking OpenSSH negotiated algorithms against msshd"
assert_matches "$LOG_DIR/openssh-msshd.err" "kex: algorithm: curve25519-sha256"
assert_matches "$LOG_DIR/openssh-msshd.err" "host key algorithm: ssh-ed25519"
assert_matches "$LOG_DIR/openssh-msshd.err" "cipher: aes256-ctr.*MAC: hmac-sha2-256"

if [[ -n "${DROPBEAR_CLIENT_KEY:-}" ]]; then
    log "testing Dropbear dbclient data and clean close against msshd"
    (
        printf '%s\n' "misshod-dropbear-dbclient:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" |
            "$DBCLIENT_BIN" -y -y -T -p "$MSSHD_PORT" -i "$DROPBEAR_CLIENT_KEY" "interop@$HOST"
    ) >"$LOG_DIR/dropbear-dbclient-msshd.out" 2>"$LOG_DIR/dropbear-dbclient-msshd.err" &
    DBCLIENT_PID=$!
    if ! wait_with_timeout "$DBCLIENT_PID" "$TIMEOUT"; then
        sed -n '1,160p' "$LOG_DIR/dropbear-dbclient-msshd.err" >&2 || true
        sed -n '1,160p' "$LOG_DIR/msshd.err" >&2 || true
        fail "Dropbear dbclient failed or did not close cleanly"
    fi
    assert_contains "$LOG_DIR/dropbear-dbclient-msshd.out" \
        "You said 'misshod-dropbear-dbclient:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
fi

if [[ "${MSSH_INTEROP_ENABLE_LIBSSH:-}" == "1" || "${MSSH_INTEROP_REQUIRE_LIBSSH:-}" == "1" ]]; then
    require_cmd cc
    require_cmd pkg-config
    if ! pkg-config --exists libssh 2>/dev/null; then
        fail "pkg-config could not find libssh"
    fi

    log "testing libssh client against msshd"
    if ! run_capture "$TIMEOUT" "$LOG_DIR/libssh-compile.out" "$LOG_DIR/libssh-compile.err" \
        cc "$ROOT/interop/libssh_probe.c" -o "$RUNTIME_DIR/libssh_probe" \
        $(pkg-config --cflags --libs libssh)
    then
        sed -n '1,160p' "$LOG_DIR/libssh-compile.err" >&2 || true
        fail "libssh probe compilation failed"
    fi
    if ! run_capture "$TIMEOUT" "$LOG_DIR/libssh-msshd.out" "$LOG_DIR/libssh-msshd.err" \
        "$RUNTIME_DIR/libssh_probe" "$HOST" "$MSSHD_PORT" "interop" "$KEY_PASSWORDLESS"
    then
        sed -n '1,160p' "$LOG_DIR/libssh-msshd.err" >&2 || true
        sed -n '1,160p' "$LOG_DIR/msshd.err" >&2 || true
        fail "libssh probe failed"
    fi
    assert_contains "$LOG_DIR/libssh-msshd.out" "You said 'misshod-libssh-probe"
    assert_contains "$LOG_DIR/libssh-msshd.out" \
        "negotiated kex=curve25519-sha256 hostkey=ssh-ed25519 cipher-in=aes256-ctr cipher-out=aes256-ctr hmac-in=hmac-sha2-256 hmac-out=hmac-sha2-256"
else
    log "skipping libssh lane; set MSSH_INTEROP_ENABLE_LIBSSH=1 to run it or MSSH_INTEROP_REQUIRE_LIBSSH=1 to require it"
fi

log "interop tests passed"
