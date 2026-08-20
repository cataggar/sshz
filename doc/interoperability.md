# Interoperability testing

The interoperability harness builds `mssh` and `msshd`, starts isolated
localhost peers on dynamic ports, and tests both client and server behavior.

Run the required OpenSSH lanes from the repository root:

```sh
zig build interop
```

The harness requires OpenSSH client/server tools. Optional lanes cover Dropbear
and the libssh client probe:

```sh
MSSH_INTEROP_ENABLE_DROPBEAR=1 \
MSSH_INTEROP_ENABLE_LIBSSH=1 \
zig build interop
```

Use `MSSH_INTEROP_REQUIRE_DROPBEAR=1` or
`MSSH_INTEROP_REQUIRE_LIBSSH=1` when a missing dependency must fail the run
instead of skipping that lane. Dropbear coverage requires its client, server,
key, and conversion tools plus non-interactive privilege escalation to create
and remove a dedicated local account.

## Configuration

| Variable | Purpose |
| --- | --- |
| `MSSH_INTEROP_ARTIFACTS` | Select the artifact root. |
| `MSSH_INTEROP_KEEP_ARTIFACTS` | Preserve a successful run's artifacts. |
| `MSSH_INTEROP_TIMEOUT` | Set the per-operation timeout in seconds; the default is 25. |
| `MSSH_INTEROP_USER` | Override the local username used by the fixture. |
| `MSSH_INTEROP_KEY_PASSPHRASE` | Override the passworded key fixture passphrase. |
| `MSSH_INTEROP_OPENSSH_PASSWORD` | Enable the OpenSSH password-auth lane for the current user. |
| `MSSH_INTEROP_ENABLE_DROPBEAR` | Run Dropbear lanes when dependencies are available. |
| `MSSH_INTEROP_REQUIRE_DROPBEAR` | Require Dropbear lanes and dependencies. |
| `MSSH_INTEROP_ENABLE_LIBSSH` | Run the libssh client lane when available. |
| `MSSH_INTEROP_REQUIRE_LIBSSH` | Require the libssh client lane and dependencies. |

The harness also supports tool-specific Dropbear binary overrides defined in
[`interop/run.sh`](../interop/run.sh).

## Artifact safety

Runtime directories can contain generated or copied private fixture material.
Only the harness's `logs/` subtree is approved for CI upload. Do not upload the
complete artifact root, environment dumps, command traces, or runtime/private
directories.

CI requires OpenSSH, Dropbear, and libssh coverage on Linux. Scheduled
duration-based peer coverage is documented in
[stress and soak testing](stress-and-soak.md).
