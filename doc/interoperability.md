# Interoperability testing

The interoperability harness builds `sshz` and `sshzd`, starts isolated
localhost peers on dynamic ports, and tests both client and server behavior.

Run the required OpenSSH lanes from the repository root:

```sh
zig build interop
```

The harness requires OpenSSH client/server tools. Optional lanes cover Dropbear,
the libssh client probe, and bidirectional `russh` interoperability:

```sh
SSHZ_INTEROP_ENABLE_DROPBEAR=1 \
SSHZ_INTEROP_ENABLE_LIBSSH=1 \
SSHZ_INTEROP_ENABLE_RUSSH=1 \
zig build interop
```

Use `SSHZ_INTEROP_REQUIRE_DROPBEAR=1`,
`SSHZ_INTEROP_REQUIRE_LIBSSH=1`, or `SSHZ_INTEROP_REQUIRE_RUSSH=1` when a
missing dependency must fail the run instead of skipping that lane. Dropbear
coverage requires its client, server, key, and conversion tools plus
non-interactive privilege escalation to create and remove a dedicated local
account. The `russh` lane builds `interop/russh_probe.rs` against a local
`russh` checkout (`SSHZ_INTEROP_RUSSH_DIR`, defaulting to `../russh`) and tests
key generation, `russh` client to `sshzd`, and `sshz` client to `russh` server
across post-quantum/hybrid and classical KEX, signature, cipher, and MAC
algorithms.

## Configuration

| Variable | Purpose |
| --- | --- |
| `SSHZ_INTEROP_ARTIFACTS` | Select the artifact root. |
| `SSHZ_INTEROP_KEEP_ARTIFACTS` | Preserve a successful run's artifacts. |
| `SSHZ_INTEROP_TIMEOUT` | Set the per-operation timeout in seconds; the default is 25. |
| `SSHZ_INTEROP_USER` | Override the local username used by the fixture. |
| `SSHZ_INTEROP_KEY_PASSPHRASE` | Override the passworded key fixture passphrase. |
| `SSHZ_INTEROP_OPENSSH_PASSWORD` | Enable the OpenSSH password-auth lane for the current user. |
| `SSHZ_INTEROP_ENABLE_DROPBEAR` | Run Dropbear lanes when dependencies are available. |
| `SSHZ_INTEROP_REQUIRE_DROPBEAR` | Require Dropbear lanes and dependencies. |
| `SSHZ_INTEROP_ENABLE_LIBSSH` | Run the libssh client lane when available. |
| `SSHZ_INTEROP_REQUIRE_LIBSSH` | Require the libssh client lane and dependencies. |
| `SSHZ_INTEROP_ENABLE_RUSSH` | Run bidirectional `russh` lanes when available. |
| `SSHZ_INTEROP_REQUIRE_RUSSH` | Require bidirectional `russh` lanes and dependencies. |
| `SSHZ_INTEROP_RUSSH_DIR` | Override the path to the `russh` workspace (default `../russh`). |

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
