# MiSSHod

*misshod. (ˌmɪsˈʃɒd). adj. badly shod*

# About

MiSSHod is a minimal, experimental SSH client and server implemented as a library.

It has been tested with both [OpenSSH](https://github.com/openssh/openssh-portable) and [Dropbear](https://github.com/mkj/dropbear).

**MiSSHod is not secure, it should not be used in real world systems**

It aims to be:

 - Transport and I/O agnostic - TCP would be normal, but MiSShod can be run over any reliable stream protocol
 - Asynchronous - MiSShod never blocks execution for I/O, it enters a wait state and can be resumed when data arrives
 - Callback free - asynchronous message passing prevents the caller needing callbacks and context structs
 - Very lightweight, opening up the possibility of running on small embedded devices

**Features**

 - Public key auth
 - Password auth
 - Supports a focused set of SSH transport algorithms
    - hmac-sha2-256 (hmac)
    - curve25519-sha256 (key exchange)
    - ssh-ed25519 (key)
    - aes256-ctr (cipher)
    - zlib@openssh.com (delayed compression)

# Building

MiSSHod requires [Zig 0.16.0](https://ziglang.org/download/) and system zlib.

## Client

To build `mssh`, a command line SSH client for Mac/Linux

```bash
zig build test
```

```bash
cd mssh
zig build
./zig-out/bin/mssh
./zig-out/bin/mssh <username@host> <port> [-A|--agent-forward] [idfile]
```

Use `-A` or `--agent-forward` to forward the local SSH agent from `SSH_AUTH_SOCK`.

The old manual Dropbear container has been retired. The `testserver` directory
now only contains key fixtures used through runtime-only copies by the automated
interop harness described below.

For non-interactive runs, `mssh` reads optional secrets from `MSSH_AUTH_PASSWORD` and `MSSH_KEY_PASSPHRASE`.

## Server

`msshd` is a toy ssh server. It handles one connection at a time and echoes back received data with "You said X".

To build `msshd`

```bash
cd msshd
zig build
./zig-out/bin/msshd
./zig-out/bin/msshd <port> <hostkey>
```

To run the server

```bash
./zig-out/bin/msshd 2022 ../testserver/id_ed25519_passwordless
Server listening on port 2022
```

Connect using OpenSSH

```bash
ssh -p 2022 foo@127.0.0.1
```

By default the server will accept any public key offered. Typically, OpenSSH offers all available keys, so it will be able to login immediately. This can be changed in `msshd/src/main.zig`. Typically, a real server would check the user's `authorized_keys` file.

Connect using `mssh` using pubkey auth (key password is "secretpassword")

```bash
cd mssh
zig build run -- foo@127.0.0.1 2022 ../testserver/id_ed25519_passworded
```

Connect using `mssh` using password auth (any password matching username will be accepted, so "foo" here)

```bash
cd mssh
zig build run -- foo@127.0.0.1 2022
```

## Interop tests

Run the OpenSSH interoperability suite from the repository root:

```bash
zig build interop
```

The runner builds `mssh` and `msshd`, starts isolated localhost peers on dynamic
ports, and keeps runtime secrets separate from upload-safe logs. It always checks
OpenSSH, and can additionally check both directions with Dropbear and the libssh
client probe. Set `MSSH_INTEROP_ENABLE_DROPBEAR=1` or
`MSSH_INTEROP_ENABLE_LIBSSH=1` to enable those installed dependencies. Use the
corresponding `MSSH_INTEROP_REQUIRE_DROPBEAR=1` or
`MSSH_INTEROP_REQUIRE_LIBSSH=1` in required lanes, and
`MSSH_INTEROP_KEEP_ARTIFACTS=1` to keep local artifacts. The Dropbear lane needs
non-interactive `sudo` so it can create and remove a dedicated local account;
CI installs Ubuntu's `dropbear-bin` package and requires the lane.


# Tiny client example

As a proof of concept, the `tiny` example logs into the test server but contains no socket code. Instead, it uses stdout and stdin. To run it via `socat`:

```bash
zig build && socat TCP4:127.0.0.1:2022 EXEC:./zig-out/bin/tiny
```

Tiny uses a weaker PRNG, a fixed buffer allocator and does no file I/O.

# Security

**MiSSHod is not secure, it should not be used in real world systems**

The [production-facing API and lifecycle contract](doc/api-production.md)
documents the client/server pump, borrowed data, mandatory trust decisions,
channel lifecycle, cleanup, and pre-1.0 compatibility policy. Compile-check the
separate fail-closed [client](examples/production/client.zig) and
[server](examples/production/server.zig) integration skeletons with
`zig build production-examples`. They are guidance, not production-readiness
claims. The [release checklist and platform matrix](doc/release-checklist.md)
defines the evidence required before such a claim.

The [production threat model](doc/threat-model.md) documents the library's
assets, trust boundaries, current mitigations, and explicit release blockers.
The [SSH algorithm policy](doc/algorithm-policy.md) separates the current
allowlist and enforcement from the algorithm work still required for release.
The `mssh`, `msshd`, and `tiny` programs are insecure examples or demos, not
production SSH clients or servers.

- Deterministic malformed, stress, soak, and peer-interoperability coverage is
  substantial but is not a substitute for coverage-guided fuzzing or
  independent review.
- Timing-sensitive paths have received targeted hardening, not a complete
  side-channel audit.
- Secret copies and lifetimes have been reduced and documented, but compiler,
  allocator, dependency, crash-dump, and application copies remain outside
  complete library control.
- MiSSHod relies on Zig's still-young standard-library cryptography and system
  zlib; release dependencies and independent vectors are not yet fully pinned.
- No independent cryptographic or protocol security review has occurred.

# Status

MiSSHod was developed rapidly as a small SSH implementation. Its pre-1.0 API,
security evidence, supported-platform matrix, and independent review are not
yet sufficient for production use.
