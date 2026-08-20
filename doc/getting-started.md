# Getting started

sshz requires [Zig 0.16.0](https://ziglang.org/download/). zlib is built from
source as a package dependency, so no system zlib installation is required.

## Library

Run the primary checks from the repository root:

```sh
zig build test
zig build malformed
zig build stress
zig build production-examples
```

The root package exports the library as `sshz`:

```zig
const sshz = @import("sshz");
```

The [production-facing API and lifecycle](api-production.md) documents the
embedding contract, ownership rules, transport pump, trust decisions, and
cleanup requirements.

## mssh client demo

`mssh` is a command-line client demo for macOS and Linux:

```sh
cd mssh
zig build
./zig-out/bin/mssh <username@host> <port> [-A|--agent-forward] [idfile]
```

Use `-A` or `--agent-forward` to forward the local SSH agent from
`SSH_AUTH_SOCK`. For non-interactive runs, `mssh` reads optional secrets from
`MSSH_AUTH_PASSWORD` and `MSSH_KEY_PASSPHRASE`.

## msshd server demo

`msshd` is a single-connection server demo:

```sh
cd msshd
zig build
./zig-out/bin/msshd <port> <hostkey>
```

For example:

```sh
./zig-out/bin/msshd 2022 ../testserver/id_ed25519_passwordless --insecure-demo-auth
ssh -p 2022 foo@127.0.0.1
```

With no authentication option, `msshd` rejects every attempt. Use
`--authorized-keys <file>` to authorize listed public keys. The explicit
`--insecure-demo-auth` mode accepts any cryptographically verified public key
or a password matching the username so the demos can be exercised locally.
These policies exercise the library's application callbacks; embedding
applications must provide their own authorization policy.

Connect the two demos with the passworded key fixture:

```sh
cd mssh
zig build run -- foo@127.0.0.1 2022 ../testserver/id_ed25519_passworded
```

The fixture key passphrase is `secretpassword`. The `testserver` directory
contains test fixtures used through runtime-only copies by the automated
interop harness.

## Next steps

- Use the fail-closed integration skeletons under
  [`examples/production/`](../examples/production/).
- Review the [resource limits](resource-limits.md) before embedding a session.
- Run the [interoperability suite](interoperability.md) against installed SSH
  peers.
