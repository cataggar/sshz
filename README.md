# sshz

sshz is a minimal, transport-agnostic SSH client and server library written in
Zig. Applications drive its asynchronous state machines over any reliable,
ordered byte stream.

## Features

- Client and server APIs with no internal transport I/O
- Post-quantum ML-KEM hybrid KEX (`mlkem1024nistp384-sha384`, `mlkem768nistp256-sha256`, `mlkem768x25519-sha256`), Curve25519 (`curve25519-sha256`, `curve25519-sha256@libssh.org`), and NIST ECDH (`ecdh-sha2-nistp384`, `ecdh-sha2-nistp256`)
- AEAD (`aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, `aes128-gcm@openssh.com`) and AES-CTR (`aes256-ctr`, `aes192-ctr`, `aes128-ctr`) ciphers with Encrypt-then-MAC (`hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`) and Encrypt-and-MAC (`hmac-sha2-512`, `hmac-sha2-256`)
- Per-algorithm compile-time build options (`-Dsecure-algorithms=false` plus individual `-D<alg>=true` flags for custom CNSA/NIST/minimal profiles)
- Client keyboard-interactive plus client/server public-key, password, and none authentication
- Post-quantum composite ML-DSA (`ssh-mldsa87-p384`, `ssh-mldsa44-ed25519`), Ed25519, ECDSA (`nistp384`, `nistp256`), and RSA SHA-2 host keys and user-authentication signatures, with per-algorithm compile-time `-D` build flags
- Multiple channels, sessions, port forwarding, and agent forwarding
- Rekeying, delayed compression, resource limits, and deadline enforcement
- Explicit acknowledged keepalives with owned request tokens and transport-flush accounting
- Client-side cancellation of queued, unframed channel data without closing the channel
- Opt-in automatic exec acknowledgment, independent of output and command exit results
- Opt-in server PTY admission and EOF observation, manual receive credit,
  extended output, and owned exit-status/signal submission
- Interoperability coverage with OpenSSH, Dropbear, and libssh

The authoritative algorithm list and negotiation rules are in the
[SSH algorithm policy](doc/algorithm-policy.md).

## Quick start

sshz requires [Zig 0.17.0](https://ziglang.org/download/).

Zlib remains the same pinned, bundled static library. Its stream bindings are
generated with the pinned `cataggar/translate-c` 2.0.0 and GitHub Aro mirror.
Android consumers may still replace the module's single bundled-library link
and include edge with the NDK/system `z` library; header translation itself
does not require the NDK. The 0.2.1 channel/authentication contracts are unchanged.

```sh
zig build test
zig build production-examples
```

See [getting started](doc/getting-started.md) for library commands and the
`sshz` and `sshzd` demo programs.

For either role, consume-readiness counts cover only the current incremental
read. Leave coalesced following packets in the transport or your own input
buffer until requested; see the [transport pump contract](doc/api-production.md#the-transport-pump).

## Documentation

- [Production-facing API and lifecycle](doc/api-production.md)
- [Getting started and demo programs](doc/getting-started.md)
- [Interoperability testing](doc/interoperability.md)
- [Malformed-input testing](doc/malformed-inputs.md)
- [Stress and soak testing](doc/stress-and-soak.md)
- [Resource limits](doc/resource-limits.md)
- [Threat model](doc/threat-model.md)
- [Release checklist and platform matrix](doc/release-checklist.md)

## Project status

> **Security and support warning:** No independent external security review has
> occurred. sshz is pre-1.0 and unsupported for production use while the
> documented release blockers and evidence gaps remain.

The 2026-08-21 [maintainer-led security review](doc/maintainer-security-review-2026-08-21.md)
found and remediated security defects, but it is not an independent review or
production approval. The
[release checklist](doc/release-checklist.md) defines the evidence and review
required for a supported release. `sshz` and `sshzd` are interoperability demos,
not deployment templates. See [SECURITY.md](SECURITY.md) for private
vulnerability reporting.
