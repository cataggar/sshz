# sshz

sshz is a minimal, transport-agnostic SSH client and server library written in
Zig. Applications drive its asynchronous state machines over any reliable,
ordered byte stream.

## Features

- Client and server APIs with no internal transport I/O
- Public-key, password, keyboard-interactive, and none authentication
- Multiple channels, sessions, port forwarding, and agent forwarding
- Rekeying, delayed compression, resource limits, and deadline enforcement
- Interoperability coverage with OpenSSH, Dropbear, and libssh

The authoritative algorithm list and negotiation rules are in the
[SSH algorithm policy](doc/algorithm-policy.md).

## Quick start

sshz requires [Zig 0.16.0](https://ziglang.org/download/).

```sh
zig build test
zig build production-examples
```

See [getting started](doc/getting-started.md) for library commands and the
`mssh` and `msshd` demo programs.

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

sshz is pre-1.0, and its API may change between minor releases. The
[release checklist](doc/release-checklist.md) defines the evidence and review
required for a supported release. `mssh` and `msshd` are interoperability demos,
not deployment templates.
