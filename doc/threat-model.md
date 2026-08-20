# Production threat model

## Status

This document describes the security boundary of the current sshz repository
and the work required before a supported release. Unresolved blockers are
listed below; release decisions require the evidence and review defined by the
[release checklist](release-checklist.md).

The model applies to the client and server library in `src/` when embedded in an
application. The checked-in programs are deliberately not production
implementations:

- `sshz` is an integration example. It verifies a bounded `known_hosts` file
  strictly by default, but it can read credentials from environment variables
  and offers explicitly unsafe demo host-key acceptance. Agent forwarding is
  off by default but can be enabled explicitly.
- `sshzd` is a toy, single-connection-at-a-time echo server. It rejects all
  authentication by default and can load a bounded `authorized_keys` file, but
  it also offers an explicitly unsafe demo mode that accepts every
  cryptographically valid public key and uses `password == username`.
- `testserver/` and `interop/` are test infrastructure, not deployment
  templates.

GitHub issue state is authoritative for tracked work. A link below means that
the gap is tracked; it does not mean the issue is fixed or closed. In
particular, no independent external security review has occurred. The review
requested by [#70](https://github.com/cataggar/sshz/issues/70) remains
blocked on engaging an external reviewer and pinning a signed release
candidate.

## Intended users and deployment modes

Today, sshz is intended for protocol study, testing, interoperability work,
and embedders prepared to audit the implementation. It is not intended for
production operators or end users until the [release blockers](#production-release-blockers)
are cleared.

The library implements client and server SSH sessions over an application-owned
reliable, ordered byte stream. TCP is the normal deployment, but the library is
transport- and I/O-agnostic. The embedding application:

- drives the event-based, nonblocking read/write interface;
- supplies the allocator and a cryptographically secure random source;
- loads and protects credentials and host private keys;
- accepts or terminates the client host-key check;
- makes server authentication and channel/forwarding authorization decisions;
- owns sockets, drives the library's monotonic deadlines, and enforces
  application-wide connection concurrency, file-descriptor/process budgets,
  rate limits, isolation, and cleanup.

A deployment that supplies predictable randomness, clears the host-key event
without validating an expected identity, grants authentication without a real
authorization policy, or exposes forwarding without policy is outside any
future production security claim.

## Security objectives and assets

The intended production security objectives are:

1. authenticate the server identity selected by the client application;
2. keep authentication material and channel payloads confidential from the
   network and detect modification;
3. admit a user only after both protocol proof and application authorization;
4. keep session state, channel authorization, and forwarded connections bound
   to the authenticated session;
5. reject malformed or out-of-state protocol input without panic, memory
   corruption, secret disclosure, or unbounded work;
6. bound resource use and cryptographic key lifetime.

Assets include:

- user passwords, keyboard-interactive responses, private keys, key
  passphrases, and forwarded-agent capabilities;
- server host private keys and the client's trusted host identity;
- ephemeral key-exchange secrets, session identifiers, encryption keys, MAC
  keys, and PRNG state;
- channel data, commands, terminal input/output, forwarding destinations, and
  metadata;
- authentication and authorization decisions and protocol state;
- endpoint availability, memory, CPU, file descriptors, and channel capacity.

## Trust boundaries

### Network and peer

All bytes from the transport and the SSH peer are untrusted. The network may
observe, drop, delay, duplicate, reorder, modify, and inject traffic. A peer may
be a malicious SSH implementation rather than OpenSSH, Dropbear, or libssh.
The reliable, ordered stream abstraction itself is supplied by the application.

### Library and embedding application

The library performs packet framing, algorithm negotiation, key exchange,
cryptographic verification, authentication protocol handling, and channel state
handling. It does not establish deployment policy:

- On the client, `CheckHostKey` exposes the raw host-key blob and SHA-256
  fingerprint before user authentication. The application must call
  `acceptHostKey()` or `rejectHostKey()` explicitly. Clearing the event is an
  error, rejection produces `EndSession.HostKeyRejected`, and credentials
  cannot be sent while the decision is pending.
- On the server, `UserAuth` exposes the username and presented method after
  required protocol checks. The application decides with `grantAccess`.
- Channel opens and TCP forwarding are surfaced for application acceptance or
  rejection. The application must authorize destinations and effects.

The application has access to all plaintext and in-process secrets. A bug,
unsafe callback/event decision, or compromised application defeats the library's
protections.

### Process, operating system, and dependencies

Credential files, environment variables, the SSH agent socket, allocator,
logging, crash dumps, and transport file descriptors cross from the process
into the host OS. Their permissions and lifecycle are operator
responsibilities. sshz relies on Zig standard-library cryptography and system
zlib; those implementations, the compiler, and the build/dependency chain are
trusted dependencies.

## Attacker capabilities

The model includes attackers who can:

- completely control the network path, including active man-in-the-middle
  behavior;
- run a malicious client against a server or a malicious server against a
  client;
- send arbitrary packet lengths, padding, name lists, compressed payloads,
  message sequences, channel/window values, and authentication attempts;
- repeatedly open, stall, or abandon connections and channels to consume
  resources;
- operate a legitimate but compromised remote account and request channels,
  forwarding, environment changes, or agent operations;
- measure remotely observable timing and error behavior;
- read information available to an ordinary local process under the
  deployment's OS policy, such as carelessly exposed environment variables.

The model does not assume that attackers can break the underlying cryptographic
primitives. Compromise of the sshz process, privileged OS access, malicious
build inputs, or physical/hardware attacks is outside the library's defensive
boundary.

## SSH-specific risks, current mitigations, and gaps

### Man-in-the-middle and host-key trust

The exchange hash binds both identification strings, both KEXINIT packets, the
ephemeral X25519 keys, and the server host key. The client verifies the server's
signature and exposes the host key to the application before authentication.
This prevents an unauthenticated network attacker from impersonating a server
only when the application validates that key against an independently trusted
identity.

`sshz` applies a bounded `known_hosts` policy and fails closed by default; its
unsafe behavior requires an explicit demo flag. The core API requires an
explicit accept or reject decision and exposes typed rejection. It still
delegates hostname, port, alias, trust-store, and replacement policy to the
application. Rekey does not prompt again: after signature verification, the client
compares the complete host-key blob with the initially application-approved
identity and fails with `HostKeyChanged` on any change. Remaining
production-safe host-trust and integration work is tracked by
[#65](https://github.com/cataggar/sshz/issues/65), with negotiation policy
covered by [#66](https://github.com/cataggar/sshz/issues/66).

### Authentication, credential theft, and agent forwarding

Password, keyboard-interactive, and public-key authentication are sent after
new encryption keys are installed. Public-key authentication verifies proof of
the presented private key before the server application makes its authorization
decision. These protections still rely on correct host-key validation.

The server library deliberately delegates account policy to its application.
`sshzd` now fails closed by default and can authorize complete public-key blobs
from a bounded `authorized_keys` file; its legacy unsafe behavior requires an
explicit demo flag. Per-user policy integration, configurable method
advertisement, and complete keyboard-interactive server behavior remain
unfinished. Passwords and key passphrases are copied into session memory;
`sshz` optionally obtains them from environment variables. Agent forwarding is
disabled by default in `sshz`, but enabling it gives the authenticated server
access to the local agent for the session and must be limited to trusted
servers.

The server now emits typed authorization attempts for `none`, password,
public-key, and keyboard-interactive requests. Applications resolve them with
an atomic allow/deny decision; undecided clears deny, and public-key probes
require policy approval without authenticating. The sample server defaults to
deny-all and provides a bounded `authorized_keys` policy. Review and release
evidence remain tracked by [#64](https://github.com/cataggar/sshz/issues/64).
Credential ownership, zeroization, and logging are tracked by
[#63](https://github.com/cataggar/sshz/issues/63); safe integration guidance
is tracked by [#69](https://github.com/cataggar/sshz/issues/69).

### Timing side channels

The implementation has not had a complete timing audit. Received packet HMACs
are compared with Zig's timing-safe equality primitive, but the demo password
rule uses ordinary equality and authentication failure paths may have
distinguishable work and errors. Constant-time behavior of all relevant
library and dependency operations has not been established. This remains a
production blocker tracked by
[#62](https://github.com/cataggar/sshz/issues/62).

### Algorithm negotiation and downgrade

The current transport set is intentionally narrow:

- key exchange: `curve25519-sha256`;
- encryption: `aes256-ctr`;
- MAC: `hmac-sha2-256`;
- compression: delayed `zlib@openssh.com` or `none`;
- host/public-key signatures: Ed25519, ECDSA P-256, and RSA with SHA-2,
  depending on the loaded key and role.

Negotiation requires an exact supported name and fails when there is no mutual
algorithm. Host-key signatures and the exchange hash are verified. The code
does not intentionally fall back to `ssh-rsa`, SHA-1, or an unencrypted
transport.

The [SSH algorithm policy](algorithm-policy.md) records the exhaustive
allowlist, rationale, and production requirements. `src/protocol.zig`
centralizes offer parsing, name-list validation, selection, and enforcement;
both roles use it, and selection follows the client's order independently for
each category and direction. Its remaining complete key validation,
strict-KEX decision, vectors, compression default, and dependency decisions
remain release blockers under
[#66](https://github.com/cataggar/sshz/issues/66).

### Malformed packets and state-machine attacks

Current defensive bounds include a 35,000-byte internal SSH packet limit,
bounded readers/writers, minimum padding checks, bounded decompression output,
identification-line limits, explicit state checks, and MAC/signature
verification errors. The checked-in, network-free `zig build malformed`
target runs 55 deterministic transport/parser/state cases with a 64-step,
512-byte-per-case budget and an exact expected typed outcome. Linux CI requires
it in Debug and ReleaseSafe modes; see [Malformed transport
inputs](malformed-inputs.md).

This fixed corpus covers identification, framing, padding, MAC, zlib, SSH
strings/mpints, KEX/auth ordering, algorithm-list failures, channel bounds and
state, disconnect, and the short-ECDH regression. It is useful negative
evidence, not proof of parser safety or a substitute for coverage-guided fuzzing.
The pinned Zig 0.16 fuzz runner currently cannot compile because its
`builtin.StackTrace` type is incompatible with the `debug.StackTrace` expected
by `std.debug.writeStackTrace`; the deterministic corpus is used until that
compiler defect is resolved. Broader parser/state assurance remains tracked by
[#60](https://github.com/cataggar/sshz/issues/60).

### Resource exhaustion

The client and server expose validated per-session limits for packet and
decompression sizes, identification input, channels/windows, buffered channel
data, pre-authentication work, server authentication attempts, peer-triggered
KEX, and pending global requests. Callers can drive handshake, authentication,
idle, and total deadlines with an explicit monotonic clock. Peer window and
packet violations and counter overflow fail closed. Defaults and the driving
contract are documented in [Per-session resource limits](resource-limits.md).

These controls do not enforce connection counts or application-wide
memory/CPU/file-descriptor/process budgets. Compression and cryptographic
handshakes still consume bounded but nontrivial per-session CPU, and disabled
compatibility-default deadlines require an explicit deployment policy. The
embedding application must retain network admission and operational limits.
The library portion of automatic key lifetime is implemented; application-wide
admission limits and selection/driving of a production key-age clock remain
deployment responsibilities tracked by
[#67](https://github.com/cataggar/sshz/issues/67).

### Rekey and key lifetime

Client and server use the same state machines for peer, local, and simultaneous
`KEXINIT`. Validated defaults initiate after 1 GiB or 2^30 encrypted packets in
either direction; deployments can configure stricter byte/packet limits and a
caller-clock key age. Ordinary output is gated, exact KEXINIT payloads are
retained for the exchange hash, the initial session identifier and accepted
host identity remain bound, and directional usage resets only at the matching
`NEWKEYS` activation.

AES-CTR byte position and SSH sequence increments are checked hard bounds. They
terminate with `KeyLifetimeExceeded` instead of wrapping; rekey does not
incorrectly reset the session-global SSH sequence number. Read-only diagnostics
expose epochs, usage, activation tick/age, next sequence number, and rekey state
without cryptographic material.

The per-session library work is covered by [#67](https://github.com/cataggar/sshz/issues/67).
Applications still must choose the production one-hour-equivalent tick duration,
drive `tick` regularly, enforce process-wide limits, and close terminal
transports. Broader long-running validation remains tracked by
[#68](https://github.com/cataggar/sshz/issues/68).

### Secret lifetime and diagnostics

Session-owned exchange state, derived keys, copied credentials, decoded private
keys, signatures, packet/decompression storage, and channel buffers now have
explicit ownership and scrub points on success, rejection, replacement, rekey,
terminal failure, and deinitialization. Borrowed event slices remain valid until
the caller releases the event, and raw secret/plaintext diagnostics require the
explicit unsafe trace build option. The complete contract and unavoidable
compiler, dependency, allocator, and crash-dump limits are documented in
[Sensitive data lifetimes](sensitive-data-lifetimes.md). Tracking remains under
[#63](https://github.com/cataggar/sshz/issues/63).

### Interoperability and long-lived correctness

Linux CI requires OpenSSH, Dropbear, and libssh interoperability. The libssh
probe also asserts the negotiated KEX, host-key, cipher, and MAC. The packaged
libssh on the current Azure Linux development host is locally defective; this
is an environment limitation, while the Ubuntu CI libssh implementation is
conforming and remains the required evidence lane.

Linux pull requests also require a fixed-seed ReleaseSafe stress acceptance
covering repeated sessions, four-channel scheduling, bidirectional large
transfers, window pressure, automatic rekey, and close/disconnect races. A
separate scheduled workflow runs 20-minute OpenSSH soaks twice weekly and
weekly Dropbear/libssh soaks, with manual seed/duration/peer selection. These
tests provide useful positive and long-lived evidence, but do not replace
independent review. Commands, scenarios, and artifact rules are documented in
[Stress and soak testing](stress-and-soak.md). Remaining interoperability and
soak confidence is tracked by [#58](https://github.com/cataggar/sshz/issues/58),
[#59](https://github.com/cataggar/sshz/issues/59), and
[#68](https://github.com/cataggar/sshz/issues/68).

## Accepted and out-of-scope risks

These exclusions define the intended library boundary; they do not relax the
production blockers below:

- sshz does not protect secrets after compromise of its process, allocator,
  OS kernel, privileged account, compiler, or cryptographic dependencies.
- Endpoint commands and channel data are visible to the authorized client,
  server application, and destination process. SSH does not sandbox them.
- Traffic analysis, endpoint addresses, packet timing, and gross traffic volume
  are not hidden.
- Physical attacks, hardware side channels, denial of the underlying network,
  and cryptanalytic breaks of accepted primitives are out of scope.
- The application remains responsible for multi-connection admission control,
  account policy, host-key provisioning, command sandboxing, forwarding policy,
  file permissions, secret input, and operational monitoring.
- Only implemented SSH features and the documented algorithm set are in scope;
  protocol extensions are not implicitly supported.

## Production release blockers

A release must retain the README production warning until every item below has
objective evidence and the linked tracking issue's acceptance criteria have
been satisfied. The issue links are tracking references, not claims about their
current state.

| Blocker | Required evidence | Tracking |
| --- | --- | --- |
| Parser and state-machine robustness | Retain the required deterministic malformed transport/state corpus; add usable coverage-guided fuzzing when the Zig runner is fixed; establish no peer-controlled panic, corruption, leak, or hang | [#60](https://github.com/cataggar/sshz/issues/60) |
| Timing behavior | Inventory and hardening of MAC, credential, key, signature, and failure paths | [#62](https://github.com/cataggar/sshz/issues/62) |
| Secret lifecycle | Documented ownership, minimized copies/lifetimes, verified cleanup, and diagnostics that cannot emit secrets in production | [#63](https://github.com/cataggar/sshz/issues/63) |
| Server authorization | Production application hooks and fail-closed examples/tests for every authentication method | [#64](https://github.com/cataggar/sshz/issues/64) |
| Client host identity | Fail-closed host-key validation, changed-key handling, rekey identity binding, and safe defaults/examples | [#65](https://github.com/cataggar/sshz/issues/65) |
| Algorithm policy | Reviewed policy, negative negotiation/downgrade tests, vectors, and dependency decision | [#66](https://github.com/cataggar/sshz/issues/66) |
| Resource and key-lifetime limits | Application-wide connection/FD/process admission limits and a driven production key-age policy; per-session limits, automatic local rekey, hard bounds, and key-lifetime tests are documented and enforced | [#67](https://github.com/cataggar/sshz/issues/67) |
| Interoperability and stress confidence | Retain required OpenSSH/Dropbear/libssh Linux CI, deterministic ReleaseSafe stress, and scheduled peer soaks; accumulate and review long-run evidence | [#58](https://github.com/cataggar/sshz/issues/58), [#59](https://github.com/cataggar/sshz/issues/59), [#68](https://github.com/cataggar/sshz/issues/68) |
| Safe, stable integration surface | Documented ownership/lifecycle/error semantics, compatibility policy, and separate production-oriented client/server examples | [#69](https://github.com/cataggar/sshz/issues/69) |
| Independent review | Engage an external reviewer, pin a signed RC, review transport, crypto use, authentication, channels, memory hygiene, and side channels, and leave no unresolved critical/high finding | [#70](https://github.com/cataggar/sshz/issues/70) |

This checked-in model is the concrete mitigation requested by
[#61](https://github.com/cataggar/sshz/issues/61). It must be updated when
the supported algorithms, trust boundaries, deployment modes, examples, or
release blockers change.
