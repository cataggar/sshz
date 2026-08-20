# External security review package

## Status and use

This package prepares an external review of a pinned sshz release candidate.
It is a scope and evidence request, not evidence that a reviewer has been
engaged, that a review has finished, or that any finding or approval exists.
sshz remains experimental and is not suitable for production use.
No independent external review has occurred. The work in
[issue #70](https://github.com/cataggar/sshz/issues/70) remains blocked on
engaging an external reviewer and creating the signed, pinned release candidate
required by this package.

Reviewers and maintainers should use:

- [review checklist](review-checklist.md) for the technical review and handoff;
- [release-candidate procedure](release-candidate.md) to identify exactly what
  was reviewed and collect reproducible evidence; and
- [finding and disclosure process](findings-and-disclosure.md) to report,
  triage, fix, accept, retest, and release-gate findings.

The existing [threat model](../threat-model.md), [algorithm
policy](../algorithm-policy.md), [host-key API](../host-key-api.md),
[resource limits](../resource-limits.md), [malformed corpus](../malformed-inputs.md),
[sensitive-data lifecycle](../sensitive-data-lifetimes.md), [stress/soak
policy](../stress-and-soak.md), and [timing-sensitive operation
inventory](../timing-sensitive-operations.md) are inputs, not conclusions.
Where those documents identify gaps, this package does not treat the gaps as
accepted risks.

## Architecture and data flow

sshz is a client/server SSH library over an application-owned reliable,
ordered byte stream. It neither opens sockets nor supplies deployment policy.

```text
untrusted peer/network bytes
        |
application transport loop (socket, deadlines, concurrency, rate limits)
        |
SshzClient / SshzServer event and readiness API (src/sshz.zig)
        |
identification + packet framing/MAC/compression (src/sshz.zig,
src/protocol.zig, src/buffer.zig)
        |
client/server protocol state machine (src/client_session.zig,
src/server_session.zig)
        |
KEX, key derivation, signatures, cipher/MAC, private-key parsing
(src/hasher.zig, src/aesctr.zig, src/key.zig, src/privkey.zig;
Zig standard-library crypto)
        |
authentication, channel, forwarding, and agent events
        |
embedding application's trust/authorization decision and plaintext handling
```

The normal session data flow is:

1. The embedding application supplies an allocator, a cryptographically secure
   `std.Random`, credentials or host key, and stream bytes.
2. The roles exchange exact SSH identification strings and `KEXINIT` payloads,
   pass both offers through the centralized policy parser/negotiator, select
   each category and direction in client preference order from the exhaustive
   allowlist, perform X25519, construct the exchange hash, and verify/sign the
   server host-key signature.
3. Before authentication, the client emits `CheckHostKey`. The application
   must explicitly accept or reject the identity. The server loads its host
   private key at initialization.
4. Directional IV, encryption, and MAC keys are derived and activated at each
   `NEWKEYS` boundary. Packets are framed, padded, encrypted with AES-256-CTR,
   and authenticated with HMAC-SHA-256 over the plaintext packet and sequence
   number.
5. The client attempts configured authentication methods. The server emits
   `UserAuth` after parsing an attempt and after verifying any signature on a
   signed public-key request. Unsigned public-key probes also require an
   application decision before `PK_OK`; allowing a probe does not authenticate.
   The application makes each final decision with `decideUserAuth`, or the
   compatible `grantAccess` plus `clearEvent` sequence.
6. After authentication, channel/global requests, flow-controlled data,
   extended data, EOF, and close are exchanged. The application must decide
   whether channel opens, commands, forwarding destinations, environment
   changes, and agent access are authorized.
7. If delayed zlib was negotiated, independent inbound/outbound streams become
   active only after authentication success. Decompressed plaintext then enters
   the same packet/state-machine path.
8. Peer, local byte/packet/time, and simultaneous rekeys use the same state
   machines. The initial session identifier and application-approved host key
   remain bound while directional keys change only at their `NEWKEYS`
   boundaries; hard cipher/sequence exhaustion terminates instead of wrapping.
9. Fail-closed terminal cleanup, `deinit`, and documented replacement/success
   paths scrub session buffers and key material. Default tests compile out raw
   secret tracing. The review must still determine whether every ownership and
   error path provides adequate lifetime and cleanup.

## Trust boundaries

The review must preserve these boundaries:

- **Network/peer to parser:** every byte, length, sequence, algorithm name,
  compressed stream, message order, channel/window value, and request is
  attacker-controlled.
- **Library to embedding application:** transport reliability, secure
  randomness, allocator behavior, host-key trust, account authorization,
  forwarding policy, timeouts, concurrency, sandboxing, logging, and process
  cleanup are application responsibilities. Events contain untrusted strings
  and may contain secrets or plaintext.
- **Library to dependencies:** the compiler, Zig standard-library cryptography,
  libc, and system zlib are trusted dependencies. Their internals are outside
  this code review, but version selection, API use, error handling, and
  cryptographic composition are in scope.
- **Process to host:** key files, environment variables, SSH-agent sockets,
  allocator pages, logs, crash dumps, file descriptors, and OS permissions
  cross this boundary. The library cannot protect secrets after process, kernel,
  compiler, or privileged-host compromise.

The fuller objectives, attacker capabilities, and boundaries are in the
[threat model](../threat-model.md#trust-boundaries).

## Exact review scope

The candidate manifest must record the commit containing these paths. Review
the production library implementation and its tests:

| Code | In-scope responsibility |
| --- | --- |
| `src/sshz.zig` | Public event/readiness API; identification and packet I/O; framing, encryption/MAC verification, host-key and application decision APIs; channel/forwarding entry points |
| `src/client_session.zig` | Client KEX/rekey, host identity, authentication, global requests, channel/agent handling, and state transitions |
| `src/server_session.zig` | Server KEX/rekey, host signing, authentication proof/application handoff, global requests, channel/agent handling, and state transitions |
| `src/protocol.zig` | SSH constants and bounds, packet/key derivation, centralized algorithm offer validation and client-order selection, system-zlib streams, wrap/unwrap support |
| `src/key.zig`, `src/privkey.zig` | Public/private key parsing, signature encoding/verification, RSA composition, OpenSSH private-key decoding and bcrypt/AES-CTR protection |
| `src/aesctr.zig`, `src/hasher.zig` | AES-CTR state and exchange-hash/key-derivation support |
| `src/channel.zig` | Four-slot channel table, windows, scheduling, buffering, EOF/close, channel types |
| `src/buffer.zig`, `src/util.zig` | Bounded binary/name-list parsing, writing, diagnostics and trace gating |
| `src/test.zig`, `src/trace_gate_test.zig`, `test/malformed.zig`, `test/stress/`, and inline `test` blocks in `src/*.zig` | Security claims, deterministic malformed/state and stress/soak evidence, missing negative cases, and adequacy of existing evidence |
| `build.zig`, `build.zig.zon` | Build options, dependency declaration, zlib linkage, unit/malformed/stress/soak/interop entry points, and unsafe trace gate |

The feature scope is:

- SSH identification and binary packet transport, sequence numbers, padding,
  bounds, encrypt-and-MAC ordering, rekey transitions, disconnect/debug/ignore
  behavior, and malformed or out-of-state input;
- `curve25519-sha256`, SHA-256 exchange hash and RFC 4253 key derivation;
  Ed25519, ECDSA P-256/SHA-256, and RSA SHA-256/SHA-512 signatures;
  AES-256-CTR and HMAC-SHA-256 composition and randomness use;
- OpenSSH `openssh-key-v1` private-key parsing for Ed25519, P-256, and RSA,
  unencrypted or bcrypt plus AES-256-CTR protected;
- client host-key decision and rekey continuity; client `none` discovery,
  public-key, password, and keyboard-interactive flows; server public-key and
  password protocol handling and the `UserAuth` authorization-decision
  boundary;
- session, `direct-tcpip`, and `forwarded-tcpip` channels; shell, exec,
  subsystem, environment, window-change, signal, data/extended-data, flow
  control, EOF, and close; `tcpip-forward` and `cancel-tcpip-forward`; opt-in
  OpenSSH agent forwarding;
- `none` and delayed `zlib@openssh.com`, including negotiation, activation,
  rekey reset, bounds, malformed streams, and compression-oracle exposure;
- allocation/ownership, copies, teardown/error cleanup, zeroization,
  diagnostics, crash/error exposure, and secret lifetimes; and
- local and remotely observable timing behavior in MAC, credentials, key
  parsing, KEX/signatures, authorization handoff, failures, compression, and
  dependency calls.

## Supported configuration to review

The current implementation has a narrow, mostly compile-time configuration:

- both client and server roles use an application-owned reliable ordered stream;
- callers supply the allocator and secure random source;
- the transport allowlist is exactly the one in the [algorithm
  policy](../algorithm-policy.md#current-transport-allowlist); there is no API
  to add transport algorithms at runtime;
- compression preference is delayed `zlib@openssh.com`, then `none`, with no
  application opt-out;
- one OpenSSH-format host key is loaded by a server; the client may provide one
  OpenSSH-format user key and passphrase, password, keyboard-interactive
  response, or optionally try `none`;
- a maximum of four channels is compiled in; session, direct/remote TCP
  forwarding, and agent channel APIs are available, with agent forwarding
  disabled until explicitly enabled;
- validated per-session resource/deadline policy is available through
  `initWithLimits`; byte and packet rekey thresholds default to 1 GiB and
  2^30 packets per directional key, and callers can configure and drive a
  monotonic key-age threshold;
- peer, automatic local, and simultaneous rekey are handled; the initial host
  identity and session identifier remain bound, and checked cipher/sequence
  hard limits terminate with `KeyLifetimeExceeded` rather than wrap; and
- `-Dunsafe-secret-tracing=true` is an explicitly unsafe build option and must
  remain off in all review and release evidence except a separately isolated
  audit that contains no real secrets.

Record any behavior that differs from this list as a finding or scope change;
do not silently broaden the review.

## Known limitations and evidence gaps

At package creation, the following are known and not approved exceptions:

- production blockers remain in parser/state-machine robustness, timing,
  secret lifecycle, authorization/host identity, algorithms, limits,
  interoperability/stress, API guidance, and independent review; see the
  [threat-model blocker table](../threat-model.md#production-release-blockers);
- the [algorithm policy](../algorithm-policy.md#production-release-criteria)
  records complete RSA validation, strict-KEX, delayed-compression,
  independent-vector, and dependency-pinning gaps; centralized enforcement,
  client-order selection, guessed-packet handling, and automatic rekey are
  present and must be reviewed rather than listed as absent;
- the [timing inventory](../timing-sensitive-operations.md) covers only the
  documented server-authentication slice, not a complete timing audit;
- `zig build malformed` is a dedicated deterministic, network-free corpus of
  55 transport/parser/state cases with exact expected outcomes and bounded
  steps/input. Linux CI requires Debug and ReleaseSafe runs. Coverage-guided
  fuzzing is not currently usable because the pinned Zig 0.16 compiler fuzz
  runner has a `builtin.StackTrace`/`debug.StackTrace` incompatibility, so the
  fixed corpus is the present evidence;
- Linux CI requires OpenSSH, Dropbear, and libssh interoperability. The Azure
  Linux development host's packaged libssh is locally defective, but the
  Ubuntu CI implementation is conforming; preserve that distinction in
  evidence rather than treating a local package failure as a protocol result;
- `zig build stress` is a required fixed-seed ReleaseSafe Linux PR job, and
  `zig build soak` is run by the scheduled twice-weekly OpenSSH and weekly
  Dropbear/libssh workflow. Candidate evidence must still identify actual run
  URLs/logs and must not turn scheduled configuration into a claim that a
  particular pinned RC completed a soak; and
- most cryptographic evidence is unit tests and self-round-trips rather than a
  complete independent-vector set.

The candidate evidence must say `missing` for absent evidence. A maintainer may
add evidence in a later candidate, but must not represent a planned command or
an issue link as a completed test.

## Exclusions

The following are excluded from the product-code review unless separately
added to a signed scope amendment:

- `mssh/` and `msshd/` as production applications; they are examples
  or demos. Their use as test drivers and their handling of the library trust
  boundary may be observed, but does not make them reviewed deployment tools;
- `interop/` and `testserver/` as production code; they are evidence
  infrastructure and fixtures;
- generated `.zig-cache/`, `zig-out/`, local evidence, and editor files;
- internal correctness of Zig cryptographic primitives, the compiler, libc,
  system zlib, OpenSSH, Dropbear, and libssh. sshz's selection, composition,
  inputs, outputs, and failure handling remain in scope;
- unimplemented SSH algorithms, extensions, services, and application
  protocols;
- application account databases, command sandboxing, destination services,
  network availability, traffic-analysis resistance, physical attacks,
  hardware side channels, privileged host compromise, and cryptanalytic breaks
  of the selected primitives.

An exclusion is not an accepted risk. If review work shows an excluded
component is necessary to support a sshz security claim, maintainers must
amend and re-pin the scope before relying on that claim.
