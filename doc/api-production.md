# Production-facing API and lifecycle

## Status

This document describes the intended embedding boundary; it is not a security
claim. **sshz is not secure and must not be used in real-world systems.**
The [threat model](threat-model.md) lists release blockers. `mssh` and
`msshd` are demos, not deployment templates. The examples under
[`examples/production/`](../examples/production/) demonstrate fail-closed
integration patterns, but do not make the library production-ready.

## Compatibility policy

sshz is currently pre-1.0 and has no stable release line. Until a release
explicitly declares API version 1, every Zig API may change between minor
releases. Releases must call out changes to the production-facing surface below
and provide a migration note for source-breaking changes.

The candidate production-facing surface is the `sshz` module's
`SshzClient`, `SshzServer`, event and event-payload types,
`ResourceLimits`, deadline/key-lifetime types, `SshOpenFailureReason`,
`SshzError`, and buffer helper types. After API version 1, these names,
their documented semantics, and default resource limits follow semantic
versioning: source-breaking changes require a major version; additive events
or errors require at least a minor version; fixes that preserve the contract
may be patches. Zig compiler-version changes are compatibility changes and
must be stated in release notes.

Everything reached through `.session`, public implementation fields, the
`client_session.zig`, `server_session.zig`, `channel.zig`, and `protocol.zig`
modules, packet inspection/exercise helpers, and `requestRead`,
`requestWrite`, `requestEvent`, `advance`, and `getRecvBuffer` is
**internal/unstable**, even where Zig currently exposes it. Agent and TCP
forwarding APIs are **experimental** until their authorization contracts have
dedicated tests and documentation. Demo program APIs and behavior carry no
compatibility guarantee.

Applications should pin an exact sshz revision and Zig version, compile with
the next candidate before upgrading, and never infer compatibility from a
successful protocol handshake.

## Construction, ownership, and cleanup

Create one `SshzClient` or `SshzServer` per ordered, reliable byte stream.
Supply a cryptographically secure `std.Random`, an allocator whose lifetime
contains the session, and explicit validated `ResourceLimits` through
`initWithLimits`. The client's second argument is the username; the server's
is one OpenSSH private host-key file. Initialization copies/decodes the values
it must retain.

The object is single-owner and not thread-safe. Serialize all calls. On every
exit path:

1. stop dispatching new application work;
2. close the transport so no more peer input arrives;
3. cancel or reap subprocesses and close forwarded resources owned by the
   application;
4. call `deinit()` exactly once.

`deinit` clears session packet buffers and key material. It does not close the
application's socket or erase copies held by the application, allocator,
credential store, logs, crash dumps, or kernel. Treat an unexpected library
error as terminal: close and deinitialize rather than attempting to resume.
Fatal protocol/resource/key-lifetime paths latch fail-closed state and later
I/O returns `SessionTerminated`.

## The transport pump

sshz performs no transport I/O. Repeatedly call `getNextEvent()` and service
exactly the returned requirement:

| Result | Caller action |
| --- | --- |
| `ReadyToConsume(n)` | Read at most `n` ordered bytes from the peer and pass each non-empty chunk to `write()`. Zero bytes means transport EOF, not progress. |
| `ReadyToProduce(n)` | Call `peek(n)`, write some or all of the returned slice to the peer, then call `consumed(actual_written)`. |
| `ReadyToConsumeAndProduce` | Service either ready direction without assuming an order. A full-duplex poller should keep both interests armed. |
| `Event(code)` | Complete the policy/application action synchronously, then call `clearEvent(code)`, except for events with explicit decision methods. |
| `error.NotReady` | Wait for transport readiness, a deadline tick, or application work; do not spin. |

`write()` copies input before returning and accepts partial fulfillment of the
announced amount. Never pass more than the current requirement.
`peek()` returns borrowed session storage. Keep it only through the transport
write and call `consumed()` with the exact count actually written, including
partial writes; never mutate or retain the slice. Do not call `consumed()` for
bytes the transport did not accept.

An event remains pending until cleared or decided. Repeated
`getNextEvent()` calls may return it again. Do not clear an event before its
payload is processed. All slices in events (`username`, key blobs, passwords,
commands, data, descriptions, and similar fields) are borrowed from session
storage and become invalid when the event is cleared/accepted/rejected, on
another state-mutating call that releases it, or at `deinit`. Copy data that
must outlive the callback, and protect/erase copied secrets.

The buffer from `getChannelWriteBuffer(channel)` is also borrowed. Copy no more
than its length, immediately call `channelWriteComplete(channel, count)`, and
do not use the slice afterward. An empty buffer means the channel cannot
currently accept data. Inputs to channel-open/rejection APIs should
conservatively remain alive until the corresponding open/failure output has
been pumped because some current implementation paths retain slices.

## Client event loop and host identity

`CheckHostKey` is a mandatory trust decision emitted after the key-exchange
signature proves possession of the presented key, but before user
authentication. Bind the decision to the intended canonical endpoint and a
trusted key database:

1. inspect/copy `raw_key` and/or `fingerprint`;
2. compare against pinned or strictly managed trust state;
3. call exactly one of `acceptHostKey()` or `rejectHostKey()`.

`clearEvent(CheckHostKey)` fails with `badClearEvent`; unknown, changed,
missing, or policy-error keys must be rejected. Trust-on-first-use is an
explicit application policy requiring atomic persistence and changed-key
rejection, never a default. Rekey is bound to the initially accepted key and a
change returns `HostKeyChanged`. See [the host-key API](host-key-api.md).

Credential request events borrow or copy credentials only for the required
setter call. Do not log them. Clear ordinary informational/request events only
after setting the requested value. `EndSession` is terminal. The current
client automatically opens a session channel after authentication (shell by
default, or `setAutoExecCommand`); this behavior is pre-1.0 and unsuitable as
an implicit production policy. Configure the intended operation before
driving the handshake.

## Server authentication and authorization

`UserAuth` means protocol-level parsing succeeded; it does **not** mean the
account is authorized. A public-key event may represent either an unsigned
probe or a request whose signature has already been verified. The application
applies the same username/key policy to both. Allowing a probe emits `PK_OK`
but does not authenticate; only allowing the later valid signed request can
emit authentication success.

While the borrowed `UserCredentials` is pending, evaluate username, method,
key, credential verifier, account state, source policy, and rate limits. Then
call `decideUserAuth(.Allow|.Deny)` exactly once; it resolves and clears the
event atomically. `grantAccess(bool)` followed by `clearEvent(event)` remains a
compatibility path, and clearing an undecided `UserAuth` event denies by
default. Deny `none`, password, keyboard-interactive, unknown users, backend
failures, and unsupported key policies by default. Never use password
equality, “any valid key,” or a missing policy as acceptance.

Authentication callbacks must be bounded and side-channel reviewed.
Application-wide attempt/source limits complement the per-session
`max_server_auth_attempts`. A backend timeout or exception is denial followed
by connection cleanup, not acceptance or an indefinite pending event.

## Channel lifecycle

1. A peer open produces `ChannelOpenRequest`. Authorize the channel type and
   every destination/origin field, then call `acceptChannelOpen(id)` or
   `rejectChannelOpen(id, reason, description)`. Never merely clear this event.
2. An outbound open is not usable until `ChannelOpened`; handle
   `ChannelOpenFailure` as final for that channel. `Connected` reports an
   accepted server channel or the client's automatic session channel.
3. For server `ChannelRequest`, authorize `Shell`, `Exec`, `Subsystem`, `Env`,
   and `AgentForward` separately. **Current limitation:** clearing a
   reply-requesting event sends success; there is no request-failure method.
   To deny, queue `sendChannelClose(channel)` before clearing. Treat this as a
   release blocker for applications needing request-level rejection.
4. Process `RxData`/`RxExtendedData` synchronously and clear the event to
   release the borrowed payload and permit window replenishment. Send with the
   borrowed channel-write buffer contract above; flow control may temporarily
   return an empty buffer or `NotReady`.
5. `sendChannelEof` ends the local data direction after queued data.
   `sendChannelClose` abandons unsent data and starts close exchange. After
   close/end-session, release every application resource bound to that channel.

Reject forwarding and agent requests unless separately authorized. Validate
resolved destinations too, preventing DNS rebinding and access to loopback,
link-local, metadata, privileged, or internal services contrary to policy.

## Limits, deadlines, and rekey

Defaults are compatibility bounds, not a deployment policy. Configure
per-session packet, channel, buffering, pre-authentication, authentication,
KEX, decompression, and global-request limits; add process-wide connection,
memory, CPU, file-descriptor, bandwidth, and source limits. See
[resource limits](resource-limits.md).

sshz does not read a clock. Call `initializeDeadlines(now)` once, use one
monotonic tick unit, call `noteActivity(now)` only for real progress, and call
`tick(now)` often enough to enforce handshake, authentication, idle, total,
and key-age limits. A timeout is terminal. The embedding transport also needs
bounded connect/read/write operations so a blocked callback cannot prevent
ticks.

Byte/packet thresholds schedule automatic rekey; configure a key-age threshold
and continue pumping while rekey is in progress. Application initiation may
return `NotReady` while output is gated. `keyLifetimeStatus()` is diagnostic,
not permission to exceed limits. Never disable or weaken rekey limits to work
around backpressure.

## Error taxonomy

- `ResourceLimitConfigError` and `DeadlineError` identify caller
  configuration/clock-contract bugs. Fix configuration; do not retry a live
  session after a monotonic-clock violation.
- `NotReady`, `cannotAcceptWrite`, `notProducing`, and `notEnoughData` normally
  indicate pump ordering/backpressure mistakes. Correct the poll state; never
  drop or duplicate bytes.
- `BufferError`, malformed framing/MAC, negotiation, unexpected response,
  channel-window/packet, auth/KEX/resource, host-key-change, and
  key-lifetime errors are peer/session failures. Close and deinitialize.
- Allocator, crypto, compression, credential/policy, transport, and
  application errors fail closed. Do not map an operational failure to a
  positive host-key, authentication, channel, or forwarding decision.
- `EndSession` and deadline outcomes are terminal lifecycle results, even when
  the peer closed cleanly.

Do not match only today’s exhaustive error set to decide safety. Future
additive errors must inherit the default terminal behavior until reviewed.
