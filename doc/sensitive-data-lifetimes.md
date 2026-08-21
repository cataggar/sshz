# Sensitive data lifetimes

sshz treats an error returned while driving protocol I/O as terminal. The
caller must stop using the transport and call `deinit`. Resource, key-lifetime,
and deadline failures also latch the session closed and scrub it immediately.
Cleanup is idempotent so `deinit` remains required and safe after fail-closed
cleanup.

## Ownership and scrub points

| Data | Owner and lifetime | Scrub point |
| --- | --- | --- |
| X25519 keypair and deterministic-generation seed | The session owns the keypair for one exchange; the seed is stack-owned | Seed on leaving generation; private key immediately after scalar multiplication; all exchange errors and terminal cleanup |
| Shared secret `K` | The session owns it from scalar multiplication through key derivation | On every return from pending-key derivation, then again by idempotent exchange cleanup |
| Exchange/KDF hash state and temporary digests | The session owns the exchange hasher; hash routines own their stack state | `final` consumes and clears the hasher and temporary digests; reset, exchange errors, fail-closed, and deinit also clear it |
| Pending directional IV, encryption, MAC, cipher, and compression state | The session owns one pending c2s and s2c epoch | On replacement, exchange failure, fail-closed, or deinit; ownership moves to the active slot only at the corresponding `NEWKEYS` boundary |
| Active directional keys | The session owns separate inbound and outbound epochs | The old outbound epoch is cleared after its `NEWKEYS` packet is queued and the replacement is ready. The old inbound epoch is cleared only after peer `NEWKEYS`. Fail-closed and deinit clear both. This also covers local, peer, and simultaneous rekey. |
| Session identifier | The session owns the initial exchange hash for authentication and every later rekey | Fail-closed or deinit; it cannot be discarded earlier without breaking SSH key derivation and user-auth signatures |
| Generated and received signatures | Signature output is stack-owned; received signatures live in the input packet | Generated blobs and signing buffers after packet copy; received user-auth signatures after verification; received exchange signatures and packet storage after verification/host-key copy |
| Client private-key text and key passphrase | Allocator-owned session copies | After a successful decode, after the final decode rejection/error, on replacement, or terminal cleanup |
| Client decoded private key | Session-owned after decode | Immediately after the signed authentication packet is constructed, or on signing/error/replacement/terminal paths |
| Client password and keyboard-interactive response | Allocator-owned session copies | After copying into the outbound packet, including construction errors; replacement and terminal cleanup are fallbacks |
| Client automatic command and terminal option text | Allocator-owned session copies | After copying into their one outbound channel request, on replacement, or terminal cleanup |
| Server host private key | Session-owned from successful initialization because rekey needs it | Fail-closed or deinit; partial initialization clears it with `errdefer` |
| Server authentication packet | Input-packet storage owned by the session | After the application clears the `UserAuth` event. Password fields are borrowed until then; unsupported keyboard-interactive requests are rejected without an event. Authentication signatures are scrubbed earlier after verification. |
| Packet plaintext, decompression output, and channel write buffers | Packet buffers belong to the core session; channel buffers belong to their channel slot | Input/decompression storage on release of a borrowing event or before reuse; output storage only after the caller reports it fully consumed; terminal cleanup/deinit; channel consumption, discard, close, slot reuse, or terminal cleanup |
| Random source | Borrowed from the caller; sshz does not own its PRNG state | Caller responsibility. sshz clears the exchange seeds it draws, but cannot clear the caller's generator state. |

Public host keys, public X25519 values, negotiation transcripts, and algorithm
names are not secret, but temporary copies are still bounded and released with
their owning packet or exchange state. The server retains only the public-key
probe blob needed to construct `SSH_MSG_USERAUTH_PK_OK`, and clears it after
copying or rejection.

## Borrowed event and I/O slices

Slices in events such as `UserAuth`, `RxData`, `RxExtendedData`, banners,
disconnect descriptions, channel requests, and forwarding requests are
borrowed. They are valid only until the caller clears, accepts, or rejects that
event. sshz deliberately does not scrub their backing packet while the event
is outstanding. Callers must copy data they need later and must not retain or
read a slice after releasing the event.

Similarly, a slice returned by `peek` is valid only until the caller reports
those bytes consumed. The output buffer is scrubbed when the complete output
item has been consumed. A slice returned as a channel write buffer belongs to
that channel and must not be retained after completion, close, or session
cleanup.

A terminal API result invalidates outstanding borrowed slices. The caller must
not concurrently access a session or its event data while another thread
drives, times out, fails, or deinitializes that session.

## Diagnostics

Ordinary logs record states, message identifiers, lengths, and non-secret
algorithm metadata, not packet bodies, credentials, keys, signatures, commands,
banners, disconnect/debug text, or channel payloads. Raw diagnostic dumps exist
only behind the explicitly unsafe `-Dunsafe-secret-tracing=true` build option.
Such builds can disclose all of those values and must not be used in production,
CI logs, or reports.

## Limits of zeroization

`std.crypto.secureZero` narrows the exposure window; it does not provide
process-compromise protection. Compiler-generated copies, register spills,
cryptographic or zlib internals, allocator metadata/quarantine, and storage
previously returned to an allocator may retain data outside sshz's direct
control. Optimizing compilers and dependencies form part of the trusted
computing base.

The library cannot prevent disclosure through core/crash dumps, swap,
hibernation, debugger access, process snapshots, privileged OS access, hardware
attacks, or a compromised embedding application. Deployments should disable or
protect dumps and swap as appropriate, restrict process inspection, use a
cryptographically secure random source, avoid environment variables for
credentials, protect key files, keep unsafe tracing disabled, serialize session
access, release events promptly, and always call `deinit`.
