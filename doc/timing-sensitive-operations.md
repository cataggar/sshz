# Timing-sensitive operation inventory

This review tracks the server-authentication portion of
[issue #62](https://github.com/cataggar/sshz/issues/62). It covers the SSH
server state machine and the `sshzd` authorization policy as of July 2026.

## Inventory

| Operation | Code | Treatment |
| --- | --- | --- |
| Packet MAC verification | `src/sshz.zig` `verifyPacketMac` | Compares the fixed-size calculated and received MAC with `std.crypto.timing_safe.eql`. A wrong length is necessarily visible in the packet framing. |
| Public-key signature verification | `src/server_session.zig` `handlePacket`; `src/key.zig` `verifySignature` | Parsing, algorithm mismatch, and cryptographic verification failure all enter `SessionState.UserAuthDenied` and produce the same RFC 4252 failure packet. Verification uses Zig's Ed25519/ECDSA/RSA primitives. Algorithm-specific computation is unavoidable because the requested algorithm and key are public wire data. |
| Authorized-key lookup | `sshzd/src/auth.zig` `AuthorizedKeys.allows` and `timingSafeAuthorizedValueEql` | A validated, equal-length candidate is zero-padded to a fixed-size array and compared with `std.crypto.timing_safe.eql`. The full authorized-key list is visited; matching does not exit the loop early. |
| Password authorization | `sshzd/src/auth.zig` `Policy.allows` | Production policies are `deny_all` and `authorized_keys`; neither compares passwords. The username-equals-password comparison exists only in the explicitly named `insecure_demo` policy and is not a production secret check. |
| Authentication rejection | `src/server_session.zig` `denyAuthentication` and `advanceSession` | Unknown methods, unsupported password-change requests, invalid key encodings/algorithms, malformed signature blobs, signature failures, and application authorization denials converge on `SSH_MSG_USERAUTH_FAILURE` with `password,publickey` and `partial success = false`. |

## Deliberate public or protocol-visible distinctions

- SSH service names, authentication method names, algorithm names, key types,
  curve names, and encoded lengths arrive in plaintext protocol structures.
  Ordinary equality and length checks on these public selectors are not secret
  comparisons.
- `password,publickey` remains the advertised method list. `none` is the RFC
  discovery request and is never advertised; unsupported methods are rejected
  without inventing support. Password-change requests are parsed completely,
  then rejected because this server only implements ordinary password
  authentication.
- A structurally valid unsigned public-key query receives
  `SSH_MSG_USERAUTH_PK_OK`, preserving RFC 4252 section 7 semantics. It does not
  authenticate the user. Unsupported algorithms and malformed/non-canonical
  key blobs receive the common failure packet.
- Truncation of the outer `SSH_MSG_USERAUTH_REQUEST` fields remains a
  `BufferError.ReaderOutOfDataErr`; invalid services remain service/protocol
  errors. These malformed packets are not relabeled as credential failures.
  Invalid nested key and signature values are credential failures and share the
  common wire response.
- Public-key blob length differs across algorithms and RSA key sizes, so a
  length mismatch is rejected before the fixed-size comparison. Those lengths
  are already disclosed by the request and `authorized_keys` formats.
- Application callback duration is outside the packet parser's control.
  `sshzd`'s non-demo policy performs no user database or password lookup and
  treats its authorized-key file as a global allowlist.

Tests in `src/server_session.zig` assert packet contents and state transitions
for invalid users, passwords, key data, signatures, password changes, unknown
methods, malformed outer packets, and unsigned public-key probes.
`sshzd/src/auth.zig` tests equal-length mismatches at both ends of an
authorization-sensitive value. No wall-clock timing assertions are used.
