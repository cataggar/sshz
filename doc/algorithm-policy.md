# SSH algorithm policy

## Status and scope

This document defines the algorithm allowlist intended for a future production
sshz release and records what the current implementation actually enforces.
It is not a release-readiness claim. See the
[production threat model](threat-model.md)
for the wider security boundary and release blockers.

The policy applies to the client and server library in `src/`. The example
programs have additional unsafe behavior described in the threat model. Terms
used below have these meanings:

- **Enforced now** means the current code implements and tests the behavior.
- **Production policy** means behavior required before a production claim.
- **Gap** means the production policy is not yet completely implemented or
  evidenced. A documented gap must not be treated as an accepted exception.

## Current transport allowlist

sshz has no API for broadening these lists at runtime.

| Purpose | SSH name and construction | Role and direction | Current rationale and status |
| --- | --- | --- | --- |
| Key exchange | `curve25519-sha256` (X25519 with SHA-256) | Client and server | The only advertised KEX. It provides ephemeral key agreement and a SHA-256 exchange hash. Enforced now. |
| Server host-key signature | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-512`, `rsa-sha2-256` | The client advertises this order. The server advertises only algorithms usable with its single loaded host key. | Ed25519 and P-256 provide compact modern signatures. RSA is retained for compatibility, but only with SHA-2. Signature verification, key-family matching, client-ordered selection, and RSA size bounds are enforced now. |
| Encryption | `aes256-ctr` | Independently named for client-to-server (c2s) and server-to-client (s2c), but it is the only choice in both directions | A widely interoperable 256-bit cipher. Enforced now. The current construction is the original SSH encrypt-and-MAC construction, not AEAD or encrypt-then-MAC; its production suitability still requires review. |
| MAC | `hmac-sha2-256` | Independently negotiated c2s and s2c; the full 32-byte MAC is used | SHA-256 HMAC over the packet sequence number and plaintext packet. Enforced now, including timing-safe comparison of equal-sized MACs. |
| Compression | `zlib@openssh.com`, then `none` | Independently negotiated c2s and s2c using client preference | Only delayed zlib and no compression are allowed. Delayed zlib is activated after `SSH_MSG_USERAUTH_SUCCESS`; authentication traffic is not compressed. Enforced now, subject to the compression policy below. |
| Key derivation | RFC 4253 SHA-256 derivation | Separate IV, encryption key, and MAC key for c2s and s2c | Uses the exchange hash, shared secret, the letters A through F, and the initial session identifier. Enforced now. |

The client host-key preference is:

1. `ssh-ed25519`
2. `ecdsa-sha2-nistp256`
3. `rsa-sha2-512`
4. `rsa-sha2-256`

For RSA, `ssh-rsa` is still the required public-key *blob format identifier*.
It is not accepted as a signature algorithm: RSA signatures use PKCS#1 v1.5
with SHA-512 or SHA-256 under the `rsa-sha2-*` names.

The same signature families are accepted for server-side public-key user
authentication. The sshz client signs user authentication with Ed25519,
ECDSA P-256/SHA-256, or RSA/SHA-512 according to the loaded key; it does not
currently negotiate an RSA/SHA-256 fallback from `server-sig-algs`.

## Private- and public-key parsing

The current private-key loader accepts one key from the
`openssh-key-v1` format:

- key types: Ed25519, ECDSA on `nistp256`, and RSA;
- unencrypted files with cipher `none`;
- passphrase-protected files with cipher `aes256-ctr` and the OpenSSH `bcrypt`
  KDF (a 16-byte salt is required).

Other private-key formats, multiple-key containers, other curves, other
private-key ciphers, and other KDFs are unsupported. Transport cipher `none`
remains forbidden even though `none` is a valid at-rest private-key encoding.
Public-key blobs are accepted only for Ed25519, ECDSA P-256, and RSA.

The production key policy is:

- Ed25519 keys must have their fixed standard encoded size.
- ECDSA keys must be valid points on P-256.
- RSA moduli must be 2048 through 4096 bits and exponents must be valid,
  odd values of at least 3. New deployments should use 3072-bit or larger RSA
  only when Ed25519 or P-256 cannot be used.
- Private-key KDF parameters and container structure must be bounded and fully
  validated; unencrypted private keys are an operator decision and require
  equivalent protection from the embedding application.

RSA public-key parsing, private-key use by both session roles, signing, and
signature verification enforce a modulus size of 2048 through 4096 bits and an
odd exponent of at least 3. **Gap:** complete mathematical validation of all RSA
private components is not implemented. The private-key parser also has no
production policy bounds for bcrypt rounds and does not fully validate all
container metadata and trailing structure.

## Negotiation and downgrade rules

Production negotiation must:

1. select the first mutually supported algorithm in the client's name-list,
   independently for every RFC 4253 category and direction;
2. fail closed when a category has no allowed mutual algorithm;
3. never infer, alias, or silently substitute an algorithm;
4. bind both exact KEXINIT payloads, both identification strings, both
   ephemeral keys, the shared secret, and the host key into the exchange hash;
5. require the returned host-key signature name and key family to match the
   negotiated choice, then verify the signature before installing keys;
6. preserve the initial session identifier across rekey and change each
   direction's keys only at its `NEWKEYS` boundary; and
7. handle or reject guessed KEX packets and strict-KEX signaling exactly as the
   applicable protocol specifications require.

Current code exact-matches supported names and returns
`AlgorithmNegotiationFailed` when a required KEX, host-key, cipher, MAC, or
compression intersection is empty. All required algorithm name-lists must be
non-empty, contain valid SSH names, and contain neither empty elements nor
duplicates; language lists may be empty but otherwise follow the same grammar.
Every name-list is limited to 64 entries so duplicate validation and
negotiation remain bounded before authentication.
Selection follows the client's order in both roles, including host-key
selection constrained by the server's loaded key. Since KEX, cipher, and MAC
each have one local choice, peer ordering cannot change those selections.
Compression selection follows client order. The exchange hash and host
signature checks prevent an unauthenticated algorithm substitution when the
embedding client also validates the host identity.

When a peer sets `first_kex_packet_follows`, sshz compares that peer's first
KEX and host-key names with the negotiated pair. A wrong guess causes exactly
the following packet to be discarded; a correct guess is processed normally.
Malformed packets are not treated as guesses. The client also binds every
rekey host-key blob to the initially signature-verified and application-approved
host identity.

The following are known blockers:

- **Strict KEX:** the OpenSSH strict-KEX extension names are not advertised or
  implemented, and the handling of unexpected transport messages during KEX
  has not been reviewed as an equivalent defense.
- **Negative evidence:** policy-level client/server matrices cover weak-only
  required categories, mixed ordering, malformed lists, and wrong guesses.
  More end-to-end evidence is still needed for mismatched signature names and
  broader downgrade attempts.

No weak compatibility fallback may be added to resolve these gaps.

## Forbidden and unsupported algorithms

The allowlist is exhaustive. Unknown names and every name not listed above are
unsupported and must produce no usable negotiation. In particular, production
policy forbids:

- SHA-1 KEX such as `diffie-hellman-group1-sha1`,
  `diffie-hellman-group14-sha1`, and
  `diffie-hellman-group-exchange-sha1`;
- `ssh-dss` and the SHA-1 `ssh-rsa` signature algorithm;
- CBC, 3DES, RC4/arcfour, and transport cipher `none`;
- MD5, SHA-1, truncated, or `none` MACs; and
- immediate `zlib` compression.

Algorithms that may be sound but are not implemented, including other
Curve25519 aliases, finite-field KEX, other NIST curves, security-key
signatures, AES-GCM, ChaCha20-Poly1305, and encrypt-then-MAC names, are
unsupported rather than implicitly approved. Adding one requires the review
process below; accepting its name before implementing its exact construction
is forbidden.

## Compression policy

`none` and delayed `zlib@openssh.com` are the only production candidates.
Immediate pre-authentication compression is forbidden. Delayed compression
must remain inactive until authentication success in each direction and must
be reset safely when algorithms change during rekey.

Delayed compression can still expose post-authentication secrets when an
attacker can influence plaintext compressed in the same stream. Embedders must
not combine secrets with attacker-controlled reflection in a compressed
channel. **Gap:** sshz advertises delayed zlib before `none` and offers no
application control to disable it. The production review must either provide a
safe opt-out/default and deployment guidance or remove delayed compression
from the production allowlist.

## Rekey and key lifetime

Peer- and locally initiated rekey use the same client/server state machines.
The implementation initiates automatically when either direction reaches the
first of:

- 1 GiB encrypted in either direction;
- 2^30 encrypted packets under a directional key; or
- the configured caller-clock key age.

The first two are enabled defaults. Key age is expressed explicitly in
caller-defined monotonic ticks and therefore has no unit-assuming default; a
nanosecond-clock production profile uses `std.time.ns_per_hour` for the
one-hour policy. Configuration accepts only equally strong byte/packet values,
reserves bounded KEX headroom below the AES-CTR and sequence hard bounds, and
rejects zero/unsafe values.

Thresholds are checked at complete packet boundaries and KEXINIT becomes the
next locally initiated transport packet. Already committed nonblocking
packet/event transitions finish, while channel and new application output is
gated. Simultaneous KEXINIT is coordinated without a duplicate offer or loss
of either exact hashed payload. Directional byte, packet, and activation-time
state resets only when that direction activates `NEWKEYS`; SSH sequence
numbers remain session-global across rekey.

The AES-CTR byte position and sequence increment are checked rather than
wrapping. `KeyLifetimeExceeded` terminates before a hard bound can be reused.
Tests cover both local roles, simultaneous initiation, exact thresholds,
directional epochs, caller time, host/session continuity, hard-bound failure,
and compressed channel traffic across automatic rekey.

**Remaining production requirement:** applications must configure the
one-hour-equivalent tick duration, drive `tick` from a trustworthy monotonic
clock, and close the transport after terminal errors.

## Dependencies and randomness

sshz currently has no package dependency in `build.zig.zon`. It depends on:

- Zig standard-library implementations of SHA-2, HMAC, X25519, Ed25519,
  ECDSA P-256, AES, bcrypt, and finite-field operations used for RSA;
- sshz's own AES-CTR state wrapper, SSH key derivation, RSA PKCS#1 v1.5
  encoding, parsing, and protocol composition;
- system zlib for `zlib@openssh.com`; and
- a cryptographically secure `std.Random` supplied by the embedding
  application for KEX keys, cookies, and packet padding.

These are trusted dependencies, not evidence of independent validation. The
minimum build version is Zig 0.16.0, while newer compilers and system zlib
versions are not locked by this repository. Before production, maintainers
must pin and inventory the supported toolchain/dependency versions, monitor
security advisories, review the custom composition code, and decide whether
the Zig/system implementations are sufficiently reviewed or an external
cryptographic backend is required. Predictable randomness is outside the
production contract.

## Current test evidence and missing vectors

Existing unit tests provide useful positive evidence:

- complete in-process handshakes with Ed25519, ECDSA P-256, and 2048-bit RSA
  host/user keys;
- signature round trips and tampered-message rejection;
- AES-CTR streaming round trips plus wrong-key and wrong-IV checks;
- MAC match, mismatch, and wrong-length checks;
- delayed-zlib round trips, size bounds, and malformed-stream rejection;
- client/server algorithm-ordering, required-category rejection, name-list
  grammar, guessed-packet, host-key, and compression checks;
- peer/local/simultaneous rekey session-ID, host-binding, key-boundary,
  threshold, traffic-gating, hard-bound, and under-load checks; and
- OpenSSH/libssh interoperability; libssh is optional for a local runner
  invocation and required by the current Linux CI configuration.

The generic SHA-256 hasher has standalone fixed known-answer digest tests.
Tests also cover RFC 4253 key derivation with fixed expected output, the RFC
4231 HMAC-SHA-256 vector, the NIST SP 800-38A AES-256-CTR vector, and an RFC
8032 Ed25519 signature carried in SSH signature encoding. Private-key fixtures
check expected decoded bytes. **Gap:** independent published vectors are still
needed for X25519 plus the exchange hash, ECDSA and RSA SSH signature
encodings, SSH packet-level MAC composition, and delayed zlib framing.

## Compatibility impact

The narrow allowlist intentionally rejects old SSH peers that require SHA-1
KEX or signatures, DSA, CBC/3DES/RC4, weak MACs, immediate compression, RSA
keys below the enforced 2048-bit minimum, or RSA keys above the enforced
4096-bit maximum. RSA peers must support RFC 8332 SHA-2 signatures; an
`ssh-rsa` key blob does not imply acceptance of an `ssh-rsa` signature.

Modern peers may still fail if they disable AES-CTR or non-EtM HMAC, require an
AEAD cipher, require strict KEX, expose only an unsupported private-key format,
or require RSA/SHA-256 user-auth fallback. This is preferable to an automatic
weak fallback. Compatibility changes must be explicit release-note items.

## Updating and deprecating the policy

Every allowlist change requires:

1. a tracked security issue with protocol references, rationale, cryptographic
   and implementation review, key-size/lifetime decisions, and compatibility
   analysis;
2. independent known-answer or published vectors, malformed-input and negative
   negotiation tests, and client/server interoperability evidence;
3. updates to this policy, the README feature list when applicable, and the
   threat model;
4. a dependency and side-channel assessment; and
5. release notes identifying additions, removals, preference changes, and
   migration steps.

Routine removals should be announced for at least one release when security
allows. Algorithms may be disabled or removed immediately in response to a
credible vulnerability. Deprecation must never mean retaining an undocumented
fallback, and a removed name must fail closed.

## Production release criteria

The algorithm-policy part of a production release is complete only when:

- implementation and tests match the exhaustive allowlist in both roles and
  directions;
- the RSA 2048-bit minimum and complete key validation are enforced;
- the strict-KEX decision is resolved;
- automatic byte/time/packet rekey limits and hard bounds prevent counter
  reuse, with a production key-age duration configured by the application;
- delayed compression has a reviewed safe default and application policy;
- independent vectors cover KEX, exchange hash/key derivation, every signature
  family, packet cipher/MAC, and compression;
- negative downgrade tests cover every negotiation category and both roles;
- required OpenSSH, Dropbear, and libssh compatibility lanes pass;
- the cryptographic backend/toolchain/system-zlib decision is documented with
  supported versions; and
- the algorithm review finds no unresolved critical or high-severity issue.

These criteria satisfy only the algorithm-policy slice of
[issue #66](https://github.com/cataggar/sshz/issues/66). Every other blocker
in the [production threat model](threat-model.md#production-release-blockers)
must also be cleared. The README production warning must remain until then.
