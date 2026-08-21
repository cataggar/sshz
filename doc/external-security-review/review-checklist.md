# External security review checklist

Use this checklist against the immutable candidate identified by
[the release-candidate procedure](release-candidate.md). Check a box only when
the supporting evidence is named. Use `N/A — reason` rather than silently
skipping an item. Record potential vulnerabilities through the
[finding process](findings-and-disclosure.md), not in this checklist if doing
so would disclose exploit details.

The 2026-08-21 [maintainer-led review](../maintainer-security-review-2026-08-21.md)
is completed internal evidence, but none of the independent-review boxes below
are checked by that work. A future reviewer must evaluate a newly pinned,
signed candidate and the maintainer remediations independently.

## Reviewer intake and scope

- [ ] Record review ID, reviewer organization/name, review dates, candidate
      commit SHA, signed/annotated tag, and evidence-bundle digest.
- [ ] Confirm the candidate commit and tag resolve to the same object and the
      checkout is clean.
- [ ] Confirm compiler, target, optimization mode, OS/architecture, libc,
      pinned zlib source revision/package hash, OpenSSH, Dropbear, and libssh
      versions are recorded, or mark an unavailable dependency/lane as missing
      evidence.
- [ ] Read the [package scope](README.md#exact-review-scope), [threat
      model](../threat-model.md), [algorithm
      policy](../algorithm-policy.md), and [timing
      inventory](../timing-sensitive-operations.md).
- [ ] Agree in writing on scope amendments, deliverables, severity rubric,
      private contact placeholders, and retest expectations before review.
- [ ] Verify excluded demos/infrastructure are not mistaken for reviewed
      production applications.

## Architecture, boundaries, and API

- [ ] Trace peer bytes from the application stream through identification,
      packet parsing, decryption/MAC, decompression, state machines, events, and
      outgoing framing.
- [ ] Check all assumptions at the network, application, dependency, allocator,
      randomness, logging, agent-socket, and OS boundaries.
- [ ] Verify every event requiring a security decision fails closed on reject,
      clear, wrong order, application error, and teardown.
- [ ] Check borrowed/owned slice lifetimes across events, partial I/O, reentry,
      replacement, and deinitialization.
- [ ] Verify public error and readiness behavior cannot deadlock, reuse stale
      state, or accept caller input outside the requested size/state.

## Transport and state machines

- [ ] Review identification grammar, line/count bounds, exact exchange-hash
      input, pre-identification input, and client/server asymmetry.
- [ ] Review packet length, padding, payload, MAC, sequence-number, compressed
      and channel-data bounds for overflow, truncation, wrap, and allocation or
      CPU amplification.
- [ ] Verify `src/protocol.zig` is the single enforcement path for algorithm
      offer grammar, exhaustive allowlists, mutual selection, and guessed-packet
      handling, and that both roles select every category/direction in client
      order without fallback.
- [ ] Verify MAC-before-use behavior, cipher/MAC ordering, failure teardown,
      directional state, and no unauthenticated plaintext is delivered.
- [ ] Exercise unexpected, duplicate, reordered, guessed-KEX, unknown,
      disconnect, debug, ignore, truncated, and out-of-state messages in both
      roles.
- [ ] Review initial, peer-initiated, automatic local, and simultaneous rekey;
      initial session-ID retention; accepted host-key binding; `NEWKEYS`
      boundaries; deferred traffic; compression reset; and session-global
      sequence-number behavior.
- [ ] Verify exact byte/packet thresholds, caller-clock key age, directional
      epoch resets, output gating, KEX headroom, and `KeyLifetimeExceeded`
      before AES-CTR or sequence hard-bound reuse.
- [ ] Check validated resource capacities, pre-auth/auth/KEX/global-request
      limits, channel/window/decompression bounds, handshake/auth/idle/total
      deadline driving, and stalled partial I/O. Distinguish per-session
      enforcement from application-wide admission limits.

## KEX, crypto use, and key handling

- [ ] Match advertised, selected, rejected, and signed algorithm names to the
      exhaustive [algorithm policy](../algorithm-policy.md), in both roles and
      directions.
- [ ] Verify X25519 public-key validation and shared-secret handling; exchange
      hash field order/encoding; session identifier; and A-F directional key
      derivation against independent vectors.
- [ ] Review randomness use for ephemeral keys, KEX cookies, and padding,
      including error behavior and the caller contract.
- [ ] Review Ed25519, P-256, and RSA public-key parsing, canonical encodings,
      key-family/name binding, signature encoding/verification, and RSA
      component, exponent, and modulus validation.
- [ ] Verify SHA-1, `ssh-rsa` signatures, weak/unknown algorithms, transport
      `none`, unsupported aliases, and empty intersections fail closed without
      fallback or downgrade.
- [ ] Review AES-256-CTR counter/state continuity, HMAC-SHA-256 key/sequence
      construction and comparison, encrypt-and-MAC implications, and key
      activation/replacement.
- [ ] Review OpenSSH private-key container bounds, metadata, one-key
      restriction, encrypted/unencrypted cases, bcrypt salt/rounds, passphrase
      failure, public/private consistency, trailing data, and scratch cleanup.
- [ ] Identify where security depends on Zig or pinned-zlib internals and
      compare candidate versions with advisories and upstream guarantees.

## Authentication and host identity

- [ ] Verify the client cannot authenticate before explicit host-key acceptance
      and rejection terminates without sending credentials.
- [ ] Verify `clearEvent(CheckHostKey)` cannot accept, `acceptHostKey()` and
      `rejectHostKey()` are state-bound, rejection reports
      `EndSession.HostKeyRejected`, and rekey rejects any changed key blob with
      `HostKeyChanged`.
- [ ] Check raw key/fingerprint ownership and the application's responsibility
      for names, ports, aliases, and trust stores.
- [ ] Review client method discovery/order, per-method/total attempt limits,
      partial success, retry stages, banners, password, public-key,
      keyboard-interactive, encrypted keys, and unsupported methods. Verify the
      server neither advertises nor accepts keyboard-interactive until a full
      RFC 4256 challenge-response exchange is implemented.
- [ ] Verify signed public-key proof precedes an authentication decision;
      unsigned probes require application authorization before `PK_OK` but
      cannot authenticate; malformed names/blobs/signatures cannot reach a
      permissive application decision.
- [ ] Verify password and `none` handling, service/user binding, advertised
      methods, common failure behavior, atomic `decideUserAuth`, compatibility
      `grantAccess` plus `clearEvent`, and fail-closed clearing of undecided
      `UserAuth` events.
- [ ] Check credentials, passphrases, usernames, key blobs, prompts, and
      authentication packets for excess copies, logs, stale events, and
      lifetime after success/failure.

## Channels, forwarding, and agent

- [ ] Review four-channel allocation, ID mapping/wrap, confirmation/failure,
      table reuse, fairness, per-channel isolation, and pending-open behavior.
- [ ] Verify remote/local windows, maximum packet sizes, fragmentation,
      extended data, adjustment arithmetic, backpressure, suffix retention, and
      cross-channel scheduling.
- [ ] Exercise EOF/close races, unconfirmed-channel close, duplicate controls,
      peer close during writes, error cleanup, and buffered-data zeroization.
- [ ] Review parsing and application authorization for session,
      `direct-tcpip`, and `forwarded-tcpip` opens and shell, exec, subsystem,
      environment, window-change, and signal requests. Verify session opens
      require explicit application approval and session-only requests are
      rejected on forwarding channels.
- [ ] Review `tcpip-forward`/`cancel-tcpip-forward`, allocated ports,
      `want_reply`, outstanding-request correlation, address/port validation,
      and fail-closed application decisions.
- [ ] Verify agent forwarding is opt-in, only authorized channel types are
      accepted, channel/data/close events remain bound, and the capability risk
      is clear to the application.
- [ ] Check unknown channel/global requests and unknown channel types fail
      safely with correct reply behavior and bounded diagnostic data.

## Zlib and compression

- [ ] Verify only `none` and delayed `zlib@openssh.com` negotiate, with client
      preference and independent directions handled correctly.
- [ ] Verify zlib remains inactive before authentication and activates at the
      correct success boundary for each role/direction.
- [ ] Review stream initialization/end/rekey behavior, partial flushes,
      incompressible maximum data, malformed/truncated/trailing streams, and
      output/CPU bounds.
- [ ] Assess post-authentication compression-oracle risks and the lack of an
      application opt-out; state whether delayed compression can remain the
      preferred default.
- [ ] Check zlib errors cannot expose stale plaintext, reuse corrupted state,
      panic, hang, or desynchronize packet/channel accounting.

## Memory hygiene and diagnostics

- [ ] Inventory each secret, owner, copy, temporary, allocation, event view,
      replacement, normal/error teardown path, and maximum lifetime.
- [ ] Inspect zeroization of shared/derived keys, private keys, passphrases,
      credentials, packet/decompression/channel buffers, KDF material,
      signatures, and crypto context state.
- [ ] Evaluate whether compiler optimization, allocator behavior, stack copies,
      unions, returned values, and library dependency APIs undermine intended
      zeroization.
- [ ] Exercise parse, allocation, authentication, KEX, compression, channel,
      and application-decision failures for leaks, double free, use-after-free,
      uninitialized use, or stale-secret reuse.
- [ ] Verify default builds compile out unsafe secret dumps and ordinary
      errors/logs cannot emit keys, plaintext, credentials, or sensitive packet
      contents. Treat `-Dunsafe-secret-tracing=true` as non-release.
- [ ] Consider crash dumps, core files, swap, process snapshots, and application
      logs in integration guidance; distinguish library guarantees from host
      controls.

## Side channels

- [ ] Extend the [timing inventory](../timing-sensitive-operations.md) beyond
      server authentication to all secret-dependent library and dependency
      operations.
- [ ] Review MAC equality, authorized-key/host-key lookup, credential and
      passphrase checks, private-key decryption checks, key parsing, signatures,
      RSA, KEX, and failure paths for secret-dependent branches/access/work.
- [ ] Compare success/failure packet shapes, method/username validity,
      application callback duration, compression behavior, and disconnect
      timing for remotely observable oracles.
- [ ] Separate public protocol distinctions from secret-dependent distinctions
      and record the attacker, measurement channel, noise assumptions, and
      practical impact for each concern.
- [ ] Treat constant-time claims in dependencies as version-specific evidence;
      do not infer them from API names alone.
- [ ] Record hardware/physical side channels as excluded while retaining remote
      and local software timing/cache behavior within scope.

## Evidence and reviewer handoff

- [ ] Run `zig build test` and retain its complete log, including the
      default-build unsafe-trace compile gate.
- [ ] Run `zig build malformed` in Debug and ReleaseSafe, retain the result for
      all 55 named cases, and map its transport/parser/state coverage and bounded
      typed outcomes. Record that coverage-guided fuzzing is blocked by the
      pinned Zig 0.16 fuzz runner's `StackTrace` incompatibility; do not
      misrepresent the deterministic corpus as fuzzing.
- [ ] Run required OpenSSH, Dropbear, and libssh lanes exactly as documented in
      [candidate evidence commands](release-candidate.md#evidence-commands), or
      mark each unavailable lane incomplete with the reason and versions.
      Distinguish the defective packaged libssh on the Azure development host
      from the conforming required Ubuntu CI lane.
- [ ] Run the required fixed-seed ReleaseSafe `zig build stress` acceptance and
      retain its counters, digests, epochs, resource measurement, and rerun
      command.
- [ ] Attach completed scheduled OpenSSH and Dropbear/libssh soak runs for the
      pinned candidate, including workflow/run IDs, candidate SHA, duration,
      seed, peer, logs, safe artifacts, and resource observations. A configured
      schedule or an ad hoc run is not completed soak evidence.
- [ ] Map each threat-model blocker and algorithm production criterion to
      evidence, a finding, an accepted-risk record, or `incomplete`.
- [ ] Deliver findings through the agreed private channel with stable IDs,
      severity, affected candidate/code, reproduction evidence, and suggested
      validation. Do not put sensitive details in a public issue.
- [ ] Sign or checksum the report and evidence bundle; state all limitations,
      exclusions, unavailable tools, and untested paths.

## Maintainer triage and release gate

- [ ] Acknowledge every finding and assign a maintainer owner and disposition
      using the required schema.
- [ ] Create a tracked issue/security item for every confirmed finding,
      following redaction and linking rules.
- [ ] Record rationale and approvals for accepted low/medium/informational
      risks; do not use acceptance to bypass the critical/high release gate.
- [ ] Re-pin the candidate after every reviewed code, test, build, dependency,
      configuration, or security-document change; retain the superseded
      candidate evidence.
- [ ] Obtain independent retest evidence against the re-pinned candidate for
      fixes; a fix author's local test alone is insufficient.
- [ ] Verify there are no unresolved critical/high findings and no critical/high
      retests that are missing, failed, or apply only to a superseded candidate.
- [ ] Keep incomplete evidence and all other production blockers visible; this
      checklist alone cannot authorize a production release.
