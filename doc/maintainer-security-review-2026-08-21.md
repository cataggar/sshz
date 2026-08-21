# Maintainer-led security review — 2026-08-21

## Review identity and limits

This record documents the maintainer-led review performed for
[issue #70](https://github.com/cataggar/sshz/issues/70) on 2026-08-21. The
original audited base was commit
`9cfc88118a7872944ab3e841f31ad6e2e6cddade`.

That base was **not** found clean. The remediations described below are in the
commit containing this record; they must not be attributed to the audited base
commit. No signed release candidate was reviewed, and no independent or
external security review occurred. This maintainer review is useful internal
evidence but does not satisfy the separate independent-review production-release
requirement.

## Scope and methods

The review covered the SSH transport and role state machines, authentication
and application authorization boundaries, channel-open and channel-request
handling, key-exchange encoding and derivation, build dependencies, CI
toolchain acquisition, and available stress/soak evidence. Methods included:

- manual source and API-boundary review against RFC 4251, RFC 4253, RFC 4254,
  and RFC 4256 behavior relevant to the implementation;
- tracing attacker-controlled packet fields through parsing, state
  transitions, events, decisions, and replies;
- checking fail-closed behavior for unsupported authentication and
  unauthorized channel operations;
- reviewing mpint encoding used by the exchange hash and key derivation;
- auditing declared source dependencies and executable CI downloads; and
- triaging the failed scheduled soak and adding focused negative/regression
  tests with each code remediation.

The review did not provide independent cryptographic validation, a complete
timing audit, coverage-guided fuzzing, a complete independent-vector set,
independent retesting, a signed/pinned candidate, or replacement passing soak
evidence.

## Findings and dispositions

| Severity | Finding | Disposition in this change | Remaining evidence |
| --- | --- | --- | --- |
| High | Server keyboard-interactive requests could reach an application authorization event without the RFC 4256 challenge-response exchange, allowing an application approval to authenticate an unproven request. | Server keyboard-interactive is no longer advertised or accepted. It remains unsupported until the RFC 4256 exchange is implemented. Negative tests cover rejection and prevent channel access. | Independent review and retest remain absent. |
| High | Incoming server-side `session` channels were confirmed automatically, bypassing the application's channel authorization policy. | Every incoming session channel now emits `ChannelOpenRequest` and requires explicit `acceptChannelOpen` or `rejectChannelOpen`; clearing the event cannot approve it. Tests cover the decision boundary. | Independent review and retest remain absent. |
| Medium | Session-only requests could be accepted on `direct-tcpip` or `forwarded-tcpip` channels. | Session-only request names are rejected at the protocol boundary on forwarding channels, with `SSH_MSG_CHANNEL_FAILURE` when requested. Tests cover both forwarding channel kinds and the affected request names. | Independent review and retest remain absent. |
| Medium | CI downloaded and executed Zig archives without verifying their contents. | SHA-256 digests are pinned and verified before extraction in build and soak workflows for each supported runner archive. | Runner images and system packages are still not immutably pinned; release provenance remains incomplete. |
| Product defect found by soak | A shared X25519 secret beginning with zero bytes was encoded as a non-canonical SSH mpint. This changed the exchange hash/key derivation and caused peer signature verification to fail with `InvalidSignature`. | Positive mpint writers now remove redundant leading zero bytes, add a sign-protection byte only when required, and encode zero canonically. Regression tests cover buffer and hash-input mpint encoding. | The failed evidence is [run 32330117112, job 96309001974](https://github.com/cataggar/sshz/actions/runs/32330117112/job/96309001974). A successful replacement soak against the resulting fix is still required. |

## Dependency and evidence status

zlib is not a system-library-only or dependency-free input. `build.zig.zon`
pins the Zig source package `https://github.com/cataggar/zlib` at commit
`b4e57365ac3c84121c99a51c54eb02a5e4b16c86` with package hash
`zlib-1.3.2-Nw5YbZEKNwAuh6XJs-vzogSoSv5jdL3PBhOI98q_QUu0`; `build.zig`
builds and statically links its `z` artifact. CI separately pins SHA-256
digests for downloaded Zig 0.16.0 toolchain archives and verifies them before
execution.

This review does not approve production use. Missing evidence includes an
independent review and retest, complete published vectors, complete timing
analysis, coverage-guided fuzzing, a passing replacement soak for the defect
above, and a signed, reproducible release candidate.
