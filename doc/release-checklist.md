# Release checklist and platform matrix

This checklist gates a future production claim. Completing a build alone is
not sufficient. **MiSSHod is currently not secure and must not be used in
real-world systems.**

## Candidate checklist

### Scope and compatibility

- [ ] Choose the exact commit, Zig version, system zlib versions, supported
  targets, and artifact provenance; freeze the candidate.
- [ ] Review the candidate production surface in
  [the API contract](api-production.md); document every breaking/additive
  change and migration.
- [ ] Update version/compatibility and release notes; ensure demos, internal
  APIs, and experimental forwarding/agent APIs remain clearly marked.
- [ ] Build the production examples with `zig build production-examples` in
  Debug and ReleaseSafe without secret tracing.

### Correctness and interoperability

- [ ] Pass `zig build test` and the bounded malformed-input corpus in Debug and
  ReleaseSafe on every supported platform.
- [ ] Pass deterministic stress tests within recorded time/RSS budgets and the
  required duration/seed soak tests.
- [ ] Pass both client and server interoperability against pinned supported
  OpenSSH, Dropbear, and libssh versions; archive sanitized results.
- [ ] Exercise partial transport reads/writes, simultaneous read/write,
  disconnects at every phase, every authentication result, channel
  backpressure, EOF/close races, deadline boundaries, peer/local/simultaneous
  rekey, and allocator failures.
- [ ] Verify no test or example requires public-network access.

### Security

- [ ] Resolve every release blocker in the
  [threat model](threat-model.md) and [algorithm policy](algorithm-policy.md),
  or stop the release.
- [ ] Complete an independent cryptographic/protocol and memory-safety review;
  triage all findings and publish a disclosure contact/advisory plan.
- [ ] Run coverage-guided fuzzing with sanitizers where available over
  identification, framing, KEX, key parsing, authentication, compression,
  channel requests/data, rekey, and state transitions; record corpus,
  duration, toolchain, and zero unresolved crashes.
- [ ] Review timing-sensitive secret operations and credential/key erasure,
  logs, crash dumps, tracing options, artifacts, and dependency advisories.
- [ ] Verify fail-closed host-key, authentication, channel, forwarding,
  timeout, resource-exhaustion, and cleanup paths in the production examples.
- [ ] Generate and verify an SBOM/provenance record; pin dependencies and
  confirm release artifacts contain no fixtures, secrets, or unsafe tracing.

### Documentation and operations

- [ ] Reconcile README, API lifecycle, limits, algorithm policy, threat model,
  examples, and actual exported declarations.
- [ ] Publish concrete deployment profiles for limits/deadlines/rekey and
  process-wide admission control.
- [ ] Document supported host-key/user-key formats, peer versions, known
  limitations, upgrade/rollback, monitoring, incident response, and secure
  key rotation.
- [ ] Test examples with real policy backends in a private acceptance
  environment; examples remain illustrative, not certification.

### Release mechanics

- [ ] All required CI checks are green on the frozen commit; failures were not
  rerun away without root-cause review.
- [ ] Tag/sign the release and checksums using the documented maintainer
  process; independently verify source and binaries from a clean checkout.
- [ ] Obtain explicit security and release-owner sign-off, then publish the
  matrix and known limitations with the release.

## Platform matrix

“CI today” records repository coverage, not a support promise. A platform is
supported only when a release marks every required cell green.

| Platform | Architecture | CI today | Production-release requirement | Current status |
| --- | --- | --- | --- | --- |
| Linux (Ubuntu runner, glibc) | x86_64 | Unit/root builds, malformed corpus, deterministic stress, OpenSSH/Dropbear/libssh interop; scheduled soak | Debug + ReleaseSafe, fuzz/sanitizer evidence, interop and soak | Candidate coverage only |
| macOS runner | arm64 or x86_64, as supplied by GitHub | Unit/root, library, `mssh`, and `msshd` builds | Debug + ReleaseSafe, platform lifecycle/cleanup tests and supported-peer interop | Candidate coverage only |
| Linux | arm64 | None required today | Native unit/malformed/stress/interop/soak plus resource budgets | Unsupported |
| Windows | x86_64/arm64 | None | Port, native lifecycle tests, zlib/toolchain packaging, interop, security review | Unsupported |
| BSD/other Unix | any | None | Native full matrix and documented dependency/toolchain support | Unsupported |
| freestanding/embedded | any | None | Explicit port, entropy/storage/clock model, resource proof, protocol and security review | Unsupported |

For every supported row, record OS version, architecture, libc, Zig, zlib,
peer implementations, optimization mode, test/fuzz/soak identifiers, and known
exceptions. Cross-compilation alone does not satisfy a row; cleanup, clock,
entropy, socket, and allocator behavior require native validation.
