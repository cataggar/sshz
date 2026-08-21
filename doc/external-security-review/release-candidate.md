# Pinned security-review release candidate

No such candidate has yet been pinned and no independent external review has
occurred. [Issue #70](https://github.com/cataggar/sshz/issues/70) was rescoped
to a maintainer-led review and closure as not planned. A future independent
review remains a separate production-release requirement and must complete this
signed-RC procedure.

## Candidate record

Copy this section into the private review record and replace every placeholder.
An unfilled field means the candidate is not pinned.

```text
review_id: <REVIEW-ID>
repository: https://github.com/cataggar/sshz
candidate_commit_sha: <FULL-40-HEX-COMMIT>
candidate_tag: <ANNOTATED-SIGNED-RC-TAG>
tag_object_sha: <FULL-TAG-OBJECT-SHA>
tag_signer_identity_or_key_fingerprint: <VERIFIED-SIGNER>
scope_package_commit_sha: <FULL-40-HEX-COMMIT>
source_archive_sha256: <SHA256>
evidence_bundle_sha256: <SHA256>
created_utc: <YYYY-MM-DDTHH:MM:SSZ>
supersedes_candidate: <NONE-OR-PRIOR-REVIEW-ID/COMMIT>
status: <PINNED|SUPERSEDED|WITHDRAWN>
```

Do not use a branch name, pull request head, abbreviated SHA, moving tag, or
dirty working tree as the reviewed identity. The tag should be an annotated,
signed release-candidate tag such as `vX.Y.Z-rc.N`; project maintainers select
the actual version. Record both the tag object and peeled commit because an
annotated tag is a separate Git object.

## Toolchain and dependency record

The repository requires Zig 0.16.0 or newer. `build.zig.zon` pins the Zig
source package `https://github.com/cataggar/zlib` at commit
`b4e57365ac3c84121c99a51c54eb02a5e4b16c86` with package hash
`zlib-1.3.2-Nw5YbZEKNwAuh6XJs-vzogSoSv5jdL3PBhOI98q_QUu0`; `build.zig`
builds and statically links its `z` artifact. CI pins and verifies SHA-256
digests for each downloaded Zig 0.16.0 toolchain archive before extraction and
execution. System packages and runner images are not immutably pinned. These
facts remain incomplete release pinning, not permission to record `latest`.

For each candidate, record:

```text
zig_version: <EXACT>
zig_executable_sha256: <SHA256>
zig_distribution_url: <URL>
zig_archive_sha256: <SHA256>
target_triple: <EXACT>
optimize_mode: <Debug|ReleaseSafe|...>
os_image_and_kernel: <EXACT>
libc_implementation_and_version: <EXACT>
zlib_source_repository_commit_and_package_hash: <EXACT>
openssh_client_and_server_version: <EXACT-OR-NOT-INSTALLED>
dropbear_version: <EXACT-OR-NOT-INSTALLED>
libssh_version: <EXACT-OR-NOT-INSTALLED>
zig_package_dependencies: <NONE-OR-NAME/VERSION/DIGEST/LINK>
environment_or_container_digest: <IMMUTABLE-DIGEST-OR-MISSING>
```

Retain the Zig archive or immutable download reference and checksum. Retain the
OS/container lock data or image digest and package-manager version output.
Record `missing/unpinned` honestly where the current infrastructure cannot
reconstruct an input; do not infer dependency versions from filenames.

## Pinning procedure

1. Merge all intended code, tests, build, security documentation, and review
   scope before selecting a candidate.
2. Start from a fresh checkout, fetch tags, detach at the full candidate SHA,
   and require no tracked, untracked, staged, or ignored-source substitutions.
   Build caches and evidence must be created only after the clean check.
3. Create and sign an annotated RC tag. Publish neither a mutable replacement
   tag nor a branch-only identity. Verify the signature and equality below on
   the evidence host.
4. Capture source, toolchain, dependency, platform, environment, test, and
   interop evidence. Record unavailable tools as incomplete.
5. Create a deterministic source archive from the commit, hash it, hash the
   final evidence bundle, and give the reviewer immutable read access.
6. Freeze the scope. Any later source, test, build, dependency, configuration,
   compiler, security-document, patch, or generated-input change creates a new
   commit and new RC tag and repeats this procedure.

Run from the repository root, replacing placeholders:

```bash
set -euo pipefail
RC_COMMIT='<FULL-40-HEX-COMMIT>'
RC_TAG='<ANNOTATED-SIGNED-RC-TAG>'

git fetch --tags --force
git switch --detach "$RC_COMMIT"
test "$(git rev-parse HEAD)" = "$RC_COMMIT"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
git verify-tag "$RC_TAG"
test "$(git rev-parse "$RC_TAG^{commit}")" = "$RC_COMMIT"
git rev-parse "$RC_TAG"
git rev-parse "$RC_TAG^{commit}"
```

If signature verification is unavailable or fails, the candidate is not pinned.
The clean-tree check is required before creating `review-evidence/`.

## Evidence commands

These are the checked-in evidence entry points that currently exist. Run them
on the pinned candidate with unsafe secret tracing disabled. In addition to the
unit suite, `zig build malformed` runs the bounded deterministic
transport/parser/state corpus, `zig build stress` runs the fixed-seed in-process
acceptance, and `zig build soak` is the duration/seed/peer-selected entry point
used by the scheduled workflow. The deterministic malformed corpus is not a
coverage-guided fuzz campaign: the pinned Zig 0.16 compiler fuzz runner
currently has a `builtin.StackTrace`/`debug.StackTrace` incompatibility.

```bash
set -euo pipefail
EVIDENCE_DIR="$PWD/review-evidence"
RC_COMMIT="$(git rev-parse HEAD)"
mkdir -p "$EVIDENCE_DIR/interop" "$EVIDENCE_DIR/stress"

git archive --format=tar --prefix="sshz-$RC_COMMIT/" "$RC_COMMIT" \
  | gzip -n >"$EVIDENCE_DIR/source.tar.gz"
sha256sum "$EVIDENCE_DIR/source.tar.gz" \
  >"$EVIDENCE_DIR/source.tar.gz.sha256"

{
  date -u +%Y-%m-%dT%H:%M:%SZ
  git rev-parse HEAD
  git status --porcelain=v1 --untracked-files=all
  zig version
  zig env
  sha256sum "$(command -v zig)"
  uname -a
  grep -A4 '\.zlib = ' build.zig.zon
  ssh -V
  sshd -V
  dropbear -V
  pkg-config --modversion libssh
} >"$EVIDENCE_DIR/environment.log" 2>&1 || true

set -o pipefail
zig build test -Dunsafe-secret-tracing=false 2>&1 \
  | tee "$EVIDENCE_DIR/unit.log"
zig build malformed -Doptimize=Debug -Dunsafe-secret-tracing=false \
  --test-timeout 30s --seed 0 2>&1 \
  | tee "$EVIDENCE_DIR/malformed-debug.log"
zig build malformed -Doptimize=ReleaseSafe -Dunsafe-secret-tracing=false \
  --test-timeout 30s --seed 0 2>&1 \
  | tee "$EVIDENCE_DIR/malformed-release-safe.log"
zig build -Doptimize=ReleaseSafe -Dunsafe-secret-tracing=false 2>&1 \
  | tee "$EVIDENCE_DIR/library-release-safe.log"
(cd sshz && zig build -Doptimize=ReleaseSafe) \
  2>&1 | tee "$EVIDENCE_DIR/sshz-release-safe.log"
(cd sshzd && zig build -Doptimize=ReleaseSafe) \
  2>&1 | tee "$EVIDENCE_DIR/sshzd-release-safe.log"

/usr/bin/time \
  -f "resource elapsed_seconds=%e max_rss_kib=%M exit=%x" \
  -o "$EVIDENCE_DIR/stress/resource.txt" \
  zig build stress -Doptimize=ReleaseSafe -Dunsafe-secret-tracing=false -- \
    --seed 1751547392 2>&1 | tee "$EVIDENCE_DIR/stress/stress.log"

SSHZ_INTEROP_ARTIFACTS="$EVIDENCE_DIR/interop" \
SSHZ_INTEROP_KEEP_ARTIFACTS=1 \
SSHZ_INTEROP_REQUIRE_DROPBEAR=1 \
SSHZ_INTEROP_REQUIRE_LIBSSH=1 \
zig build interop 2>&1 | tee "$EVIDENCE_DIR/interop.log"

find "$EVIDENCE_DIR" -type f ! -name SHA256SUMS -print0 \
  | sort -z | xargs -0 sha256sum >"$EVIDENCE_DIR/SHA256SUMS"
```

The environment inventory deliberately continues when a version command is
absent so the log shows the gap. The build, unit, malformed, stress, and
required interop commands must not continue on failure. The OpenSSH, Dropbear,
and libssh lanes are all release evidence; `zig build interop` is made
fail-closed for Dropbear/libssh by the required environment variables above.

The packaged libssh on the current Azure Linux development host is locally
defective. Record that as an environment failure rather than a sshz protocol
finding; the required Ubuntu CI libssh implementation is conforming. A
candidate still needs a passing required Ubuntu lane—local failure does not
waive it.

Also retain immutable CI workflow/run/job URLs, logs, and artifact IDs. The
required scheduled evidence is:

- the fixed-seed ReleaseSafe stress PR/CI job for the candidate;
- a 20-minute OpenSSH soak from the twice-weekly schedule; and
- both 20-minute Dropbear and libssh lanes from the weekly schedule.

For each soak record candidate SHA, workflow/run/job IDs, exact command,
duration, seed, peer, result, resource observations, and safe artifact hashes.
A workflow definition or green summary is not evidence that the pinned
candidate completed those runs. For any later fuzz campaign, record its exact
repository/revision, command, seed/corpus digest, duration, resource limits,
sanitizer/instrumentation, target, result, and artifact hashes.

## Artifact contents and retention

The evidence bundle must contain:

- completed candidate and dependency records;
- verified tag output, clean-tree output, source archive and hashes;
- full stdout/stderr and exit status for every evidence command;
- machine-readable test results if available, crash inputs, minimized
  reproducers, seeds/corpora, interop logs, and environment/package inventory;
- reviewer scope amendments, report, finding index, maintainer dispositions,
  fix commits, accepted-risk records, and independent retest reports; and
- a checksum manifest and access-control/handling note. Never include real
  credentials, private deployment keys, tokens, or unrelated user data.

Keep the original and every superseding candidate bundle immutable for at least
two years after the later of the associated release date or candidate
withdrawal. Keep critical/high finding and retest evidence for the supported
lifetime of every affected release and at least two years afterward. A public
release may publish a redacted report, but redaction must not replace the
access-controlled original.

## Fixes and re-pinning

A reviewed fix changes the reviewed object. It must never be patched into the
old tag or described as covered by the old report:

1. Link finding ID, fix commit, tests, and reviewer-requested validation.
2. Merge the fix and any associated test, build, dependency, scope, or document
   updates into a new commit.
3. assign a new RC tag and review ID; mark the previous record `SUPERSEDED`
   without deleting or mutating it;
4. repeat clean checkout, tool/dependency inventory, all applicable evidence
   commands, source/evidence hashes, and release-gate evaluation; and
5. obtain independent retest evidence against the new full SHA. Record whether
   the retest is narrow or regression-wide and which old evidence, if any,
   remains applicable.

Changes made only to evidence tooling also require a re-pin if their results
are used for the review. Documentation-only changes after reviewer handoff
require a re-pin when they alter scope, trust boundaries, supported
configuration, limitations, findings, risk, or release criteria.
