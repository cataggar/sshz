# Stress and soak testing

The required stress test drives `SshzClient` and `SshzServer` through
their public APIs over a deterministic, in-memory full-duplex transport. Core
acceptance does not depend on the `mssh` or `msshd` process lifecycle.

## Commands

Run the required smoke test:

```sh
zig build stress -Doptimize=ReleaseSafe -- --seed 1751547392
```

Run a duration-based soak:

```sh
zig build soak -Doptimize=ReleaseSafe -- \
  --duration-seconds 1200 --seed 1751547392 --peer internal
```

`--peer` accepts `internal`, `openssh`, `dropbear`, `libssh`, or `all`.
Peer modes run the in-process acceptance first, then repeatedly invoke the
existing isolated interop fixture. Dropbear and libssh selections make their
existing lanes required; they never weaken or silently replace those lanes.
Soak seeds must be in the range `0..9223372036854775807`.

Both commands print the seed and an exact rerun command. The stress output also
prints scenario counts, byte counts, SHA-256 digests, key epochs/rekey count,
and progress heartbeats. It never prints payloads, credentials, private keys,
session keys, or secret tracing.

## Deterministic scenarios

The smoke acceptance includes:

- 100 complete client/server connect, none-auth, and alternating-order
  disconnect/deinitialization cycles;
- four simultaneously active channels carrying strict round-robin traffic;
- 32 MiB in each direction, with per-channel ordering checks, byte counts,
  deterministic content validation, and combined SHA-256 verification;
- repeated exhaustion of a 32 KiB advertised channel window by 16 KiB packets,
  followed by verified progress only after window replenishment;
- sustained application traffic crossing a 2 MiB automatic-rekey threshold,
  with `keyLifetimeStatus()` proving all client/server inbound/outbound epochs
  advanced and reporting a nonzero rekey count; and
- eight named-by-index EOF/close/transport-disconnect schedules: six drain both
  SSH close handshakes and two drop the in-memory transport with opposite
  endpoint teardown orders.

The 32 MiB directions are sent sequentially through the same four still-active
channels. This preserves deterministic ordering while testing both directions
without conflating the acceptance result with scheduler timing.

## CI policy

Linux pull requests run the fixed-seed ReleaseSafe stress acceptance as a
separate required job with a 12-minute job timeout. The acceptance semantics
are not reduced to fit the ordinary unit-test job.

The `Stress and soak` workflow runs:

- a 20-minute OpenSSH soak twice weekly;
- a separate weekly, `fail-fast: false` Dropbear/libssh matrix; and
- manual runs with selectable duration, seed, and peer.

Scheduled and manual jobs have 35-minute timeouts and use ReleaseSafe. GNU
`time` records elapsed time and maximum RSS for child runs. Linux `/proc`
heartbeats record the orchestration shell's peak RSS and open FD count.

## Resource baseline and budgets

On 2026-07-24, a warm-cache Linux x86_64 ReleaseSafe run at seed `1751547392`
took 2.7 seconds and reported 41,036 KiB maximum RSS; an observed cold compile
and run took about 25 seconds. Based on that baseline, required CI uses broad,
non-flaky ceilings of 600 seconds and 1,048,576 KiB RSS, in addition to the
12-minute job timeout. Rebaseline on materially different Zig versions or
runner classes before tightening either value.

Soak RSS and FD values are evidence, not pass/fail budgets: peer tools and
host distributions have materially different resource profiles. Retain
multiple scheduled samples before introducing a peer-specific threshold.

## Diagnostics and artifact safety

Start with the printed rerun command and seed. Compare the last heartbeat,
scenario byte counts, hashes, window counts, and endpoint epochs. A hash or
ordering failure identifies a deterministic library/transport failure rather
than a shell-process timing failure.

Set `SSHZ_SOAK_ARTIFACTS` to choose an artifact root. The interop fixture
retains its existing per-run logs and runtime directory on failure. **Only
`*/logs/**` and the top-level stress/soak console log are approved for CI
upload.** Never upload the artifact root or runtime/private directories: they
can contain generated or copied private fixture material. CI uploads only the
explicit safe paths and retains them for seven days.

Unsafe secret tracing must remain disabled. Do not add packet dumps, payload
samples, environment dumps, command tracing (`set -x`), or credentials to
stress diagnostics.

## Environmental limits

- Peer modes require the same OpenSSH, Dropbear, libssh, compiler, account,
  and non-interactive privilege facilities documented by `interop/run.sh`.
- Dropbear account creation is Linux-specific. RSS and FD evidence uses Linux
  `/proc`; other hosts still run the deterministic driver without that evidence.
- Scheduled peer coverage supplements the in-process public-API acceptance.
  A peer failure can involve host packaging or process startup, while a core
  stress failure is independent of those processes.
- Duration is checked between complete interop iterations, so a peer run can
  finish slightly after the requested duration but remains bounded by the
  workflow timeout.
