# Malformed protocol inputs

From the repository root, run the network-free corpus in both safety modes:

```sh
timeout 120s zig build malformed --summary all
timeout 120s zig build malformed -Doptimize=ReleaseSafe --summary all
```

`test/malformed.zig` contains 55 committed cases, with a hard ceiling of 64.
Each corpus input and each generated packet is limited to 512 bytes. A case
constructs at most one client state machine and one packet; there is no
network, retry loop, or unbounded input generation. The shell `timeout` is an
additional 120-second process bound, so a regression cannot hang a local or CI
job indefinitely.

## Determinism and reproduction

The fixed corpus seed is `0x604d414c464f524d`. Case `N` uses that seed plus
its zero-based corpus index for client initialization and packet padding.
Running either command above reproduces those exact bytes; the Zig test
runner's separately printed `--seed` does not alter the corpus. A failing case
logs its name and derived seed.

## Corpus categories

- **Transport framing:** identification grammar and limits, packet
  header/body/padding/block boundaries, truncated or corrupt MACs, corrupt
  zlib, SSH string/mpint bounds, message IDs, and overflow-safe readers and
  writers.
- **Key exchange:** truncated KEXINIT cookies, invalid and non-overlapping
  algorithm name-lists, ECDH replies in the wrong state or with trailing data,
  the short-ECDH regression, and NEWKEYS before negotiation.
- **Authentication:** service acceptance and success before a corresponding
  request/attempt, plus truncated failure, banner, and interactive-prompt
  fields.
- **Channel/state machine:** truncated DATA/EXTENDED_DATA, DATA in an invalid
  channel state, packet/window limit violations, window-adjust overflow,
  invalid open parameters, an unsolicited global success, truncated
  disconnect, and explicit peer/channel disconnect outcomes.

These are named protocol cases, not random byte mutation or fake fuzzing.
Every case declares one exact typed error or disconnect event and fails if the
handler instead succeeds, emits another outcome, panics, or exceeds a bound.

Peer-controlled failures retain their existing typed classifications:

| Input boundary | Error |
| --- | --- |
| Missing packet bytes | `IoError.notEnoughData` |
| Invalid length, padding, block size, or compressed bytes | `IoError.InvalidPacketSize` |
| Missing, incorrectly sized, or mismatched MAC | `IoError.InvalidMac` |
| Missing SSH string/mpint bytes | `BufferError.ReaderOutOfDataErr` |
| Invalid identification grammar/state | `IoError.UnexpectedResponse` |
| Unterminated/oversized identification line | `IoError.noEOLFound` |
| Unknown message identifier in strict framing inspection | `IoError.UnsupportedMessage` |
| Invalid or non-overlapping KEX name-list | `IoError.AlgorithmNegotiationFailed` |
| Invalid KEX/auth/channel transition | `IoError.UnexpectedResponse` |
| Channel packet or receive-window excess | `ChannelError.ChannelPacketTooLarge` / `ChannelError.ReceiveWindowExceeded` |
| Channel window arithmetic overflow | `ChannelError.WindowOverflow` |
| Invalid peer channel parameters | `IoError.InvalidChannelParameters` |
| Well-formed peer disconnect | `EndSession.ServerDisconnect` |
| Final channel close | `EndSession.Disconnect` |

Allocator, cryptographic, and compression-initialization failures are not
translated into peer-input errors; their original error values propagate.

The pinned Zig 0.16 distribution cannot currently compile its own fuzz test
runner because of a stack-trace type mismatch. No fake or non-working fuzz
target is provided; CI and the commands above run only the bounded fixed
corpus.
