# Client host-key decision API

`CheckHostKey` is emitted only after the server has proved possession of the
presented key by signing the key exchange. The client must then call exactly
one of:

- `acceptHostKey()` to continue key exchange;
- `rejectHostKey()` to end the session with
  `EndSession.HostKeyRejected`, before authentication.

`clearEvent(CheckHostKey)` is no longer an acceptance operation and returns
`error.badClearEvent`. Leaving or trying to clear the event keeps the client
blocked; it cannot authenticate or open channels without explicit acceptance.

This is an intentional compatibility break for clients that previously
auto-accepted by clearing every event. Rekey does not prompt again, but each
signature-verified rekey key blob must match the initially accepted host
identity; a change fails with `error.HostKeyChanged`.
