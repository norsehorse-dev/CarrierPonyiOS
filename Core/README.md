# CarrierPony Core (iOS foundation)

The non-UI spine of the client. Everything here depends only on Foundation,
CryptoKit, and the `CryptoEngine` protocol. PGPonyCore is touched in exactly one
file.

## Layers

- `Envelope/CPN1.swift` — the length-prefixed container codec. Byte-exact with
  the envelope spec and `cp_envelope_harness.py`.
- `Envelope/Manifest.swift` — the manifest model and the deterministic pairwise
  `thread_id` (SHA-256 of the sorted fingerprints).
- `Crypto/CryptoEngine.swift` — the protocol the rest of the app codes against,
  plus `Fingerprint`, `PublicKey`, `VerifiedMessage`.
- `Crypto/PGPonyCryptoEngine.swift` — the only file that calls PGPonyCore. Four
  methods to fill: `armoredPublicKey`, `detachedSignature`, `signAndEncrypt`,
  `decryptAndVerify`, plus `fingerprint`.
- `Networking/RelayModels.swift`, `Networking/RelayClient.swift` — async client
  for the live relay API, with challenge-response auth.
- `Messaging/EnvelopeFactory.swift` — assembles outgoing and opens incoming
  envelopes. The Swift twin of the harness.

## Wiring order

1. Add PGPonyCore as a package dependency.
2. Implement `PGPonyCryptoEngine` against the active PGPony identity.
3. Prove conformance: this engine must open envelopes produced by
   `cp_envelope_harness.py`, and the harness must open envelopes this builds.
4. Then build QR pairing and the SwiftUI conversation UI on top.

## Conformance test worth writing first

A unit test that runs `CPN1.encode` then `CPN1.decode` on a text part plus a
random-bytes part and asserts the bytes survive. Then, once the crypto engine is
wired, a test that decodes a fixed envelope emitted by the Python harness.
