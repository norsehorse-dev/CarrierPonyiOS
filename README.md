# CarrierPony for iOS

CarrierPony is a private messenger and secure file transfer app built on real OpenPGP
encryption. There is no phone number, no email, and no account. Your identity is an OpenPGP
key pair created on your device, and your private key never leaves it.

This repository holds the iPhone client. The app is also available on the App Store. The
Android client lives in [CarrierPonyAndroid](https://github.com/norsehorse-dev/CarrierPonyAndroid).

## How it works

Every message and every file is end-to-end encrypted with OpenPGP. Content is encrypted on
your device and only decrypted on your contact's device. Between the two, a store-and-forward
relay carries sealed envelopes: it sees a recipient fingerprint, an opaque message id, a
size, and timestamps, and nothing else. No names, no contents, no plaintext.

New accounts use OpenPGP v6 keys with an ML-KEM-768 + X25519 encryption subkey, so messages
to them are protected by a post-quantum and a classic algorithm together. Accounts made
before 4.0 keep their v4 Ed25519 and Curve25519 keys, and the two kinds can message each
other.

The relay is a separate, self-hostable component under its own Apache-2.0 license:
[CarrierPony-Relay](https://github.com/norsehorse-dev/CarrierPony-Relay). The client
authenticates to it with a challenge-response signature from your key, and a random
per-install id is the only device identifier it ever holds.

Pairing happens three ways. In person, one QR scan pairs both phones and marks the contact
verified, because the fingerprint travelled physically. Remotely, you send an invite over a
channel you already trust, and the invitee's app fetches your key from the relay and refuses
to add it unless it hashes to the fingerprint the invite carried. Or you add someone by their
public key, and they get a request to accept or decline. Either way you can compare a safety
number to be certain no one is in the middle.

## Layout

- `App/` holds the app entry point.
- `Core/` holds everything else: the envelope format, the crypto engine, the relay client,
  messaging, pairing and the SwiftUI screens. `Core/README.md` describes the lower layers.
- `CarrierPonyTests/` holds the unit tests, including envelopes and identities traded with
  the Android core.

All OpenPGP work goes through [NorseHorsePGPCore](https://github.com/norsehorse-dev/NorseHorsePGPCore),
which is called from one file, `Core/Crypto/PGPonyCryptoEngine.swift`.

## Building

You need Xcode 26 or later. The app targets iOS 18.6.

The project uses two Swift packages by local path, so clone them where it expects them or
point the package references at your own checkouts in Xcode:

- [NorseHorsePGPCore](https://github.com/norsehorse-dev/NorseHorsePGPCore) at
  `../../Documents/GitHub/NorseHorsePGPCore`, relative to this folder
- [PonyDirect](https://github.com/norsehorse-dev/PonyDirect) at `../PonyDirect`

To run on a device, set your own development team and bundle identifier in the target's
signing settings. Push notifications need the publisher's APNs key, so a build of your own
receives messages by polling while it is open.

Run the unit tests on a simulator:

```
xcodebuild test -project CarrierPony.xcodeproj -scheme CarrierPony -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Security

Report a vulnerability by email to NorseHorse@norsehor.se. Please do not open a public issue
for it.

## License

Apache-2.0. See [LICENSE](LICENSE).
