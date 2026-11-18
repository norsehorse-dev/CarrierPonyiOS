import Foundation

#if DEBUG
// Two real v4 test identities ("alice" and "bob") from the PGPonyCore conformance
// suite (GnuPG 2.4.4, Ed25519 signing + Cv25519 encryption, unprotected). Baked
// in so two devices can run distinct identities, pair, and message over the live
// relay before the onboarding / key-generation flow exists. DEBUG-only; never
// ships in a release build.
//
// To test the full loop: load Alice on one device and Bob on the other, then pair
// BOTH ways (each scans the other's "My Code"), which is required so each side can
// verify the other's signatures.
enum DevIdentity {

    static let alice = make(
        fingerprint: "B671D9A8B401BB207C264787A18FB667413300FD",
        secretKeyB64: "lFgEakR4VBYJKwYBBAHaRw8BAQdAnznJbtIY8Bs9aN2/4mC9DkQMR5dA8YHjtCjUExtdGvgAAQCnCHFJweSajt3G37loPYhdCa7mhFwxl1PccEV6/ywPvhCXtB5hbGljZSA8YWxpY2VAY2FycmllcnBvbnkudGVzdD6IkwQTFgoAOxYhBLZx2ai0AbsgfCZHh6GPtmdBMwD9BQJqRHhUAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEKGPtmdBMwD9H78A/3yQdCMjIkhFr6/kwhazMIueOJmDKreaELNLSgNgPpzMAQDmfsjO8BddtXxtfYYfnScb7CoIPooO1pNVFUSlNJ9QAJxdBGpEeFQSCisGAQQBl1UBBQEBB0D2H4y+g5gcKfgaw9W4Z7XEqD014M80nkoY8OUfkkRGOgMBCAcAAP9ZOexF0/evyEbRxxm36vjIg4Zc8kHjYrWOcxHxG9WTYBPTiHgEGBYKACAWIQS2cdmotAG7IHwmR4ehj7ZnQTMA/QUCakR4VAIbDAAKCRChj7ZnQTMA/UAYAQDWJvUc1v7jjTxJA7dSTZoOC0HVUhZ3bK2gjYrZ+Jkb3gEArbSGVO/3UwsI7sJisCOYUHTfZv6Q4XUXq7j1Bzu9zgc=",
        armoredPublicKey: """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEakR4VBYJKwYBBAHaRw8BAQdAnznJbtIY8Bs9aN2/4mC9DkQMR5dA8YHjtCjU
ExtdGvi0HmFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PoiTBBMWCgA7FiEE
tnHZqLQBuyB8JkeHoY+2Z0EzAP0FAmpEeFQCGwMFCwkIBwICIgIGFQoJCAsCBBYC
AwECHgcCF4AACgkQoY+2Z0EzAP0fvwD/fJB0IyMiSEWvr+TCFrMwi544mYMqt5oQ
s0tKA2A+nMwBAOZ+yM7wF121fG19hh+dJxvsKgg+ig7Wk1UVRKU0n1AAuDgEakR4
VBIKKwYBBAGXVQEFAQEHQPYfjL6DmBwp+BrD1bhntcSoPTXgzzSeShjw5R+SREY6
AwEIB4h4BBgWCgAgFiEEtnHZqLQBuyB8JkeHoY+2Z0EzAP0FAmpEeFQCGwwACgkQ
oY+2Z0EzAP1AGAEA1ib1HNb+4408SQO3Uk2aDgtB1VIWd2ytoI2K2fiZG94BAK20
hlTv91MLCO7CYrAjmFB032b+kOF1F6u49Qc7vc4H
=CjfC
-----END PGP PUBLIC KEY BLOCK-----
"""
    )

    static let bob = make(
        fingerprint: "61D27B04E1E90899E8D162824891888765D64C51",
        secretKeyB64: "lFgEakR4VBYJKwYBBAHaRw8BAQdAKcGxRPM6atQb5K6tQv+XHxBSXyXwWBjNkBzsW+Ddlf4AAP45Tbo3jwG7Tmpp2L0xN6f99yVVSXMorIWukcoIoP0+sRCltBpib2IgPGJvYkBjYXJyaWVycG9ueS50ZXN0PoiTBBMWCgA7FiEEYdJ7BOHpCJno0WKCSJGIh2XWTFEFAmpEeFQCGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQSJGIh2XWTFHBlgEA6iDEiZ/hxnV4r19ruAjOdrZic7Zi+R8y2LGT+2dUi0MBAJYgRZTWAkSKm5DuCcV2Vp0pJNF25EvUsW6vu5xkVsYInF0EakR4VBIKKwYBBAGXVQEFAQEHQBtEr1ZnxhJhb5ICeVeaPx1W2RA/PEc80vvoVU/0LS8SAwEIBwAA/1VL2Ab2l90G6nDyFaNuRz8WqyNTSBjRU/Q4la/zcjcYD8SIeAQYFgoAIBYhBGHSewTh6QiZ6NFigkiRiIdl1kxRBQJqRHhUAhsMAAoJEEiRiIdl1kxRPawBANPE0wdUKnfk6jxnxCEql4O+mhDiFAeGKgRKEQSQJAU2AQCaTw+EU5x+TIKB2cYJnk8uxYCwz60fxhP7s1sgMAlZCA==",
        armoredPublicKey: """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEakR4VBYJKwYBBAHaRw8BAQdAKcGxRPM6atQb5K6tQv+XHxBSXyXwWBjNkBzs
W+Ddlf60GmJvYiA8Ym9iQGNhcnJpZXJwb255LnRlc3Q+iJMEExYKADsWIQRh0nsE
4ekImejRYoJIkYiHZdZMUQUCakR4VAIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIe
BwIXgAAKCRBIkYiHZdZMUcGWAQDqIMSJn+HGdXivX2u4CM52tmJztmL5HzLYsZP7
Z1SLQwEAliBFlNYCRIqbkO4JxXZWnSkk0XbkS9Sxbq+7nGRWxgi4OARqRHhUEgor
BgEEAZdVAQUBAQdAG0SvVmfGEmFvkgJ5V5o/HVbZED88RzzS++hVT/QtLxIDAQgH
iHgEGBYKACAWIQRh0nsE4ekImejRYoJIkYiHZdZMUQUCakR4VAIbDAAKCRBIkYiH
ZdZMUT2sAQDTxNMHVCp35Oo8Z8QhKpeDvpoQ4hQHhioEShEEkCQFNgEAmk8PhFOc
fkyCgdnGCZ5PLsWAsM+tH8YT+7NbIDAJWQg=
=dSfD
-----END PGP PUBLIC KEY BLOCK-----
"""
    )

    /// Back-compat single accessor (Alice).
    static var identity: Identity? { alice }

    private static func make(fingerprint: String, secretKeyB64: String, armoredPublicKey: String) -> Identity? {
        guard let fp = Fingerprint(fingerprint),
              let secret = Data(base64Encoded: secretKeyB64),
              !armoredPublicKey.isEmpty else {
            return nil
        }
        return Identity(fingerprint: fp, secretKey: secret, armoredPublicKey: armoredPublicKey)
    }
}

extension AppModel {
    /// Install the baked-in Alice identity. DEBUG only.
    func installDevIdentity() {
        if let identity = DevIdentity.alice { setIdentity(identity) }
    }
}
#endif
