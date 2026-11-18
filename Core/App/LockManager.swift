import Foundation
import Observation
import LocalAuthentication

// The app lock. When enabled, the UI is gated behind Face ID / Touch ID (with the
// device passcode as a fallback) on launch and whenever the app returns from the
// background. For an imported, passphrase-protected identity, a successful unlock
// also loads the key's passphrase into memory for the session; going to the
// background drops it again, so the passphrase is never resident while locked.

@MainActor
@Observable
final class LockManager {

    private let enabledKey = "cp.appLock.enabled"

    var isLocked: Bool = false
    private(set) var sessionPassphrase: String?

    var appLockEnabled: Bool {
        didSet { UserDefaults.standard.set(appLockEnabled, forKey: enabledKey) }
    }

    init() {
        appLockEnabled = UserDefaults.standard.bool(forKey: enabledKey)
    }

    var biometricsAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    /// Engage the lock (called on launch and when entering the background).
    func lockIfEnabled() {
        guard appLockEnabled else { return }
        isLocked = true
        sessionPassphrase = nil
        // An imported v6 identity's unlocked ML-KEM key goes with it.
        PGPonyCryptoEngine.forgetUnlockedKeys()
    }

    func lockNow() {
        isLocked = true
        sessionPassphrase = nil
        // An imported v6 identity's unlocked ML-KEM key goes with it.
        PGPonyCryptoEngine.forgetUnlockedKeys()
    }

    /// Hold a passphrase for the current session (e.g. right after import, so
    /// messaging works before the first lock/unlock cycle).
    func setSessionPassphrase(_ passphrase: String?) {
        sessionPassphrase = passphrase
    }

    func clearSessionPassphrase() {
        sessionPassphrase = nil
        PGPonyCryptoEngine.forgetUnlockedKeys()
    }

    /// Prompt for biometrics/passcode. On success, unlock and (for a protected
    /// identity) load its passphrase using the same authenticated context.
    func unlock(fingerprint: String?, protected: Bool) async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = "Enter Passcode"

        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            // No biometrics or passcode configured: don't strand the user.
            isLocked = false
            return true
        }

        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock CarrierPony")
            guard ok else { return false }
            if protected, let fingerprint {
                sessionPassphrase = PassphraseVault.read(fingerprint: fingerprint, context: context)
            }
            isLocked = false
            return true
        } catch {
            return false
        }
    }
}
