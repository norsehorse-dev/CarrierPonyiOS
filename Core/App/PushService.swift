import UIKit
import UserNotifications

// Contentless push. We ask for notification permission, register for remote
// notifications, and hand the APNs device token to the relay via the existing
// register-push endpoint. The relay sends a generic "New message" alert with no
// sender or content, so nothing about a message is revealed by the notification.

@MainActor
final class PushService {
    static let shared = PushService()

    private(set) var token: String?
    var onToken: ((String) -> Void)?

    /// Fetch the inbox now. Set by AppModel once a store exists. Invoked when a
    /// push arrives, including while the app is backgrounded, which is the only
    /// way a message can land without the user opening the app first.
    var onPush: (() async -> Void)?

    func setToken(_ hex: String) {
        token = hex
        onToken?(hex)
    }

    /// Ask for permission (once, remembered by the system) and register for a token.
    func requestAndRegister() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { granted, _ in
            guard granted else { return }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
}

// Minimal app delegate, attached via @UIApplicationDelegateAdaptor. Receives the
// APNs device token, and wakes the app to fetch when a push arrives.
final class PushDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in PushService.shared.setToken(hex) }
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        // No push this launch; messaging still works via foreground polling.
    }

    // Woken by a push. Without this the notification is decorative: backgrounding
    // cancels the poll task, so nothing fetches until the user foregrounds the app
    // and a message can sit undelivered for as long as the app stays closed.
    //
    // Requires two things outside this file to actually fire in the background:
    // the remote-notification background mode (set in the build settings), and a
    // payload carrying content-available: 1 from the relay. An alert-only push
    // does not wake the app.
    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        Task { @MainActor in
            guard let fetch = PushService.shared.onPush else {
                completionHandler(.noData)
                return
            }
            await fetch()
            completionHandler(.newData)
        }
    }
}
