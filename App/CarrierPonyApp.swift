import SwiftUI
import UIKit

@main
struct CarrierPonyApp: App {
    @UIApplicationDelegateAdaptor(PushDelegate.self) var pushDelegate

    init() {
        #if DEBUG
        // Store screenshots: seed demo data before RootView builds AppModel.
        DemoSeed.seedIfRequested()
        #endif
        KeyboardDismissTap.shared.install()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}

// MARK: - Tap outside a text field to dismiss the keyboard (app-wide)

/// Adds one tap recognizer to each app window. A tap anywhere that isn't a text
/// input ends editing, so the keyboard never traps buttons underneath it.
/// The recognizer doesn't cancel touches, so buttons and links still fire.
/// Taps in the focused field's own row are ignored (keeps the chat send and
/// attach buttons working with the keyboard up), and so are taps in alerts.
@MainActor
final class KeyboardDismissTap: NSObject, UIGestureRecognizerDelegate {
    static let shared = KeyboardDismissTap()
    private static let recognizerName = "CPKeyboardDismissTap"
    private var observer: NSObjectProtocol?
    private var editingObservers: [NSObjectProtocol] = []
    /// The text field or text view being edited right now, tracked from UIKit's
    /// begin/end editing notifications. Checking this on each touch replaces a
    /// walk of the whole window's view tree, which ran on every touch (scrolls
    /// included) and got slow in long conversations.
    private weak var editingView: UIView?

    func install() {
        guard observer == nil else { return }
        let center = NotificationCenter.default
        let begin = { [weak self] (note: Notification) in
            let view = note.object as? UIView
            MainActor.assumeIsolated { self?.editingView = view }
        }
        let end = { [weak self] (note: Notification) in
            let view = note.object as? UIView
            MainActor.assumeIsolated {
                if let self, self.editingView === view { self.editingView = nil }
            }
        }
        editingObservers = [
            center.addObserver(forName: UITextField.textDidBeginEditingNotification, object: nil, queue: .main, using: begin),
            center.addObserver(forName: UITextView.textDidBeginEditingNotification, object: nil, queue: .main, using: begin),
            center.addObserver(forName: UITextField.textDidEndEditingNotification, object: nil, queue: .main, using: end),
            center.addObserver(forName: UITextView.textDidEndEditingNotification, object: nil, queue: .main, using: end),
        ]
        observer = NotificationCenter.default.addObserver(
            forName: UIWindow.didBecomeKeyNotification, object: nil, queue: .main
        ) { [weak self] note in
            guard let window = note.object as? UIWindow else { return }
            MainActor.assumeIsolated { self?.attach(to: window) }
        }
    }

    private func attach(to window: UIWindow) {
        if window.gestureRecognizers?.contains(where: { $0.name == Self.recognizerName }) == true { return }
        let tap = UITapGestureRecognizer(target: self, action: #selector(handleTap(_:)))
        tap.name = Self.recognizerName
        tap.cancelsTouchesInView = false
        tap.delaysTouchesBegan = false
        tap.delaysTouchesEnded = false
        tap.delegate = self
        window.addGestureRecognizer(tap)
    }

    @objc private func handleTap(_ recognizer: UITapGestureRecognizer) {
        recognizer.view?.endEditing(true)
    }

    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer,
                           shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
        true
    }

    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
        guard let window = gestureRecognizer.view as? UIWindow,
              let editing = editingView, editing.window === window, editing.isFirstResponder else { return false }
        if Self.isInAlert(editing) || Self.isInAlert(touch.view) { return false }

        var view = touch.view
        while let current = view {
            if current is UITextField || current is UITextView || current is UISearchBar { return false }
            view = current.superview
        }

        let row = editing.convert(editing.bounds, to: window).insetBy(dx: 0, dy: -10)
        let y = touch.location(in: window).y
        if y >= row.minY && y <= row.maxY { return false }
        return true
    }

    private static func isInAlert(_ view: UIView?) -> Bool {
        var responder: UIResponder? = view
        while let current = responder {
            if current is UIAlertController { return true }
            responder = current.next
        }
        return false
    }
}

private extension UIView {
    var cpFirstResponderDescendant: UIView? {
        if isFirstResponder { return self }
        for sub in subviews {
            if let found = sub.cpFirstResponderDescendant { return found }
        }
        return nil
    }
}
