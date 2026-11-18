import SwiftUI

// Shown over the whole app while locked. Prompts biometrics automatically on
// appear, with a manual retry if the user dismisses the system prompt.

struct LockView: View {
    let app: AppModel
    @State private var attempted = false

    var body: some View {
        ZStack {
            CPTheme.screen.ignoresSafeArea()
            VStack(spacing: 18) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(CPTheme.accent)
                Text("CarrierPony is locked")
                    .font(.title3.bold())
                Text("Unlock with Face ID or your passcode.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button {
                    Task { await app.unlock() }
                } label: {
                    Label("Unlock", systemImage: "faceid")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 28)
                        .padding(.vertical, 12)
                        .background(Capsule().fill(CPTheme.send))
                }
                .padding(.top, 6)
            }
            .padding(40)
        }
        .task {
            guard !attempted else { return }
            attempted = true
            await app.unlock()
        }
    }
}
