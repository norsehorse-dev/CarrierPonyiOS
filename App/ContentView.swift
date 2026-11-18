import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "bird")
                .font(.system(size: 48))
            Text("CarrierPony")
                .font(.title2.weight(.semibold))
            Text("Foundation wired. UI next.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
