import SwiftUI

/// Navigation root: onboarding until this device has joined a vault, then unlock, then the app.
struct RootView: View {
    @StateObject private var session = AppSession()

    var body: some View {
        NavigationStack {
            if session.vault == nil {
                OnboardingView(session: session)
            } else if !session.unlocked {
                UnlockView(session: session)
            } else {
                VaultListView(session: session)
            }
        }
        // Cover before the system snapshots the app for the switcher; only once unlocked, so the
        // Face ID prompt (which also deactivates the scene) is not covered.
        .onReceive(NotificationCenter.default.publisher(for: UIScene.willDeactivateNotification)) { _ in
            if session.unlocked { PrivacyCover.show() }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didEnterBackgroundNotification)) { _ in
            session.didEnterBackground()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didActivateNotification)) { _ in
            session.didBecomeActive()
            PrivacyCover.hide()
        }
        .alert("Unlock with Face ID?", isPresented: $session.offerFaceID) {
            Button("Turn on") { Task { await session.enableFaceID() } }
            Button("Not now", role: .cancel) { session.declineFaceID() }
        } message: {
            Text("The master password always still works.")
        }
    }
}

/// First screen that round-trips through the Rust core via UniFFI (generate + score).
struct GeneratorView: View {
    @State private var password = ""
    @State private var strength: UInt8 = 0
    @State private var failed = false

    var body: some View {
        Form {
            Section {
                Text(failed ? "Generation failed" : password)
                    .font(.system(.body, design: .monospaced))
                    .accessibilityIdentifier("password")
                LabeledContent("Strength", value: "\(strength)/4")
                    .accessibilityIdentifier("strength")
            }
            Button("Generate") { generate() }
        }
        .navigationTitle("Generator")
        .onAppear(perform: generate)
    }

    private func generate() {
        do {
            password = try generatePassword(length: 20)
            strength = estimateStrength(password: password)
            failed = false
        } catch {
            password = ""
            failed = true
        }
    }
}
