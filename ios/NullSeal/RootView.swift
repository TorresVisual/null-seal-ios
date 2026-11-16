import SwiftUI

/// Navigation root. Vault screens (#86+) hang off this stack.
struct RootView: View {
    var body: some View {
        NavigationStack {
            List {
                NavigationLink("Password generator") { GeneratorView() }
                LabeledContent("Core", value: coreVersion())
            }
            .navigationTitle("Null Seal")
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
