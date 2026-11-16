import SwiftUI

// Placeholder shell so CI can produce an installable IPA that proves the Rust core is linked (#83).
// The real app lands in #85.
@main
struct NullSealApp: App {
    var body: some Scene {
        WindowGroup {
            Text("Null Seal core \(coreVersion())")
        }
    }
}
