import AVFoundation
import SwiftUI

/// First run: enter the relay address and the code the desktop shows (typed or scanned).
struct OnboardingView: View {
    @ObservedObject var session: AppSession
    @State private var relay = ""
    @State private var code = ""
    @State private var scanning = false

    var body: some View {
        Form {
            Section("Relay address") {
                TextField("https://", text: $relay)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("relay")
            }
            Section("Code from your other device") {
                TextField("xxxx-xxxx-…", text: $code)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("code")
                Button("Scan QR code") { scanning = true }
            }
            Section {
                if session.waiting {
                    HStack {
                        ProgressView()
                        Text("Approve this device on your other device…")
                    }
                    Button("Cancel", role: .cancel) { session.cancelJoin() }
                } else {
                    Button("Join vault") { session.join(code: code, relay: relay) }
                        .disabled(relay.isEmpty || code.isEmpty)
                        .accessibilityIdentifier("join")
                }
                if let error = session.error {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Join your vault")
        .sheet(isPresented: $scanning) {
            QRScanner { scanned in
                code = scanned
                scanning = false
            }
            .ignoresSafeArea()
        }
    }
}

/// After joining: the master password unlocks the vault and pulls it from the relay.
struct UnlockView: View {
    @ObservedObject var session: AppSession
    @State private var password = ""

    var body: some View {
        Form {
            if session.faceID {
                Section {
                    Button("Unlock with Face ID", systemImage: "faceid") { session.unlockWithFaceID() }
                        .accessibilityIdentifier("faceid")
                }
            }
            Section {
                SecureField("Master password", text: $password)
                    .accessibilityIdentifier("password")
                Button("Unlock and sync") { session.unlock(password: password) }
                    .disabled(password.isEmpty)
                    .accessibilityIdentifier("unlock")
            }
            if let error = session.error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Unlock")
        .task { session.unlockWithFaceID() }
    }
}

/// Camera QR reader; hands back the first code's text.
struct QRScanner: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let c = ScannerController()
        c.onScan = onScan
        return c
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    private let capture = AVCaptureSession()
    private var done = false

    override func viewDidLoad() {
        super.viewDidLoad()
        guard let device = AVCaptureDevice.default(for: .video),
            let input = try? AVCaptureDeviceInput(device: device),
            capture.canAddInput(input)
        else { return }
        capture.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard capture.canAddOutput(output) else { return }
        capture.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: capture)
        preview.frame = view.layer.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)
        DispatchQueue.global().async { self.capture.startRunning() }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        capture.stopRunning()
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !done,
            let text = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue
        else { return }
        done = true
        onScan?(text)
    }
}
