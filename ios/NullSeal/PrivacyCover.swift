import UIKit

/// Hides the app in the app-switcher snapshot. A separate window, because an overlay on the root
/// view would leave sheets (the add/edit forms) visible above it.
@MainActor
enum PrivacyCover {
    private static var window: UIWindow?

    static func show() {
        guard window == nil, let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene else { return }
        let w = UIWindow(windowScene: scene)
        w.windowLevel = .alert + 1
        let vc = UIViewController()
        vc.view.backgroundColor = .systemBackground
        w.rootViewController = vc
        w.isHidden = false
        window = w
    }

    static func hide() {
        window?.isHidden = true
        window = nil
    }
}
