import Foundation
import LocalAuthentication
import Security

enum DeviceKeyError: Error {
    /// The user dismissed Face ID or chose the password.
    case cancelled
    /// The key is not in the Keychain any more: Face ID enrolment changed, or the passcode was
    /// removed. The wrapper in the vault can never be opened again.
    case gone
    case failed
}

/// The device unlock key (#88): 32 random bytes in the Keychain, readable only after Face ID.
/// `.biometryCurrentSet` ties the item to the enrolled faces, so adding or resetting a face makes
/// the system drop it; `ThisDeviceOnly` keeps it out of backups and iCloud. The app's default
/// keychain access group is used on purpose: shared groups do not survive AltStore re-signing.
/// The core wraps the Account Key under these bytes; the master password always still works.
enum DeviceKey {
    private static let service = "app.nullseal.device-unlock-key"

    static var available: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    private static var identity: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
    }

    /// A fresh key, replacing any earlier one. Adding the item does not prompt.
    static func create() throws -> Data {
        delete()
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess,
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil)
        else { throw DeviceKeyError.failed }
        let key = Data(bytes)
        var item = identity
        item[kSecAttrAccessControl as String] = access
        item[kSecValueData as String] = key
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw DeviceKeyError.failed }
        return key
    }

    /// Shows Face ID; blocks until answered, so call it off the main actor.
    static func read(reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = "" // no passcode fallback: the master password is the fallback
        var query = identity
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context
        var out: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &out) {
        case errSecSuccess:
            guard let data = out as? Data, data.count == 32 else { throw DeviceKeyError.failed }
            return data
        case errSecItemNotFound: throw DeviceKeyError.gone
        case errSecUserCanceled, errSecAuthFailed: throw DeviceKeyError.cancelled
        default: throw DeviceKeyError.failed
        }
    }

    static func delete() {
        SecItemDelete(identity as CFDictionary)
    }
}
