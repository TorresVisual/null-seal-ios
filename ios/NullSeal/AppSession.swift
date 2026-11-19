import Foundation

/// Owns the on-device vault and the join flow. The relay address lives only inside the vault
/// database (Application Support, excluded from device backups), never in code or settings.
/// Every call into the core that can wait on the network or the KDF runs off the main actor.
@MainActor
final class AppSession: ObservableObject {
    @Published private(set) var vault: Vault?
    @Published private(set) var waiting = false
    @Published private(set) var unlocked = false
    @Published private(set) var synced: SyncSummary?
    @Published private(set) var items: [ItemRow] = []
    /// This device holds a Face ID wrapper for the vault (#88).
    @Published private(set) var faceID = false
    /// Just unlocked with the password and Face ID is off: ask once whether to turn it on.
    @Published var offerFaceID = false
    @Published var error: String?

    private var worker: Task<Vault?, Error>?

    init() {
        do { vault = try openVault(storePath: Self.storePath()) } catch { self.error = Self.message(error) }
        faceID = vault?.deviceUnlockEnabled() ?? false
    }

    /// Post a join request to the relay, then wait (up to the relay's 10 minute window) for
    /// the existing device to approve it.
    func join(code: String, relay: String) {
        guard !waiting else { return }
        waiting = true
        error = nil
        let work = Task.detached { () async throws -> Vault? in
            let path = try Self.storePath()
            let e = try Enrollment.start(
                code: code, relayUrl: relay, transport: URLSessionTransport(base: relay))
            var hiccups = 0
            for _ in 0..<300 {
                try Task.checkCancellation()
                do {
                    if let v = try e.poll(storePath: path) { return v }
                } catch VaultError.Network {
                    hiccups += 1  // a dropped connection is not a failed join; give up after a few
                    if hiccups > 10 { throw VaultError.Network }
                }
                try await Task.sleep(nanoseconds: 2_000_000_000)
            }
            return nil
        }
        worker = work
        Task {
            do {
                vault = try await work.value
                if vault == nil { error = "The other device did not approve in time." }
            } catch is CancellationError {
            } catch {
                self.error = Self.message(error)
            }
            waiting = false
        }
    }

    func cancelJoin() {
        worker?.cancel()
    }

    /// Unlock with the master password, then pull the vault from the relay. A failed sync
    /// leaves the vault unlocked with what it already holds.
    func unlock(password: String) {
        guard let vault else { return }
        error = nil
        Task {
            do {
                try await Task.detached { try vault.unlock(password: password) }.value
                offerFaceID = !faceID && DeviceKey.available && !Self.declinedFaceID
                await finishUnlock()
            } catch {
                self.error = Self.message(error)
            }
        }
    }

    /// Unlock with the Keychain device key behind Face ID. Cancelling just leaves the password
    /// field; a key the system dropped (Face ID enrolment changed) retires the wrapper.
    func unlockWithFaceID() {
        guard let vault, faceID, !unlocked else { return }
        error = nil
        Task {
            do {
                try await Task.detached {
                    let key = try DeviceKey.read(reason: "Unlock Null Seal")
                    try vault.unlockWithDeviceKey(key: key)
                }.value
                await finishUnlock()
            } catch DeviceKeyError.cancelled {
            } catch DeviceKeyError.gone, VaultError.WrongPassword {
                try? vault.disableDeviceUnlock()
                DeviceKey.delete()
                faceID = false
                Self.declinedFaceID = false  // it was on before: offer it again after the next unlock
                self.error = "Face ID changed, so it was turned off. Unlock with your master password."
            } catch {
                self.error = Self.message(error)
            }
        }
    }

    /// Needs the vault unlocked. The key is created first, so a failed wrap leaves nothing behind.
    func enableFaceID() async {
        offerFaceID = false
        guard let vault, unlocked else { return }
        do {
            try await Task.detached {
                let key = try DeviceKey.create()
                do { try vault.enableDeviceUnlock(key: key) } catch {
                    DeviceKey.delete()
                    throw error
                }
            }.value
            faceID = true
        } catch { self.error = "Could not turn on Face ID." }
    }

    func disableFaceID() {
        try? vault?.disableDeviceUnlock()
        DeviceKey.delete()
        faceID = false
        Self.declinedFaceID = true
    }

    func declineFaceID() {
        offerFaceID = false
        Self.declinedFaceID = true
    }

    private func finishUnlock() async {
        await reload()  // what this device already holds shows before the sync returns
        unlocked = true
        await refresh()
    }

    /// Not a secret: only whether to ask again after a password unlock.
    private static var declinedFaceID: Bool {
        get { UserDefaults.standard.bool(forKey: "faceIDDeclined") }
        set { UserDefaults.standard.set(newValue, forKey: "faceIDDeclined") }
    }

    /// Pull from the relay, then re-read the list. A failed sync leaves the vault as it was.
    func refresh() async {
        do {
            synced = try await run { (v: Vault) -> SyncSummary? in
                guard let relay = v.relayUrl() else { return nil }
                return try v.sync(transport: URLSessionTransport(base: relay))
            }
        } catch { self.error = Self.message(error) }
        await reload()
    }

    func reload() async {
        do { items = try await run { try $0.listItems() } } catch { self.error = Self.message(error) }
    }

    func totpEntries() async throws -> [TotpEntry] {
        try await run { try $0.totpEntries() }
    }

    func load(_ id: String) async throws -> LoginData {
        try await run { try $0.getLogin(id: id) }
    }

    /// Create (`id` nil) or update, then push in the background. False if it was refused.
    func save(id: String?, _ data: LoginData) async -> Bool {
        await write { _ = try $0.saveLogin(id: id, data: data) }
    }

    func delete(_ id: String) async -> Bool {
        await write { try $0.deleteLogin(id: id) }
    }

    private func write(_ change: @escaping @Sendable (Vault) throws -> Void) async -> Bool {
        error = nil
        do { try await run(change) } catch {
            self.error = Self.message(error)
            return false
        }
        await reload()
        Task { await refresh() }
        return true
    }

    /// The core can hold its lock for a whole sync, so no call into it runs on the main actor.
    private func run<T>(_ work: @escaping @Sendable (Vault) throws -> T) async throws -> T {
        guard let vault else { throw VaultError.Locked }
        return try await Task.detached { try work(vault) }.value
    }

    /// How long the app may sit in the background before it locks. iOS suspends us, so no timer
    /// runs; the elapsed time is checked on return. ponytail: fixed, make it a setting if wanted.
    static let autoLockAfter: TimeInterval = 60

    private var backgroundedAt: Date?

    nonisolated static func autoLockExpired(since: Date?, now: Date) -> Bool {
        guard let since else { return false }
        return now.timeIntervalSince(since) >= autoLockAfter
    }

    func didEnterBackground() { backgroundedAt = Date() }

    func didBecomeActive() {
        if unlocked, Self.autoLockExpired(since: backgroundedAt, now: Date()) { lock() }
        backgroundedAt = nil
    }

    /// Does not wait for a running sync: the core locks at once or as soon as that call ends.
    func lock() {
        vault?.lock()
        unlocked = false
        offerFaceID = false
        synced = nil
        items = []
    }

    private nonisolated static func storePath() throws -> String {
        var dir = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        return dir.appendingPathComponent("vault.db").path
    }

    private static func message(_ error: Error) -> String {
        switch error as? VaultError {
        case .Invalid: return "That code or relay address is not valid."
        case .Network: return "Could not reach the relay."
        case .Rejected: return "The relay refused the request (is the code still valid?)."
        case .WrongPassword: return "Wrong master password."
        case .TryLater: return "Too many wrong attempts. Try again shortly."
        case .AlreadyJoined: return "This device already has a vault."
        case .Locked: return "The vault is locked."
        case .NotFound: return "That item no longer exists."
        default: return "Something went wrong."
        }
    }
}
