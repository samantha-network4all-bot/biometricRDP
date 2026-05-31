import Foundation
import CryptoKit

enum VaultError: Error {
    case notUnlocked
    case duplicateId
    case notFound
    case cryptoFailure
}

struct StoredCredential: Codable {
    let id: String
    let host: String
    let username: String
    let password: String
}

final class Vault {
    static let shared = Vault()

    private var isUnlocked = false
    private var encryptionKey: SymmetricKey?
    private var credentials: [String: StoredCredential] = [:]
    private var storageURL: URL?

    private init() {}

    // MARK: - Lifecycle

    func setStorageURL(_ url: URL) {
        storageURL = url
    }

    /// Unlock with a raw key (derived externally — from biometric-gated Secure Enclave key or test secret).
    func unlock(key: Data) {
        self.encryptionKey = SymmetricKey(data: key)
        self.isUnlocked = true
        try? loadFromDisk()
    }

    func lock() {
        self.encryptionKey = nil
        self.isUnlocked = false
        credentials.removeAll()
    }

    var unlocked: Bool { isUnlocked }

    // MARK: - CRUD

    func save(credential: StoredCredential) throws {
        guard isUnlocked else { throw VaultError.notUnlocked }
        credentials[credential.id] = credential
        try flushToDisk()
    }

    func list() throws -> [(id: String, host: String, username: String)] {
        guard isUnlocked else { throw VaultError.notUnlocked }
        return credentials.values
            .sorted { $0.id < $1.id }
            .map { (id: $0.id, host: $0.host, username: $0.username) }
    }

    func get(id: String) throws -> StoredCredential {
        guard isUnlocked else { throw VaultError.notUnlocked }
        guard let cred = credentials[id] else { throw VaultError.notFound }
        return cred
    }

    func delete(id: String) throws {
        guard isUnlocked else { throw VaultError.notUnlocked }
        guard credentials.removeValue(forKey: id) != nil else { throw VaultError.notFound }
        try flushToDisk()
    }

    // MARK: - Persistence (AES-GCM)

    private func flushToDisk() throws {
        guard let key = encryptionKey else { throw VaultError.notUnlocked }
        guard let url = storageURL else { return }

        let encoder = JSONEncoder()
        let plaintext = try encoder.encode(Array(credentials.values))

        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        guard let combined = sealed.combined else { throw VaultError.cryptoFailure }
        try combined.write(to: url)
    }

    private func loadFromDisk() throws {
        guard let key = encryptionKey else { throw VaultError.notUnlocked }
        guard let url = storageURL else { return }
        guard FileManager.default.fileExists(atPath: url.path) else { return }

        let combined = try Data(contentsOf: url)
        let sealed = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealed, using: key)

        let decoder = JSONDecoder()
        let items = try decoder.decode([StoredCredential].self, from: plaintext)
        credentials = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
    }
}
