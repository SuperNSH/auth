// Keychain storage for auth tokens: one generic-password item per key under
// the sandbox service. ThisDeviceOnly keeps tokens from migrating to another
// device through backups; the simulator needs no entitlement for
// generic-password items.

import Foundation
import Security

struct AuthKeychain {
    /// Service name every item of this module shares.
    static let service = "nsh-auth.sandbox"

    let service: String

    init(service: String = AuthKeychain.service) {
        self.service = service
    }

    private func baseQuery(key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }

    /// Delete-then-add: simpler than updating item attributes and safe here,
    /// since a token rewrite never depends on the previous value.
    func save(key: String, value: String) throws {
        var add = baseQuery(key: key)
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemDelete(baseQuery(key: key) as CFDictionary)
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AuthHostError("keychain add failed with OSStatus \(status)")
        }
    }

    /// nil when the key has no item; distinguishes "absent" from empty text.
    func load(key: String) -> String? {
        var query = baseQuery(key: key)
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return String(decoding: data, as: UTF8.self)
    }

    /// Deletes one key, or every item of the service when `key` is nil.
    func clear(key: String?) throws {
        var query = baseQuery(key: key ?? "")
        if key == nil {
            query.removeValue(forKey: kSecAttrAccount as String)
        }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AuthHostError("keychain delete failed with OSStatus \(status)")
        }
    }
}
