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
            throw AuthHostError("keychain add failed: \(AuthKeychain.statusMessage(status))")
        }
    }

    /// nil only for errSecItemNotFound; any other OSStatus throws, so a
    /// keychain failure can never masquerade as "no session" and force re-auth.
    func load(key: String) throws -> String? {
        var query = baseQuery(key: key)
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw AuthHostError("keychain read failed: \(AuthKeychain.statusMessage(status))")
        }
        guard let data = item as? Data else {
            throw AuthHostError("keychain read returned no data")
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
            throw AuthHostError("keychain delete failed: \(AuthKeychain.statusMessage(status))")
        }
    }

    /// Human text for a keychain OSStatus; mapping adapted from expo-secure-store
    /// SecureStoreExceptions.swift:21-69 (MIT, © 650 Industries).
    static func statusMessage(_ status: OSStatus) -> String {
        switch status {
        case errSecUnimplemented: return "function or operation not implemented"
        case errSecIO: return "I/O error"
        case errSecOpWr: return "file already open with write permission"
        case errSecParam: return "invalid parameter passed to a keychain function"
        case errSecAllocate: return "failed to allocate memory"
        case errSecUserCanceled: return "user canceled the operation"
        case errSecBadReq: return "bad parameter or invalid state for the operation"
        case errSecNotAvailable: return "no keychain is available"
        case errSecDuplicateItem: return "the item already exists in the keychain"
        case errSecItemNotFound: return "the item could not be found in the keychain"
        case errSecInteractionNotAllowed: return "user interaction with the keychain is not allowed (device may be locked)"
        case errSecDecode: return "unable to decode the provided data"
        case errSecAuthFailed: return "authentication failed: the PIN/passphrase is wrong or no user authentication method is configured"
        default:
            if let message = SecCopyErrorMessageString(status, nil) {
                return message as String
            }
            return "unknown keychain error (OSStatus \(status))"
        }
    }
}
