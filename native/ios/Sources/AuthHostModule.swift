// The "auth.*" host channel the nsh-auth TSX package calls.
//
// API names are verified against nsh 0.4.0: the two `handle` overloads in the
// swiftinterface of $(brew --prefix nsh)/libexec/embed/ios/NativeShell.xcframework
// and examples/embed-ios/main.swift. The payload contract with packages/nsh-auth
// is documented in native/ios/README.md; keep the two in sync.

import AuthenticationServices
import Foundation
import NativeShell
import UIKit

/// Thrown by handlers; its message becomes the host-channel rejection text.
struct AuthHostError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

@MainActor
final class AuthHostModule: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let keychain: AuthKeychain
    private let launchProvider: String?
    private let registeredSchemes: Set<String>
    private weak var anchorView: UIView?
    private var session: ASWebAuthenticationSession?

    /// Launch arguments come from the process: `simctl launch <udid>
    /// dev.nshauth.sandbox --provider google` lands in ProcessInfo.
    init(
        launchArguments: [String] = ProcessInfo.processInfo.arguments,
        keychain: AuthKeychain = AuthKeychain()
    ) {
        self.keychain = keychain
        self.launchProvider = Self.provider(from: launchArguments)
        self.registeredSchemes = Self.registeredSchemes()
    }

    /// Setup order requires handlers to exist before `loadBundle` runs.
    func register(on app: NshAppView, anchorView: UIView) {
        self.anchorView = anchorView

        app.handle("auth.authorize") { [weak self] data, reply in
            self?.authorize(data: data, reply: reply)
        }

        app.handle("auth.store.save") { [weak self] data in
            guard let self else { throw AuthHostError("auth module is gone") }
            guard let args = data as? [String: Any], let key = args["key"] as? String, !key.isEmpty else {
                throw AuthHostError("auth.store.save expects {key, value}")
            }
            guard let value = Self.canonicalValue(args["value"]) else {
                throw AuthHostError("auth.store.save: value must be a string or a JSON object or array")
            }
            try self.keychain.save(key: key, value: value)
            return ["ok": true]
        }

        app.handle("auth.store.load") { [weak self] data in
            guard let self else { throw AuthHostError("auth module is gone") }
            guard let args = data as? [String: Any], let key = args["key"] as? String, !key.isEmpty else {
                throw AuthHostError("auth.store.load expects {key}")
            }
            let stored: Any = self.keychain.load(key: key) ?? NSNull()
            return ["value": stored]
        }

        app.handle("auth.store.clear") { [weak self] data in
            guard let self else { throw AuthHostError("auth module is gone") }
            let key = (data as? [String: Any])?["key"] as? String
            if key?.isEmpty == true {
                throw AuthHostError("auth.store.clear: key must not be empty")
            }
            try self.keychain.clear(key: key)
            return ["ok": true]
        }

        app.handle("auth.config") { [weak self] data in
            guard let self else { throw AuthHostError("auth module is gone") }
            let args = data as? [String: Any]
            // autoStart is the host's own decision, from --provider on launch.
            let provider = self.launchProvider
            return [
                "mockBaseUrl": args?["mockBaseUrl"] ?? NSNull(),
                "autoStart": provider != nil,
                "provider": provider ?? NSNull(),
            ]
        }
    }

    /// The reply answers late: the session completion fires after user
    /// interaction, so the deferred `{ data, reply }` handle overload is used.
    private func authorize(data: Any?, reply: NshHostReply) {
        guard
            let args = data as? [String: Any],
            let urlString = args["url"] as? String,
            let url = URL(string: urlString),
            url.scheme == "https" || url.scheme == "http",
            let scheme = args["scheme"] as? String, !scheme.isEmpty
        else {
            reply.reject("auth.authorize expects {url, scheme} with an https authorize URL")
            return
        }
        // RFC 8252: the callback scheme must be the app's own, so the session
        // cannot capture redirects meant for foreign schemes.
        guard registeredSchemes.contains(scheme) else {
            reply.reject("auth.authorize: the callback scheme is not registered by this app")
            return
        }
        session?.cancel()
        let web = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme) { callback, error in
            // NshHostReply is Sendable; the completion thread is unspecified.
            if let callback {
                reply.resolve(["callbackUrl": callback.absoluteString])
            } else if (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin {
                reply.reject("cancelled")
            } else {
                reply.reject(error?.localizedDescription ?? "authorize failed")
            }
        }
        web.presentationContextProvider = self
        // Cookies must persist so provider account pickers survive; ephemeral
        // sessions also break providers that rely on their login state.
        web.prefersEphemeralWebBrowserSession = false
        session = web
        guard web.start() else {
            session = nil
            reply.reject("could not start the sign-in session")
            return
        }
    }

    /// The schemes in Bundle.main's CFBundleURLTypes, i.e. what the system
    /// will actually route back to this app.
    static func registeredSchemes() -> Set<String> {
        let types = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]] ?? []
        let schemes = types.flatMap { ($0["CFBundleURLSchemes"] as? [String]) ?? [] }
        return Set(schemes)
    }

    /// `--provider <id>` or `--provider=<id>`; unknown or malformed args give no auto-start.
    static func provider(from arguments: [String]) -> String? {
        var i = 0
        while i < arguments.count {
            let arg = arguments[i]
            if arg == "--provider", i + 1 < arguments.count, !arguments[i + 1].hasPrefix("--") {
                return arguments[i + 1]
            }
            if arg.hasPrefix("--provider=") {
                let value = String(arg.dropFirst("--provider=".count))
                return value.isEmpty ? nil : value
            }
            i += 1
        }
        return nil
    }

    /// Strings are stored verbatim; other JSON values become JSON text so the
    /// TSX side round-trips its own encoding.
    static func canonicalValue(_ value: Any?) -> String? {
        if let string = value as? String { return string }
        guard let value, JSONSerialization.isValidJSONObject(value),
            let data = try? JSONSerialization.data(withJSONObject: value)
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: ASWebAuthenticationPresentationContextProviding

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchorView?.window ?? ASPresentationAnchor()
    }
}
