// The "auth.nativeSignIn" host channel: native SDK sign-ins behind the same
// registry as AuthHostModule. Contract (keep in sync with native/ios/README.md
// and packages/nsh-auth): google -> {provider, serverAuthCode}, apple ->
// {provider, identityToken, authorizationCode, nonce}, facebook -> {provider,
// accessToken, expiresAt (epoch ms)}; user cancel rejects with exactly
// "cancelled". Every SDK symbol here is verified against the SPM checkouts
// pinned in Package.resolved: GoogleSignIn-iOS 10.1.0, facebook-ios-sdk
// v19.0.1 (the FacebookLogin product @_exports the FBSDKLoginKit binary
// framework).

import AuthenticationServices
import FacebookCore
import Foundation
import GoogleSignIn
import NativeShell
import FacebookLogin
import UIKit

@MainActor
final class NativeSignInModule: NSObject {
    static let supersededMessage = "cancelled: superseded by a new nativeSignIn call"

    private weak var anchorView: UIView?
    // One in-flight flow per provider; the slot holds the reply so a replaced
    // flow can settle its TS promise instead of hanging (the Apple delegate is
    // only weakly held by ASAuthorizationController).
    private var appleFlow: AppleSignInFlow?
    private var facebookFlow: FacebookSignInFlow?

    func register(on app: NshAppView, anchorView: UIView) {
        self.anchorView = anchorView
        app.handle("auth.nativeSignIn") { [weak self] data, reply in
            self?.nativeSignIn(data: data, reply: reply)
        }
    }

    private func nativeSignIn(data: Any?, reply: NshHostReply) {
        guard let args = data as? [String: Any], let provider = args["provider"] as? String else {
            reply.reject("auth.nativeSignIn expects {provider: \"google\"|\"apple\"|\"facebook\"}")
            return
        }
        let nonce = args["nonce"] as? String
        switch provider {
        case "google": google(reply: reply)
        case "apple": apple(nonce: nonce, reply: reply)
        case "facebook": facebook(reply: reply)
        default: reply.reject("auth.nativeSignIn: unknown provider \(provider)")
        }
    }

    // MARK: Google

    private func google(reply: NshHostReply) {
        let info = Bundle.main.infoDictionary ?? [:]
        guard let clientID = info["GIDClientID"] as? String, !clientID.isEmpty else {
            reply.reject("auth.nativeSignIn google: GIDClientID missing from Info.plist")
            return
        }
        GIDSignIn.sharedInstance.configuration = GIDConfiguration(
            clientID: clientID,
            serverClientID: info["GIDServerClientID"] as? String
        )
        guard let presenting = Self.presentingViewController(from: anchorView) else {
            reply.reject("auth.nativeSignIn google: no view controller to present from")
            return
        }
        // serverAuthCode exists only because GIDServerClientID is configured
        // (GIDSignInResult.h); the completion runs on the main queue, and the
        // singleton SDK retains it, so a replaced sign-in still settles.
        GIDSignIn.sharedInstance.signIn(withPresenting: presenting) { result, error in
            if let error {
                if Self.isGoogleCancel(error) {
                    reply.reject("cancelled")
                } else {
                    reply.reject(error.localizedDescription)
                }
                return
            }
            guard let code = result?.serverAuthCode else {
                reply.reject("google sign-in returned no serverAuthCode")
                return
            }
            reply.resolve(["provider": "google", "serverAuthCode": code])
        }
    }

    // kGIDSignInErrorDomain's NS_ERROR_ENUM imports as GIDSignInError.Code.
    private static func isGoogleCancel(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == kGIDSignInErrorDomain as String
            && nsError.code == GIDSignInError.Code.canceled.rawValue
    }

    // MARK: Apple

    private func apple(nonce: String?, reply: NshHostReply) {
        // The response echoes the RAW nonce, so the request cannot proceed
        // without one; ASAuthorizationAppleIDRequest carries SHA256(raw) — the
        // opposite of Google's verbatim rule (Apple's documented pattern).
        guard let nonce, !nonce.isEmpty else {
            reply.reject("auth.nativeSignIn apple expects {nonce} (the raw nonce from the core)")
            return
        }
        // Superseding settles the old reply first; its controller (with the
        // weak delegate) is then released, so a new sheet can present.
        appleFlow?.supersede()
        appleFlow = nil
        let request = ASAuthorizationAppleIDProvider().createRequest()
        request.requestedScopes = [.fullName, .email]
        request.nonce = AuthSignInMath.sha256Hex(nonce)
        let flow = AppleSignInFlow(
            rawNonce: nonce,
            controller: ASAuthorizationController(authorizationRequests: [request]),
            anchorView: anchorView,
            reply: reply
        )
        // The delegate must survive the whole sheet round-trip; nil the slot
        // only when it still holds the finishing instance.
        appleFlow = flow
        flow.onFinish = { [weak self, weak flow] in
            guard let self, let flow else { return }
            if self.appleFlow === flow { self.appleFlow = nil }
        }
        flow.start()
    }

    // MARK: Facebook

    private func facebook(reply: NshHostReply) {
        // Swift cannot catch the SDK's NSException: LoginManager's
        // validateAppID throws when the SDK never got its plist provider, so
        // a configuration gap is rejected here instead of crashing the host.
        guard Settings.shared.appID?.isEmpty == false,
            Settings.shared.clientToken?.isEmpty == false
        else {
            reply.reject("auth.nativeSignIn facebook: FacebookAppID/FacebookClientToken missing — the host app must carry them in Info.plist and initialize the Facebook SDK at launch")
            return
        }
        // Classic (.enabled) tracking yields the opaque Graph API AccessToken;
        // web-only = AppSwitch.disabled so no switch into a Facebook app.
        guard
            let configuration = LoginConfiguration(
                permissions: ["public_profile", "email"],
                tracking: .enabled,
                messengerPageId: nil,
                authType: nil,
                appSwitch: .disabled
            )
        else {
            reply.reject("auth.nativeSignIn facebook: LoginConfiguration rejected the request")
            return
        }
        guard let presenting = Self.presentingViewController(from: anchorView) else {
            reply.reject("auth.nativeSignIn facebook: no view controller to present from")
            return
        }
        // One login at a time per manager (LoginManager.swift @warning); each
        // flow owns a fresh manager, and superseding settles the old reply.
        facebookFlow?.supersede()
        facebookFlow = nil
        let flow = FacebookSignInFlow(reply: reply)
        facebookFlow = flow
        flow.onFinish = { [weak self, weak flow] in
            guard let self, let flow else { return }
            if self.facebookFlow === flow { self.facebookFlow = nil }
        }
        flow.start(configuration: configuration, presenting: presenting)
    }

    // Topmost presented controller in the anchor's window; SDKs present from
    // the host's own view controller, never from inside the embedded view.
    static func presentingViewController(from anchorView: UIView?) -> UIViewController? {
        guard let window = anchorView?.window else { return nil }
        var top = window.rootViewController
        while let presented = top?.presentedViewController { top = presented }
        return top
    }
}

// Shared shape for the per-provider in-flight flows: settleReply is idempotent
// so a superseded flow's late SDK callback can neither double-settle its reply
// nor (via the identity-checked onFinish) release its replacement mid-flight.
@MainActor
private protocol NativeSignInFlow: AnyObject {
    func supersede()
}

@MainActor
private final class AppleSignInFlow: NSObject, NativeSignInFlow,
    ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding
{
    var onFinish: (() -> Void)?
    private let rawNonce: String
    private let controller: ASAuthorizationController
    private weak var anchorView: UIView?
    private let reply: NshHostReply
    private var settled = false

    init(
        rawNonce: String,
        controller: ASAuthorizationController,
        anchorView: UIView?,
        reply: NshHostReply
    ) {
        self.rawNonce = rawNonce
        self.controller = controller
        self.anchorView = anchorView
        self.reply = reply
        super.init()
        controller.delegate = self
        controller.presentationContextProvider = self
    }

    func start() {
        controller.performRequests()
    }

    func supersede() {
        settleReply { $0.reject(NativeSignInModule.supersededMessage) }
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        settleReply { reply in
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                let tokenData = credential.identityToken,
                let codeData = credential.authorizationCode
            else {
                reply.reject("apple sign-in returned no identityToken or authorizationCode")
                return
            }
            // JWT and code are ASCII; the core later verifies identityToken
            // against Apple's JWKS (aud = bundle id, nonce == sha256 of raw).
            reply.resolve([
                "provider": "apple",
                "identityToken": String(decoding: tokenData, as: UTF8.self),
                "authorizationCode": String(decoding: codeData, as: UTF8.self),
                "nonce": rawNonce,
            ])
        }
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        settleReply { reply in
            if (error as? ASAuthorizationError)?.code == .canceled {
                reply.reject("cancelled")
            } else {
                reply.reject(error.localizedDescription)
            }
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchorView?.window ?? ASPresentationAnchor()
    }

    private func settleReply(_ settle: (NshHostReply) -> Void) {
        guard !settled else { return }
        settled = true
        settle(reply)
        onFinish?()
    }
}

@MainActor
private final class FacebookSignInFlow: NativeSignInFlow {
    var onFinish: (() -> Void)?
    private let reply: NshHostReply
    private let manager = LoginManager()
    private var settled = false

    init(reply: NshHostReply) {
        self.reply = reply
    }

    func start(configuration: LoginConfiguration, presenting: UIViewController) {
        manager.logIn(viewController: presenting, configuration: configuration) { [weak self] result in
            // self is gone only after a supersede already settled the reply.
            guard let self else { return }
            switch result {
            case .cancelled:
                self.settleReply { $0.reject("cancelled") }
            case .failed(let error):
                self.settleReply { $0.reject(error.localizedDescription) }
            case .success(_, _, let token):
                self.settleReply { reply in
                    guard let tokenString = token?.tokenString else {
                        reply.reject("facebook login returned no access token")
                        return
                    }
                    var payload: [String: Any] = ["provider": "facebook", "accessToken": tokenString]
                    if let expiresAt = token?.expirationDate {
                        payload["expiresAt"] = AuthSignInMath.facebookExpiresAt(expiresAt)
                    }
                    reply.resolve(payload)
                }
            }
        }
    }

    func supersede() {
        settleReply { $0.reject(NativeSignInModule.supersededMessage) }
    }

    private func settleReply(_ settle: (NshHostReply) -> Void) {
        guard !settled else { return }
        settled = true
        settle(reply)
        onFinish?()
    }
}
