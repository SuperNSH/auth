// UIKit host app embedding the nsh-auth demo (examples/demo) through
// NshAppView, with the same NshAppView setup as nsh 0.4.0
// examples/embed-ios/main.swift. Unlike that example this uses the UIScene
// lifecycle: apps built with the iOS 26+ SDK require it (this machine's SDK
// is 27.0).

import NativeShell
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        true
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var hostController: HostViewController?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let controller = HostViewController()
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window
        self.hostController = controller
        forwardURLs(connectionOptions.urlContexts)
    }

    // ASWebAuthenticationSession consumes its own callback; this path covers
    // flows that return through the registered scheme another way.
    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        forwardURLs(URLContexts)
    }

    private func forwardURLs(_ contexts: Set<UIOpenURLContext>) {
        for context in contexts {
            _ = hostController?.forwardOpenURL(context.url)
        }
    }
}

final class HostViewController: UIViewController {
    private let app = NshAppView()
    private let authModule = AuthHostModule()
    private let status = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        status.font = .systemFont(ofSize: 12)
        status.textColor = .secondaryLabel
        status.numberOfLines = 2
        status.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(status)

        app.translatesAutoresizingMaskIntoConstraints = false
        app.onError = { [weak self] message in self?.status.text = "nsh error: \(message)" }
        view.addSubview(app)

        NSLayoutConstraint.activate([
            status.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            status.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            status.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            app.topAnchor.constraint(equalTo: status.bottomAnchor, constant: 8),
            app.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            app.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            app.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        do {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            app.storageDirectory = support
                .appendingPathComponent("nsh-auth", isDirectory: true)
                .appendingPathComponent("sandbox", isDirectory: true)
            // Least privilege: the grant is the ceiling over the app's
            // declaration (nsh-core access.rs: a request must be allowed by
            // both), so the loopback hosts the mock needs are granted here.
            try app.grantCapabilities(
                #"{ "host": ["auth.*"], "network": { "hosts": ["127.0.0.1", "localhost"] } }"#
            )
            authModule.register(on: app, anchorView: app)
            guard let bundleURL = Bundle.main.url(forResource: "bundle", withExtension: "nshc", subdirectory: "nsh") else {
                status.text = "no nsh/bundle.nshc in the app; run examples/host-ios/build-gate.sh"
                return
            }
            try app.loadBundle(at: bundleURL)
            status.text = "nsh loaded"
        } catch {
            status.text = "\(error)"
        }
    }

    fileprivate func forwardOpenURL(_ url: URL) -> Bool {
        app.onOpenURL?(url) ?? false
    }

    // Let the embedded app's pages and dialogs set the status bar.
    override var preferredStatusBarStyle: UIStatusBarStyle { NshAppView.preferredStatusBarStyle }
    override var prefersStatusBarHidden: Bool { NshAppView.prefersStatusBarHidden }
    override var preferredStatusBarUpdateAnimation: UIStatusBarAnimation {
        NshAppView.preferredStatusBarUpdateAnimation
    }
}
