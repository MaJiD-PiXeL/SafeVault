import SwiftUI
import UIKit
import WebKit

@main
struct SafeVaultApp: App {
    private let origin: URL? = {
        guard let host = Bundle.main.object(forInfoDictionaryKey: "SafeVaultHost") as? String,
              host.range(of: #"^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])$"#, options: .regularExpression) != nil,
              host.contains(".") else { return nil }
        return URL(string: "https://\(host)/")
    }()

    var body: some Scene {
        WindowGroup {
            if let origin {
                VaultView(origin: origin)
            } else {
                Text("The SafeVault server has not been configured.")
                    .multilineTextAlignment(.center)
                    .padding()
            }
        }
    }
}

struct VaultView: UIViewControllerRepresentable {
    let origin: URL

    func makeUIViewController(context: Context) -> VaultController {
        VaultController(origin: origin)
    }

    func updateUIViewController(_ controller: VaultController, context: Context) {}
}

final class VaultController: UIViewController, WKNavigationDelegate, WKDownloadDelegate {
    private let origin: URL
    private let browser = WKWebView()
    private var downloadDirectories: [ObjectIdentifier: URL] = [:]

    init(origin: URL) {
        self.origin = origin
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { nil }

    override func loadView() {
        view = browser
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        browser.navigationDelegate = self
        browser.load(URLRequest(url: origin))
    }

    private func isVaultURL(_ url: URL?) -> Bool {
        guard let url else { return false }
        return url.scheme == "https" && url.host == origin.host && (url.port ?? 443) == 443
            && url.user == nil && url.password == nil
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let url = navigationAction.request.url
        let source = navigationAction.sourceFrame.securityOrigin
        let fromVault = source.protocol == "https" && source.host == origin.host && [0, 443].contains(source.port)
        if navigationAction.shouldPerformDownload && (isVaultURL(url) || (url?.scheme == "blob" && fromVault)) {
            decisionHandler(.download)
        } else {
            decisionHandler(isVaultURL(url) && navigationAction.targetFrame?.isMainFrame == true ? .allow : .cancel)
        }
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        decisionHandler(isVaultURL(navigationResponse.response.url) ? .allow : .cancel)
    }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let filename = (suggestedFilename as NSString).lastPathComponent
        guard !["", ".", "..", "/"].contains(filename) else { completionHandler(nil); return }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            downloadDirectories[ObjectIdentifier(download)] = directory
            completionHandler(directory.appendingPathComponent(filename))
        } catch {
            completionHandler(nil)
        }
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let directory = downloadDirectories.removeValue(forKey: ObjectIdentifier(download)) else { return }
        guard let file = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).first,
              presentedViewController == nil else {
            try? FileManager.default.removeItem(at: directory)
            return
        }
        let share = UIActivityViewController(activityItems: [file], applicationActivities: nil)
        share.popoverPresentationController?.sourceView = view
        share.popoverPresentationController?.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1)
        share.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: directory) }
        present(share, animated: true)
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        if let directory = downloadDirectories.removeValue(forKey: ObjectIdentifier(download)) {
            try? FileManager.default.removeItem(at: directory)
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard (error as NSError).code != NSURLErrorCancelled, presentedViewController == nil else { return }
        let alert = UIAlertController(title: "Could not connect to SafeVault", message: origin.host, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Retry", style: .default) { [weak self] _ in
            guard let self else { return }
            self.browser.load(URLRequest(url: self.origin))
        })
        present(alert, animated: true)
    }
}
