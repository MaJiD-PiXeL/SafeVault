# SafeVault apps

The app projects connect to the SafeVault web deployment. They use the existing
browser vault and its encryption. For release builds, use the HTTPS hostname of
the same-origin SafeVault deployment.

The [mobile build workflow](../.github/workflows/build-mobile.yml) takes a
hostname and produces an Android debug APK with its `assetlinks.json` file and
an iOS Simulator bundle. Pull requests that change either mobile project run
the builds with a placeholder hostname.

## Windows x64

Extract the portable bundle into one folder and run `SafeVault.exe`. The app
uses the installed Microsoft Edge WebView2 Runtime and .NET Framework 4.8. By
default it connects to the local beta at `http://127.0.0.1:18010/`. To connect it
to a hosted SafeVault instance, pass the full HTTPS origin at launch.

```powershell
& .\native\windows\dist\SafeVault.exe https://vault.example.com/
```

To rebuild, download and extract the Microsoft.Web.WebView2 NuGet package
version `1.0.4314.35`, then run `./native/windows/build.ps1 -WebView2Sdk <folder>`.
The build requires the Windows .NET Framework C# compiler and outputs the
executable and its dependencies in `native/windows/dist`.
[WebView2 runtime distribution](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)

## Android

The Android package opens SafeVault in a Trusted Web Activity managed by the
device browser. Use JDK 17, Gradle 8.13 and Android SDK 36. From `native/android`
run the following commands with your deployed hostname.

```sh
gradle -PsafevaultHost=vault.example.com assembleDebug
gradle -PsafevaultHost=vault.example.com bundleRelease
```

For a beta build from the workflow, download the `SafeVault-Android-debug`
artifact. Deploy its `assetlinks.json` using the
[Compose instructions](../docs/compose-deployment.md#android-domain-verification)
and install the APK from the same artifact. GitHub runners can generate a new
debug signing key on each run. Use the matching file and reinstall the app if
its signing certificate changes.

Sign the release bundle with your Android distribution key. Before a release build,
set `SAFEVAULT_ANDROID_KEYSTORE` to the keystore's absolute path and supply
`SAFEVAULT_ANDROID_STORE_PASSWORD`, `SAFEVAULT_ANDROID_KEY_ALIAS` and
`SAFEVAULT_ANDROID_KEY_PASSWORD` through the build environment. Release
assembly/bundling fails if these values are missing; use `assembleDebug` for
the beta. Keep the signing key and passwords outside Git.

For Play builds, publish the Digital Asset Links association for `com.nexora.safevault` with the
Play app-signing certificate's SHA-256 fingerprint. Check that the installed
app opens fullscreen and test sign-in, locking, file import and backup export
on a device.
[Trusted Web Activity setup](https://developer.chrome.com/docs/android/trusted-web-activity/quick-start/)

## iOS and iPadOS

The iOS app embeds the HTTPS vault in a WKWebView. It uses the system share
dialog for downloaded files. Build with Xcode on macOS and generate the project
with XcodeGen from `native/ios`.

```sh
xcodegen generate
xcodebuild -project SafeVault.xcodeproj -scheme SafeVault \
  -destination 'generic/platform=iOS Simulator' -derivedDataPath build \
  SAFEVAULT_HOST=vault.example.com CODE_SIGNING_ALLOWED=NO build
```

For a device build or archive, configure the Apple signing team and the real
`SAFEVAULT_HOST` in Xcode. Test sign-in, locking, file import and backup export
on the device before submitting a build.
[XcodeGen project generation](https://github.com/yonaskolb/XcodeGen)

## Browser extension and beta release status

See the [Chrome/Edge autofill instructions](../docs/browser-autofill.md) and
[beta readiness report](../docs/beta-readiness.md). The mobile workflow also
packages a Windows portable beta and the origin-bound extension. In manual
runs, `include_ios` defaults to false while iOS is deferred. Windows builds
can optionally pass `-CertificateThumbprint` to `build.ps1` for Authenticode
signing with a certificate already installed in the current user's store.
The Windows ZIP has a separate SHA-256 checksum file.
