# SafeVault apps

The app projects connect to the SafeVault web deployment. They use the existing
browser vault and its encryption. For release builds, use the HTTPS hostname of
the same-origin SafeVault deployment.

The [mobile build workflow](../.github/workflows/build-mobile.yml) takes a
hostname and produces an Android debug APK and an iOS Simulator bundle.

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

Sign the release bundle with the Android distribution key. At
`https://<hostname>/.well-known/assetlinks.json`, publish the Digital Asset Links
association for `com.nexora.safevault` and the SHA-256 fingerprint of the
certificate that signs the installed package. Use the debug certificate when
testing the debug APK, or the Play app-signing certificate for Play builds.
Check that the installed app opens in the verified fullscreen activity and
exercise sign-in, locking, file import and backup export on a device.
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
