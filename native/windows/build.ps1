param(
    [Parameter(Mandatory)]
    [string]$WebView2Sdk,
    [string]$CertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$sdk = (Resolve-Path -LiteralPath $WebView2Sdk).Path
$library = Join-Path $sdk 'lib/net462'
$runtime = Join-Path $sdk 'runtimes/win-x64/native'
$output = Join-Path $PSScriptRoot 'dist'
New-Item -Path $output -ItemType Directory -Force | Out-Null
$core = Join-Path $library 'Microsoft.Web.WebView2.Core.dll'
$winForms = Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll'
$icon = Join-Path $PSScriptRoot 'SafeVault.ico'
$arguments = @('/nologo', '/target:winexe', '/platform:x64', '/optimize+',
    "/win32icon:$icon",
    "/out:$output/SafeVault.exe", "/reference:$core", "/reference:$winForms",
    '/reference:System.Drawing.dll', '/reference:System.Windows.Forms.dll', (Join-Path $PSScriptRoot 'SafeVault.cs'))
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$dependencies = @($core, $winForms, (Join-Path $runtime 'WebView2Loader.dll'),
    (Join-Path $sdk 'LICENSE.txt'), (Join-Path $sdk 'NOTICE.txt'))
Copy-Item -LiteralPath $dependencies -Destination $output
if ($CertificateThumbprint) {
    $certificate = Get-Item -LiteralPath "Cert:/CurrentUser/My/$CertificateThumbprint"
    if (-not $certificate.HasPrivateKey) { throw 'The signing certificate must include its private key.' }
    $signed = Set-AuthenticodeSignature -LiteralPath (Join-Path $output 'SafeVault.exe') -Certificate $certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
    if ($signed.Status -ne 'Valid') { throw "Executable signing failed: $($signed.Status)" }
}
$files = @('SafeVault.exe', 'Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.WinForms.dll',
    'WebView2Loader.dll', 'LICENSE.txt', 'NOTICE.txt') | ForEach-Object { Join-Path $output $_ }
$archive = Join-Path $output 'SafeVault-Windows-x64.zip'
Compress-Archive -LiteralPath $files -DestinationPath $archive -Force
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $output 'SafeVault-Windows-x64.zip.sha256') -Value "$hash  SafeVault-Windows-x64.zip" -Encoding ascii
Get-Item -LiteralPath $archive
