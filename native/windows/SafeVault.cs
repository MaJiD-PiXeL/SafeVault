using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        Uri origin;
        string address = args.Length == 0 ? "http://127.0.0.1:18010/" : args[0];
        if (args.Length > 1 || !Uri.TryCreate(address, UriKind.Absolute, out origin)
            || origin.Host.Length == 0 || origin.UserInfo.Length != 0 || origin.AbsolutePath != "/"
            || origin.Query.Length != 0 || origin.Fragment.Length != 0
            || (origin.Scheme != "https" && !(origin.Scheme == "http" && origin.Host == "127.0.0.1")))
        {
            MessageBox.Show("Open SafeVault with an HTTPS origin or the local beta address.", "SafeVault");
            return;
        }

        Application.Run(new VaultWindow(origin));
    }
}

internal sealed class VaultWindow : Form
{
    private readonly Uri origin;
    private readonly WebView2 browser = new WebView2 { Dock = DockStyle.Fill };
    private readonly Label message = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter };

    public VaultWindow(Uri origin)
    {
        this.origin = origin;
        Text = "SafeVault — Connecting";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1100, 760);
        MinimumSize = new Size(400, 480);
        Controls.Add(browser);
        Controls.Add(message);
        message.Text = "Connecting to " + origin.Authority + "…";
        message.BringToFront();
        Shown += Initialize;
    }

    private bool IsVaultUri(string address)
    {
        Uri destination;
        return Uri.TryCreate(address, UriKind.Absolute, out destination)
            && destination.Scheme == origin.Scheme && destination.IdnHost == origin.IdnHost
            && destination.Port == origin.Port && destination.UserInfo.Length == 0;
    }

    private async void Initialize(object sender, EventArgs args)
    {
        try
        {
            string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NEXORA", "SafeVault");
            var environment = await CoreWebView2Environment.CreateAsync(null, data);
            await browser.EnsureCoreWebView2Async(environment);
            if (IsDisposed) return;

            var web = browser.CoreWebView2;
            web.Settings.AreHostObjectsAllowed = false;
            web.Settings.IsWebMessageEnabled = false;
            web.Settings.AreDevToolsEnabled = false;
            web.NavigationStarting += (view, request) => { request.Cancel = !IsVaultUri(request.Uri); };
            web.NewWindowRequested += (view, request) => { request.Handled = true; };
            web.PermissionRequested += (view, request) => { request.State = CoreWebView2PermissionState.Deny; };
            web.NavigationCompleted += (view, result) =>
            {
                message.Visible = !result.IsSuccess;
                Text = result.IsSuccess ? "SafeVault" : "SafeVault — Connection failed";
                message.Text = "Could not load SafeVault at " + origin.Authority + ". Check the server, then press F5 to retry.";
            };
            browser.Source = origin;
            KeyPreview = true;
            KeyDown += (window, key) => { if (key.KeyCode == Keys.F5) web.Navigate(origin.AbsoluteUri); };
        }
        catch (WebView2RuntimeNotFoundException)
        {
            message.Text = "Microsoft Edge WebView2 Runtime is required to open SafeVault.";
        }
        catch (Exception)
        {
            if (!IsDisposed) message.Text = "SafeVault could not start. Close the app and try again.";
        }
    }
}
