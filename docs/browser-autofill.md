# Chrome and Edge autofill beta

Build an extension for the vault's exact origin:

```powershell
python native/extension/build.py --origin https://vault.example.com
```

The output directory is `native/extension/dist/SafeVault-Extension` and its ZIP
is alongside it. The default build targets the isolated local beta at
`http://127.0.0.1:18010`. A new hosted origin requires rebuilding the package.
Load the output directory as an unpacked extension in Chrome/Edge developer
mode. This package has not been submitted to either extension store.

Copy the ID from its popup into **Security Center → Browser autofill**. Pair
only an installed extension you trust; requests never automatically pair an ID
supplied in a URL. Pairing is local to the account and browser.

On an HTTPS login page, click the extension and choose **Choose a login in
SafeVault**. The extension opens a vault tab with a random, two-minute request.
Sign in/unlock and explicitly choose a matching entry. Its stored website must
match the exact HTTPS origin, including any nondefault port. Subdomains and
HTTP URLs do not match automatically. A fresh request is needed if sign-in or
pairing takes longer than two minutes.

The extension has only `activeTab`, `scripting` and `storage` permissions, no
permanent website host permissions. Its external-message manifest allows only
the packaged vault hostname; runtime checks further enforce the exact origin,
source tab, top frame, request token and expiry. Only routing metadata is saved
in session storage, never credentials. The token is consumed before injection;
the worker serializes messages to reject concurrent reuse.

Injection rechecks the destination origin immediately before touching fields,
uses only the main frame and requires an unambiguous visible username/password
form. It rejects cross-origin form actions, new-password fields and pages with
multiple visible password inputs. It dispatches input/change events and does
not submit the form. Credential fields necessarily become readable by the
selected website, including scripts running there.

This is explicit browser filling, not a system-wide Android AutofillService,
Windows credential provider or Firefox extension. Shadow DOM, multi-step forms
and unusual controls may need manual entry. Store publication, real extension
installation and end-to-end testing on target websites remain outstanding.

[activeTab](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab)
and [external messaging](https://developer.chrome.com/docs/extensions/reference/manifest/externally-connectable)
