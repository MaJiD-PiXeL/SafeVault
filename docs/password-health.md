# Local password health and generator controls

Open **Security Center** after unlocking a vault. Password health analyzes only
the currently selected vault in browser memory. It lists entries with fewer than
12 Unicode code points, a small set of common password patterns (including some
letter substitutions), repeated one-to-four-character blocks, or simple counting
and keyboard sequences. Exact duplicate passwords are counted across entries.
Case, spaces and Unicode normalization are preserved when comparing duplicates.

The summary counts **entries**, not unique password strings. Weak-pattern and
reuse counts overlap; Need review counts the union once. Empty vaults show zero
checks and an invitation to add an entry. Findings can be filtered and are paged
20 at a time. Review opens the existing encrypted entry editor, with its original
revision checks. Saving refreshes the report from the controller's current entries.
Changing a vault entry does not change the password on its corresponding website.

These are basic, transparent heuristics, not an entropy estimator, complete weak
password dictionary, breach lookup or security certification. Long predictable
phrases may receive no warning. No security percentage, cracking-time estimate or
claim that an unflagged password is safe is made. Existing passwords remain
saveable regardless of warnings; the warnings do not impose composition rules.

Analysis makes no requests and uses no persistent browser storage. The report
contains only entry IDs, warning codes and reuse counts. Its temporary password
map is local to the calculation. The UI reads titles/usernames from the already
unlocked entries; it never renders password values in the report. Locking the
vault clears the entries, report, filters and open editor through the existing
controller lifecycle. A Lock vault action is available in the header on every
page while unlocked. JavaScript/browser memory cannot be forensically zeroized.

**Password Generator** supports uppercase, lowercase, digits, symbols and excluding
similar-looking characters. Length remains 12–128. At least one group is required;
every enabled group is represented. Random bytes come from Web Crypto with
rejection sampling both for individual alphabet indices and complete candidates,
so generated strings are uniform among strings meeting the selected groups.
No Math.random or network service is used. Changing options/length clears the old
output; Clear removes it, and hidden-tab/account/lock handling remains active.
Copy remains explicit and does not automatically clear the OS clipboard.

The entry editor shows local warnings as you type and can generate a replacement.
The dashboard now shows the real number of entries to review. The entry list also
supports recent-update/title sorting, clearing filters and an actionable empty
vault state. These controls work at mobile and desktop widths.

Validation: frontend unit tests cover exact duplicate semantics, overlapping and
empty counts, Unicode, pattern detection, every nonempty generator group
combination, rejected options and forbidden weak randomness. Existing encrypted
CRUD, revision, cancellation and locking tests remain in the suite. Browser QA
uses an isolated disposable SQLite database and public synthetic credentials.

References: [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
