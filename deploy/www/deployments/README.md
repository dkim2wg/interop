# DKIM2 deployments

These files build <https://dkim2.com/deployments/>: one JSON file per entry.

- `sites/` — **services running DKIM2** on real mail (mailbox providers,
  sending platforms, …).
- `software/` — **supporting software**: mail servers and MTAs you can run
  that sign or verify DKIM2. Libraries, test tools and hosted checkers belong
  on the Implementations page instead.

## Adding an entry

Copy an existing file, name it after yourself (lower-case letters, digits and
`-`, ending `.json`), edit it, and open a pull request. One file per entry
means two pull requests never edit the same file.

```json
{
  "name": "Example Mail",
  "url": "https://www.example.com/",
  "kind": "mailbox provider",
  "signs": true,
  "verifies": true,
  "since": "2026-11",
  "notes": "Signing for a few domains so far.",
  "source": "https://example.com/blog/dkim2"
}
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Shown in the table, linked to `url`. |
| `url` | yes | Your home page; must be `https://`. |
| `kind` | yes | Free text: `mailbox provider`, `sender platform`, `mail server`, `MTA`, … |
| `signs` | yes | `true` if it adds DKIM2 signatures to outgoing mail. |
| `verifies` | yes | `true` if it checks DKIM2 on incoming mail and records the result (it need not act on it yet). |
| `since` | no | Month it started, `YYYY-MM`. |
| `notes` | no | One short line. |
| `source` | no | `https://` link to a public statement; the date links to it. Without one the page says "reported to us". |

No other keys are allowed.

## Checking

```sh
perl deploy/bin/build-deployments.pl --data deploy/www/deployments --check
prove deploy/t/build-deployments.t
```

`deploy/bin/stage-www.sh` builds the page; a bad file stops the deploy and
names the file.
