# Route all outbound mail through the DKIM2 split gateway

2026-07-29

## Problem

A Mailman list message signed on this box carries every subscriber's address in
its `DKIM2-Signature` `rt=` tag, visible to all of them. Observed on a real
message to `test@mailman.dkim2.com`: one `rt=` listing five subscribers.

The cause is documented in `DKIM2Sign.pm` and `SERVER.md` — the milter signs a
message **once**, recording all of the SMTP transaction's `RCPT TO` values. It
cannot fan a queued message out into separately-signed copies, because the
Postfix milter protocol edits a single message at end-of-message.

Spec-04 §8.6 permits one `rt=` naming every recipient, so this is not a
conformance failure. It is a privacy failure: list subscribers are not named in
`To:`/`Cc:`, so they are undisclosed recipients, and disclosing them is the same
class of leak as a leaked `Bcc`.

The fix already exists in this repo — `perl/bin/dkim2-split-lmtp.pl` and
`Mail::DKIM2::Split`, running as `dkim2-split.service` — but nothing routes
through it. It was built as a reference path for a Bcc case the reflector never
hits, and never wired into the list managers.

A second problem surfaced while investigating: `deploy/` cannot rebuild this
box. The DKIM2 mail path is fully covered; the nginx vhosts, both list managers'
configuration, the live Postfix state, and `/usr/local/bin/sympa-sendmail` exist
only on the server.

## Approach

Make `127.0.0.1:10587` — the port Mailman, Sympa and every documented `swaks`
recipe already talk to — the split entry, instead of adding a new port and
updating each client to use it.

The alternative of pointing clients at the existing `10586` was rejected: it
leaves two outbound paths, and any sender not migrated keeps leaking. Setting
`max_recipients: 1` in Mailman and `nrcpt 1` in Sympa would also fix the
symptom without the splitter, but pushes the same policy into each list
manager's config and does nothing for a multi-recipient injection from anywhere
else.

## Design

### Splitter rewiring

`127.0.0.1:10587` gains `content_filter=lmtp:[127.0.0.1]:10590` and loses its
`smtpd_milters`, becoming the split entry. `127.0.0.1:10589` is unchanged and
remains the signing re-injection: outbound milter on, `content_filter=` empty as
the loop guard. `127.0.0.1:10586` is deleted — it duplicated 10589's entry point
under a different number and would only drift.

    Mailman ─┐
    Sympa   ─┼─→ 10587  no milter, content_filter → LMTP
    swaks   ─┘         │
                       ▼
                    10590  dkim2-split-lmtp: one copy per recipient
                       │
                       ▼
                    10589  outbound milter signs each copy
                       │
                       ▼
                    delivery

10587 keeps its existing `smtpd_client_restrictions`, `local_recipient_maps=`
and `smtpd_recipient_restrictions`, and gains the
`receive_override_options=no_unknown_recipient_checks,no_address_mappings,no_header_body_checks`
from the 10586 recipe. `no_address_mappings` matters: without it, alias and
virtual expansion runs before the filter and again after re-injection.

`syslog_name` changes from `postfix/listserv` to `postfix/dkim2-split-in`, so the
logs stop implying that signing happens there.

No client configuration changes. Mailman's `smtp_port: 10587`,
`sympa-sendmail`'s hardcoded port, and the `swaks --server 127.0.0.1:10587`
recipes in SERVER.md all keep working and become Bcc-safe.

`Mail::DKIM2::Split::plan_copies` needs no change. A list message names the list
address in `To:`, so no subscriber is disclosed and every one gets its own copy —
which is the desired result, reached by the existing rule rather than a new one.

### What is deliberately not routed through the splitter

- **The reflector** (`10588`): signs in process and injects to a milter-free
  port. One recipient per message. Routing it through the splitter would
  double-sign it.
- **Postfix-generated bounces and DSNs**: signed by `non_smtpd_milters` in
  cleanup, never through an `smtpd` listener. A bounce has exactly one
  recipient, so it cannot leak.
- **Inbound mail on port 25**: unrelated path.

### New failure mode

`dkim2-split.service` becomes load-bearing for all list mail. If it is down,
Postfix defers with `451` — mail is delayed, never delivered unsigned or with a
leaking `rt=`. The unit already has `Restart=on-failure`. This is a deliberate
trade: availability for correctness.

### Server configuration capture

`deploy/config/` holds a redacted snapshot of the server state that lives
nowhere else:

    deploy/config/nginx/{dkim2.com,mail.dkim2.com,mailman.dkim2.com,sympa.dkim2.com}
    deploy/config/mailman3/{mailman.cfg,mailman-hyperkitty.cfg,web-settings.py}
    deploy/config/sympa/{sympa.conf,aliases}
    deploy/config/postfix/{main.cf.live,master.cf.live}
    deploy/config/aliases
    deploy/sympa-sendmail

`dkim2wg/interop` is public, so three values are replaced with placeholders:

| File | Key | Placeholder |
|---|---|---|
| `mailman3/mailman.cfg` | `admin_pass` | `__MAILMAN_REST_PASS__` |
| `mailman3/mailman-hyperkitty.cfg` | `api_key` | `__HYPERKITTY_API_KEY__` |
| `mailman3/web-settings.py` | `SECRET_KEY` | `__DJANGO_SECRET_KEY__` |

`sympa.conf`, the nginx vhosts and the Postfix state contain no credentials and
are captured verbatim. `main.cf.live` is `postconf -n` output — the real
`transport_maps` and `local_recipient_maps` values, which
`deploy/postfix-main.cf.patch` deliberately omits.

### Capture and drift-check scripts

`deploy/capture-server-config.sh` runs **locally**, fetching over ssh (host
`dkim2` by default) into the checkout, applying the redactions. Refreshing the
snapshot is one command, matching the existing edit-locally / box-pulls
workflow.

`deploy/check-server-config.sh` runs **on the box**, diffing live files against
`deploy/config/` and ignoring placeholder lines. `deploy.sh` calls it last and
reports drift as a **warning, not a gate** — a stale snapshot should be visible
on the next deploy, but must not block a signing fix.

Restore stays a documented sequence in SERVER.md (install files, substitute the
three secrets, reload) rather than a script pretending to reproduce
`apt install mailman3`.

### Order of work

Capture runs **before** the rewiring, so there is a tracked pre-change snapshot
to diff and roll back to, then again afterwards.

## Testing

On the box:

1. **Two-recipient split.** `swaks` to 10587 with two recipients, one named in
   `To:` and one not. Expect two copies with disjoint `rt=`.
2. **Mailman.** Post to `dkim2test@mailman.dkim2.com` (sole member
   `dkim2capture@`, byte-exact Maildir capture). Decode the captured `rt=`;
   expect exactly one address.
3. **Sympa.** Same via `dkim2test@sympa.dkim2.com`.
4. **`deploy/dkim2-list-smoke.sh`** for both managers — must still report
   `verify=pass`.
5. **Null sender.** The splitter passes `'<>'` to `Net::SMTP->mail()`, which may
   double-bracket it into `MAIL FROM:<<>>`. Checked explicitly rather than
   assumed, alongside the existing `smoke-null-sender-milter.pl`.
6. **Drift check** reports clean immediately after a capture.

Rollback: one `master.cf` edit plus `postfix reload`.
