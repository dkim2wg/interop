# DKIM2 Demo Server — dkim2.com

## Overview

A Digital Ocean VPS running the DKIM2 demonstration server.

| Item | Value |
|------|-------|
| Hostname | mail.dkim2.com |
| IP | 134.209.211.166 |
| OS | Ubuntu 25.10 (Questing Quokka) |
| SSH alias | `ssh dkim2` (configured in ~/.ssh/config) |

---

## Software Components

### 1. Postfix (system package)

**Role:** Edge MTA — receives inbound mail on port 25, routes outbound mail
from lists via port 10587, the DKIM2 **split gateway** (see "Split outbound
gateway" below: 10587 fans each message out per recipient, then 10589 signs each
copy, so a `DKIM2-Signature` `rt=` never names anyone but its own recipient).

**Config files:**
- `/etc/postfix/main.cf` — main configuration
- `/etc/postfix/master.cf` — process table (includes listserv entry)

**Key `main.cf` settings:**
```
myhostname = mail.dkim2.com
mydomain = dkim2.com
myorigin = $mydomain
mydestination = dkim2.com, test1-5.dkim2.com, sympa.dkim2.com,
                mailman.dkim2.com, localhost
smtpd_milters = unix:var/run/dkim2-milter-in.sock
non_smtpd_milters = unix:var/run/dkim2-milter-in.sock,
                    unix:var/run/dkim2-milter-out.sock
```

**`master.cf` split-gateway entry (port 10587):** receives mail from
Mailman/Sympa and runs **no** milter — it hands the message to the splitter, and
signing happens on 10589 after the fan-out. Source of truth is
`deploy/postfix-dkim2-split.master.cf`; the live process table is captured in
`deploy/config/postfix/master.cf.live`.

```
127.0.0.1:10587 inet n  -  y  -  -  smtpd
  -o syslog_name=postfix/dkim2-split-in
  -o content_filter=lmtp:[127.0.0.1]:10590
  -o smtpd_milters=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o local_recipient_maps=
  -o smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination
  -o receive_override_options=no_unknown_recipient_checks,no_address_mappings,no_header_body_checks
```

Until 2026-07-29 this port signed directly (`syslog_name=postfix/listserv`,
`smtpd_milters=dkim2-milter-out.sock`), which is what leaked whole subscriber
lists into one `rt=`.

**Update:** `systemctl restart postfix`

#### Signing Postfix-generated (delayed) DKIM2 bounces

**Why:** Postfix runs no milters or content filters on its own bounces by
default. A *delayed* bounce — accept at RCPT (`250`), delivery fails later,
`bounce(8)` originates an RFC3464 DSN with `MAIL FROM <>` — would otherwise
leave unsigned and unverifiable per draft-02 §11. This is the recipe (the
substance of a mailing-list reply to that question).

**The recipe (`main.cf`):**
```
internal_mail_filter_classes = bounce
non_smtpd_milters = unix:var/run/dkim2-milter-out.sock
disable_mime_output_conversion = yes
```
- `internal_mail_filter_classes = bounce` is the key knob: it makes Postfix
  run `non_smtpd_milters` (and content filters) on its own bounce/notification
  messages, off by default.
- `non_smtpd_milters` must be **outbound-only**. Left listing both sockets (as
  in the "Key `main.cf` settings" above), the inbound milter would stamp the
  bounce with `Authentication-Results` and a spurious `Message-Instance`
  before the outbound milter signs it. Dropping the inbound socket here loses
  nothing: a genuine *inbound* DSN from outside still reaches the inbound
  milter via `smtpd_milters` on port 25 — internally-injected mail (bounces,
  local submissions) only ever needs the outbound (signing) milter.
- `disable_mime_output_conversion = yes` is **required for the signed bounce to
  survive delivery** (spec §12, "Preventing Transport Conversions"). `bounce(8)`
  emits DSNs as **8bit** (the human-readable part is `charset=utf-8;
  Content-Transfer-Encoding: 8bit`, propagated to the `multipart/report`
  container and the `message/rfc822` part — regardless of body content). The
  milter signs that 8bit DSN; without this setting, Postfix downgrades it to
  7bit when the next hop does not advertise `8BITMIME`, rewriting the
  `Content-Transfer-Encoding` header **after** signing and invalidating the
  DKIM2 Message-Instance header hash. Verified: to an 8BITMIME hop the DSN
  verifies either way; to a non-8BITMIME hop it verifies **only** with this
  setting. (See the interoperability note in `c/INTEROP-NOTES.md` — Postfix's
  8bit DSNs are a general DKIM2 transport-conversion hazard.)

**Routing (`transport_maps` / `local_recipient_maps`):** append
`hash:/etc/postfix/dkim2-delayedbounce` (the map at
`deploy/postfix-dkim2-delayedbounce`) to your existing `transport_maps` and
`local_recipient_maps` — do **not** set either parameter to a bare/partial
value, since Postfix takes only one value per parameter in `main.cf` and this
server's `transport_maps`/`local_recipient_maps` already carry the Mailman
`regexp:` map and (for `local_recipient_maps`) `proxy:unix:passwd.byname`. See
the Mailman/Sympa routing setup below (§6, "DKIM2 Reflector" — the `postconf
-e` block) for this server's actual full values, which already include the
`dkim2-delayedbounce` map appended.
This is the demo's own live address, `reflector-delayedbounce@dkim2.com`:
accepted at RCPT (`250`), then routed to the **`dkim2-delayedbounce` pipe(8)
transport** (`deploy/postfix-dkim2-reflect.master.cf`), whose delivery agent
(`/usr/local/bin/dkim2-delayedbounce-fail`) always exits with a permanent
failure — so Postfix's `bounce(8)` originates the DSN. Accept-then-fail-at-
delivery deterministically models a delayed bounce with no external dependency.

> **Do NOT use the `error:` transport for this.** `error:` rejects the
> recipient at RCPT time for SMTP clients (a synchronous `550`), which is
> *not* a delayed bounce — no DSN is generated. (It only appears to work via
> local pickup, which bypasses smtpd.) The failing pipe accepts at RCPT and
> fails at delivery, which is what produces the asynchronous, MTA-generated
> DSN. Add the `dkim2-delayedbounce` pipe service to `master.cf` and set
> `dkim2-delayedbounce_destination_recipient_limit = 1`.

See `deploy/postfix-dkim2-delayedbounce` for the map file and install steps.

**Milter requirement:** the outbound milter must sign a null-sender (`MAIL
FROM <>`) message by falling back to the `From:` header domain (e.g.
`MAILER-DAEMON@mail.dkim2.com` → `dkim2.com`, via the existing keydir
parent-walk) when that domain resolves to a held key, and emit `mf=<>` on the
resulting `DKIM2-Signature`. This is already implemented in the stock
`perl/bin/dkim2-milter.pl`, so any operator running it gets bounce-signing
"for free" once the two `main.cf` settings above are in place — no code
changes needed on the operator side. With no existing DKIM2 chain on a fresh
bounce, this produces a clean origin signature: `Message-Instance m=1` +
`DKIM2-Signature i=1`.

**§11 conformance and known limits:**
- **Addressing.** Postfix addresses the DSN to the envelope `MAIL FROM`,
  which in a DKIM2 chain *is* the `mf=` of the highest-numbered
  `DKIM2-Signature` — satisfying §11's "a DSN MUST be addressed to the MTA
  that sent the message."
- **Null `mf=` on the DSN itself.** The DSN's own signature carries `mf=<>` —
  you cannot bounce a bounce, matching "if this field is null (`mf=<>`) then
  a DSN MUST NOT be sent."
- **Embedded-original verification (§11.1.2) is receiver-side.** We preserve
  the embedded original's headers verbatim, but if Postfix truncates the
  original body (`bounce_size_limit`), the enclosed message's own body-MI may
  not verify — draft-02 removed the `z` body recipe that §11 had relied on
  for truncated bodies. Acceptable for a demo, and documented rather than
  worked around; the enclosed message in the demo is usually not itself
  DKIM2-signed anyway.

This is **EXPERIMENTAL**: it signs Postfix's bounce verbatim (no
reconstruction of the enclosed original, no re-addressing to a different
hop's `mf=`), and does not attempt bounce *propagation* through a forwarder
(§11.1.1) — that is `reflector-dsn`'s job, via `Mail::DKIM2::DSN->propagate`.

---

### 2. DKIM2 Milter (dkim2-milter.pl)

**Role:** DKIM2 signing and verification + Message-Instance header computation.

**Source:** `/root/interop/` — this git repository (`github.com/dkim2wg/interop`).
The milter code is in `perl/bin/dkim2-milter.pl` and `perl/lib/Mail/DKIM2/`.

**Two instances run:**

| Service | Mode | Socket | Purpose |
|---------|------|--------|---------|
| `dkim2-milter-inbound` | inbound | `dkim2-milter-in.sock` | Verify DKIM2, add Auth-Results, add MI v=1 |
| `dkim2-milter-outbound` | outbound | `dkim2-milter-out.sock` | Compute MI diff, sign with DKIM2 |

**Service files:** `/etc/systemd/system/dkim2-milter-{inbound,outbound}.service`
(also committed to `deploy/` in this repo — but on server `ProtectHome=no`
since repo is under `/root/`)

**Keys:** `/etc/dkim2/keys/{domain}/{selector}.key` (RSA PKCS#8 PEM format)
- `dkim2.com/sel1.key`, `dkim2.com/ed25519.key`
- `test{1-5}.dkim2.com/sel1.key`, etc.

**Snapshots:** `/var/spool/dkim2/snapshots/`

**Update process:**
```bash
ssh dkim2
cd /root/interop
git pull
systemctl restart dkim2-milter-inbound dkim2-milter-outbound
```

#### Recipient leak on origination — FIXED 2026-07-29 by the split gateway

The outbound milter signs each message **once**, recording **all** of the SMTP
transaction's envelope recipients in a single DKIM2-Signature `rt=`. It does
**not** split the message into per-recipient instances.

- **Forwarding hops are unaffected**: the message was already split at
  origination, so each copy carries a disclosed recipient set and the single
  `rt=` reveals nothing new.
- **Origination is the problem**: envelope recipients not named in `To:`/`Cc:`
  get written into `rt=`, visible to every recipient. That covers a submitted
  message's `Bcc`, and — as observed on a real `test@mailman.dkim2.com` post
  whose `rt=` listed all five subscribers — **every subscriber of a mailing
  list**, since a list post names only the list address in `To:`. Spec-04 §8.6
  permits one `rt=` naming every recipient, so this is a privacy failure, not a
  conformance one.

The milter can't fix this: the Postfix milter protocol edits a single queued
message at end-of-message and cannot fan one message into several
separately-signed instances. The split must happen **before** signing.

**This is now fixed on this box for all originated mail** — port 10587, which
Mailman, Sympa and every `swaks` recipe below already use, is the split entry.
See "Split outbound gateway" below for the deployed wiring. The rest of this
section is the generic Postfix recipe, kept because it is the answer for anyone
running DKIM2 on Postfix without this repo's LMTP daemon:

**A content filter that re-injects one copy per recipient through the signing
milter.** New mail is submitted to a filter that fans it out per recipient;
each single-recipient copy is re-injected to a signing listener, so `rt=`
records only that copy's recipient.

1. Split transport (`master.cf`):
   ```
   dkim2-split unix  -       n       n       -       -       pipe
     flags=q user=nobody:nogroup
     argv=/usr/local/bin/dkim2-split ${sender} ${recipient}
   ```
2. One recipient per invocation (`main.cf`):
   ```
   dkim2-split_destination_recipient_limit = 1
   ```
3. Submission service runs the split filter and does **not** sign there
   (signing happens post-split) — on the `submission`/`smtps` `smtpd` in
   `master.cf`:
   ```
     -o content_filter=dkim2-split:
     -o smtpd_milters=
   ```
4. A re-injection listener that **does** sign and does **not** re-filter (the
   loop guard) — add to `master.cf`:
   ```
   127.0.0.1:10589 inet  n  -  n  -  -  smtpd
     -o content_filter=
     -o smtpd_milters=unix:var/run/dkim2-milter-out.sock
     -o receive_override_options=no_address_mappings,no_unknown_recipient_checks,no_header_body_checks
     -o smtpd_authorized_xclient_hosts=127.0.0.0/8
   ```
5. `/usr/local/bin/dkim2-split` re-injects one copy per recipient:
   ```perl
   #!/usr/bin/perl
   use strict; use warnings;
   use Net::SMTP;
   # Postfix invokes this once per recipient (dkim2-split_destination_recipient_limit=1),
   # passing ${sender} and the single ${recipient}. Re-inject one copy for that
   # recipient to the signing listener (127.0.0.1:10589), which runs the DKIM2
   # milter and NO content filter, so rt= records only this recipient -> no Bcc leak.
   my ($sender, $rcpt) = @ARGV;
   my $msg = do { local $/; <STDIN> };
   my $smtp = Net::SMTP->new('127.0.0.1', Port => 10589, Timeout => 30) or exit 75; # EX_TEMPFAIL -> retry
   $smtp->mail(length $sender ? $sender : '<>');
   $smtp->recipient($rcpt) or exit 75;
   $smtp->data(); $smtp->datasend($msg); $smtp->dataend(); $smtp->quit;
   exit 0;
   ```

Notes:
- Per-recipient split is always Bcc-safe. It also separates disclosed
  (`To:`/`Cc:`) recipients into their own copies, which the spec permits; for
  efficiency you could keep disclosed recipients together in one copy and split
  only the Bcc'd ones, but per-recipient is the simplest always-safe rule.
- The loop guard is essential: the re-injection listener (`10589`) MUST have
  `content_filter=` empty, or copies are re-split forever.
- The signing milter runs **only** on the re-injection path, never on
  submission — so it signs the single-recipient copies (correct `rt=`), not the
  pre-split message.

**Cleaner variant — an LMTP content filter (implemented).** Instead of the
per-recipient `pipe(8)` fan-out, run the filter as a persistent **LMTP**
daemon. This repo ships one: `perl/bin/dkim2-split-lmtp.pl` (grouping logic in
`Mail::DKIM2::Split`, tested by `t/split.t` + `t/split-lmtp.t`). It listens on
`127.0.0.1:10590`, and for each message re-injects one copy per disclosed group
/ per Bcc recipient to the signing listener (`10589`), answering one LMTP status
per recipient. Run it as a service (as `nobody`), then point submission at it:

```
# on the submission smtpd (master.cf): filter, don't sign here
  -o content_filter=lmtp:[127.0.0.1]:10590
  -o smtpd_milters=
```

LMTP is the right protocol because it returns a **separate status per
recipient** after the final `.` (that's exactly what distinguishes it from
SMTP). So Postfix delivers the message to the daemon **once, with all
recipients**, and for each recipient the daemon does one of:

- **re-inject** a single-recipient (or disclosed-group) copy to the signing
  listener (`127.0.0.1:10589`, milter on / `content_filter=` empty) and reply
  `250` for that recipient; or
- **bounce** that recipient by replying a per-recipient `5xx` — Postfix then
  generates the DSN for just that address.

This is nicer than the pipe: one invocation with full recipient visibility (so
you can keep disclosed `To:`/`Cc:` recipients together in a single copy and
split only the Bcc'd ones), per-recipient accept-or-bounce in the protocol
itself, and no per-message process spawn. Same loop guard applies — the
re-injection listener (`10589`) must not re-filter.

**Before-queue vs after-queue.** Both recipes above run *after* Postfix has
accepted the message — the client already got its `250` — so a per-recipient
failure becomes an async bounce. You can instead run the filter *before-queue*
(`smtpd_proxy_filter`), inside the client's SMTP session, so a failure is a
synchronous `5xx` to the client and **no bounce is generated at all** — the
cleanest outcome for origination. The catch is the SMTP response model: the
client gets per-recipient answers only at **RCPT** (before you have the body to
sign or split) and a **single** verdict after the final `.`. So before-queue
you can accept-or-reject the *whole* submission in session, but you can't hand
back per-recipient sign/bounce results — LMTP's per-recipient statuses only
help when Postfix speaks LMTP to the filter as an *after-queue* delivery. A
before-queue proxy also ties up an smtpd worker for the whole split+re-inject.
Pragmatic split: reject what you can at RCPT in-session (no bounce), then fan
out and sign after-queue for the accepted set; a *downstream* per-recipient
failure is async regardless (and is then subject to the bounce-trust rules —
see the DSN discussion in `docs/` / the interop notes).

#### Split outbound gateway (DEPLOYED — all originated mail, since 2026-07-29)

Every message this box originates is fanned out per recipient **before** signing.

```
Mailman (smtp_port: 10587)  ─┐
Sympa (via sympa-sendmail)  ─┼─→  10587  split entry: NO milter, content_filter
swaks --server ...:10587    ─┘         │
                                       ▼
                                  10590  dkim2-split-lmtp
                                       │   one copy per disclosed group,
                                       │   one per undisclosed recipient
                                       ▼
                                  10589  outbound milter signs each copy
                                       │
                                       ▼
                                   delivery
```

- **Daemon:** `dkim2-split.service` (`deploy/dkim2-split.service`) runs
  `/usr/local/bin/dkim2-split-lmtp` on `127.0.0.1:10590`, re-injecting to `10589`.
- **Postfix listeners:** `deploy/postfix-dkim2-split.master.cf` defines both
  `10587` (split entry) and `10589` (signing re-injection, `content_filter=`
  empty as the loop guard).
- All loopback-only — this box has no public submission and `mynetworks` is
  localhost, so there is no open-relay exposure.

**Why 10587 and not a new port.** It is the port Mailman's `smtp_port`,
`/usr/local/bin/sympa-sendmail` and every documented `swaks` recipe already talk
to, so nothing needed reconfiguring — and, more importantly, there is no
surviving unsplit path for a future sender to point at by mistake. An earlier
iteration of this used a separate `10586` entry that nothing routed through,
which is exactly how the leak went unnoticed. `10586` has been retired.

**Not routed through the gateway, deliberately:**
- the **reflector** (`10588`) — signs itself, so it would be double-signed, and
  it only ever sends to one recipient;
- **Postfix-generated bounces/DSNs** — signed by `non_smtpd_milters` in cleanup,
  never via an `smtpd` listener, and always single-recipient.

**Trade-off:** `dkim2-split.service` is now load-bearing for all list mail. If it
is down, Postfix defers with `451` — mail is delayed, never delivered unsigned or
with a leaking `rt=`. The unit has `Restart=on-failure`.

Migration (already applied; idempotent, so safe to re-run):
```bash
ssh dkim2 'cd /root/interop && git pull && python3 deploy/migrate-10587-to-split.py'
ssh dkim2 'postfix check && postfix reload'
```
It backs `master.cf` up first and refuses to run from a stale checkout (it will
not remove `10587` unless the fragment it is about to append actually defines it).

Verifying the split:
```bash
# two recipients, one disclosed in To: and one not -> two copies, disjoint rt=
ssh dkim2 'swaks --server 127.0.0.1:10587 --from dkim2capture@dkim2.com \
  --to dkim2capture@dkim2.com,dkim2capture@test1.dkim2.com \
  --h-To dkim2capture@dkim2.com --h-Subject "split test" --body x'
ssh dkim2 'journalctl -u dkim2-split -n5 --no-pager'     # one "copy rcpts=[...]" per copy
```
Both addresses alias to the same capture Maildir, so both copies are readable
locally. Decode each copy's `rt=` and expect exactly one recipient in each.

---

### 3. Mailman 3

**Role:** Mailing list manager at `mailman.dkim2.com`.

**Source:** Fork at `github.com/brong/mailman` with DKIM2 additions in
`src/mailman/handlers/message_instance.py` and
`src/mailman/mta/message_instance.py`.

**Installation:** Installed as a Python package in a venv at `/opt/mailman/venv/`.
The installed package files live at:
```
/opt/mailman/venv/lib/python3.13/site-packages/mailman/
```
Version: 3.3.11b1 (from brong fork, installed via pip in development mode or
copied directly).

**Config files:**
- `/etc/mailman3/mailman.cfg` — main mailman config
- `/etc/mailman3/web/settings.py` — Django settings for Postorius + HyperKitty
- `/etc/mailman3/postfix-mailman.cfg` — Postfix transport map config
- `/etc/mailman3/mailman-hyperkitty.cfg` — HyperKitty plugin config

**Key `mailman.cfg` settings:**
```ini
[mta]
incoming: mailman.mta.postfix.LMTP
outgoing: mailman.mta.deliver.deliver
lmtp_host: 127.0.0.1
lmtp_port: 8024
smtp_host: localhost
smtp_port: 10587        # DKIM2 split gateway → fan out, then sign on 10589
message_instance: yes   # global DKIM2 MI enable

[database]
url: sqlite:////var/lib/mailman3/mailman.db
```

**Services:**
- `mailman3.service` — core Mailman daemon (LMTP on :8024, REST on :8001)
- `mailman-web.service` — gunicorn serving Postorius + HyperKitty on :8080

**Web UI:** `https://mailman.dkim2.com` → nginx → gunicorn :8080

**REST API:** `http://localhost:8001` (user: `restadmin`, pass: `dkim2demo`)

**Logs:**
- `/var/log/mailman3/mailman.log` — core mailman
- `/var/log/mailman3/dkim2.log` — DKIM2 MI handler
- `/var/log/mailman3/mailman-web.log` — Django/gunicorn

**Database:** `/var/lib/mailman3/mailman.db` (SQLite)
**Web database:** `/var/lib/mailman3/web/mailman-web.db` (SQLite, Django)

**Lists:**
- `test@mailman.dkim2.com` — subject prefix + footer (full MI)
- `test-subject-only@mailman.dkim2.com` — subject prefix only
- `test-body-only@mailman.dkim2.com` — footer only
- `test-passthrough@mailman.dkim2.com` — no modification (passthrough)

**Log rotation gotcha (fixed 2026-06-18):** Mailman core runs as user
`mailman`, but the distro `/etc/logrotate.d/mailman3` shipped
`create 640 list list`. After a rotation, `mailman.log` became owned by
`list`, the `mailman`-user service could no longer write it, and `mailman3`
crash-looped (`PermissionError: /var/log/mailman3/mailman.log`) — taking down
Postorius ("Mailman REST API not available"). A second `mailman3-fix` stanza was
ignored by logrotate as a duplicate. Corrected config is committed at
`deploy/logrotate-mailman3` (single stanza, `create 640 mailman mailman`,
`su mailman mailman`, `mailman reopen` postrotate); deploy it to
`/etc/logrotate.d/mailman3` and delete `/etc/logrotate.d/mailman3-fix`.
Recovery if it recurs: `chown mailman:mailman /var/log/mailman3/mailman.log &&
systemctl restart mailman3`.

**Update process:**

Sync changed handler files from the local brong/mailman checkout:
```bash
VENV=/opt/mailman/venv/lib/python3.13/site-packages/mailman
rsync -av src/mailman/handlers/message_instance.py \
          src/mailman/mta/message_instance.py \
          root@dkim2.com:$VENV/handlers/
```
Or from the repo directory on the local machine, run the deploy script
(see below).  After copying files:
```bash
ssh dkim2
# Run Alembic migration if model changed:
/opt/mailman/venv/bin/mailman --config /etc/mailman3/mailman.cfg \
    shell -r mailman.database.initialize:initialize
# or: /opt/mailman/venv/bin/alembic upgrade head
systemctl restart mailman3 mailman-web
```

**Per-list DKIM2 toggle (added 2026-03-23):**
The `dkim2_message_instance` boolean attribute on each list can be set
via the REST API to disable MI for a specific list:
```bash
curl -u restadmin:dkim2demo -X PATCH \
     http://localhost:8001/3.1/lists/test-passthrough.mailman.dkim2.com/config \
     -d '{"dkim2_message_instance": false}'
```

---

### 4. Sympa

**Role:** Mailing list manager at `sympa.dkim2.com`.

**Source:** Fork at `github.com/brong/sympa` (branch `dkim2`) with DKIM2
additions in `src/lib/Sympa/Message.pm`.

**Installation:** Installed from the Debian/Ubuntu `sympa` package, then
DKIM2-modified Perl files overlaid into `/usr/share/sympa/lib/`.
The key modified file is `/usr/share/sympa/lib/Sympa/Message.pm`.

Version: 6.2.76

**Config files:**
- `/etc/sympa/sympa/sympa.conf` — main Sympa config
- `/etc/sympa/auth.conf` — authentication config

**Key `sympa.conf` settings:**
```
domain sympa.dkim2.com
listmaster admin@dkim2.com
wwsympa_url https://sympa.dkim2.com/sympa
db_type SQLite
db_name /var/lib/sympa/sympa.sqlite
sendmail /usr/local/bin/sympa-sendmail
```

**`/usr/local/bin/sympa-sendmail`:** Custom sendmail wrapper that submits
outbound mail via SMTP to localhost:10587 — the DKIM2 split gateway — so the
message is fanned out per recipient and then signed by the outbound milter only
(never the inbound one). Tracked as `deploy/sympa-sendmail`; it existed nowhere
but the box until 2026-07-29.

**Services:**
- `sympa.service` — main Sympa process
- `sympa-archived.service`, `sympa-bounced.service`, `sympa-bulk.service`,
  `sympa-task_manager.service` — Sympa sub-processes
- `wwsympa.service` — web interface FastCGI backend (socket:
  `/run/sympa/wwsympa.socket`)

**Web UI:** `https://sympa.dkim2.com/sympa` → nginx → FastCGI

**Static assets (fixed 2026-06-18):** the nginx vhost must serve two distinct
trees under the `/static-sympa/` URL, or the UI loads unstyled with broken
icons:
- `/static-sympa/css/` → **`/var/lib/sympa/css/`** — per-robot CSS that Sympa
  generates at runtime (`css_path`), e.g. `css/sympa.dkim2.com/style.css`.
- `/static-sympa/` → **`/opt/sympa-dkim2/www/`** — the shipped JS/fonts/icons
  for the running 6.2.76 build (Font Awesome 6). NOTE: the distro
  `/usr/share/sympa/static_content` is a **stale older bundle** (Font Awesome 4,
  wrong filenames) — do not point nginx there.
```
location /static-sympa/css/ { alias /var/lib/sympa/css/; }
location /static-sympa/     { alias /opt/sympa-dkim2/www/; }
```

**Database:** `/var/lib/sympa/sympa.sqlite` (SQLite)

**Perl dependency (Mail::DKIM2):** Installed system-wide from this repo:
```bash
ssh dkim2
cd /root/interop/perl
perl Makefile.PL && make && make install
```

**Update process:**
```bash
# From local machine
rsync -av src/lib/Sympa/Message.pm \
          root@dkim2.com:/usr/share/sympa/lib/Sympa/Message.pm
ssh dkim2 systemctl restart sympa sympa-bulk sympa-archived
```

---

### 5. Nginx

**Role:** TLS termination and reverse proxy.

**Config:** `/etc/nginx/sites-enabled/`
- `dkim2.com` → apex landing page (also the 443 `default_server`); `www` → apex
- `mailman.dkim2.com` → proxy to gunicorn :8080
- `sympa.dkim2.com` → FastCGI to wwsympa socket

**Apex landing page:** Static `index.html` + `style.css` served from
`/var/www/dkim2.com`. Source of truth is `deploy/www/` in this repo. The
`dkim2.com` vhost is the 443 `default_server`, so the bare domain (and
unknown-host hits) land on the explainer instead of falling through to
Mailman. Deploy after editing `deploy/www/`:
```bash
ssh dkim2 'cd /root/interop && git pull && \
    install -m 644 deploy/www/index.html deploy/www/style.css /var/www/dkim2.com/'
# (no service restart needed — nginx serves the files directly)
```

**TLS certificates:** Let's Encrypt, stored at:
- `/etc/letsencrypt/live/dkim2.com/` (covers `dkim2.com` + `www.dkim2.com`)
- `/etc/letsencrypt/live/mailman.dkim2.com/`
- `/etc/letsencrypt/live/sympa.dkim2.com/`
- `/etc/letsencrypt/live/mail.dkim2.com/` (for Postfix SMTP TLS)

**Renewal (webroot, no downtime):** All four certs renew via the
`webroot` authenticator, served from `/var/www/acme`. Each port-80
server block (including a minimal `mail.dkim2.com` vhost that exists
only for this) includes `snippets/acme-challenge.conf`, which maps
`/.well-known/acme-challenge/` to that webroot. Auto-renewal runs from
the system `certbot.timer`.

> History: certs were originally issued with the `standalone`
> authenticator, which binds port 80 itself and so conflicted with
> nginx — every auto-renewal failed and the certs expired 2026-06-17.
> Switched to webroot 2026-06-18. NOTE: `certbot renew` adds a random
> delay of up to ~8 min before renewing (anti-thundering-herd); this is
> normal, not a hang. Add `--no-random-sleep-on-renew` for an immediate
> manual renew.

```bash
# Manual renew / force:
ssh dkim2 'certbot renew --no-random-sleep-on-renew'
# Dry-run (verifies webroot path, nginx stays up):
ssh dkim2 'certbot renew --dry-run --no-random-sleep-on-renew'
```

---

### 6. DKIM2 Reflector

**Role:** Six addresses that verify an incoming DKIM2 message, transform it per
mode, and reflect it back to the sender — signing as `dkim2.com` only when the
incoming DKIM2 chain verified. For interop testing of chain behaviour.

**Addresses** (delivered by the `dkim2-reflect` pipe transport — see below):

| Address | Behaviour at the sender |
|---------|-------------------------|
| `reflector-raw@dkim2.com` | re-signed, unchanged (new sig, same `m=`) — verifies |
| `reflector-subject@dkim2.com` | `Subject:` prefixed `[DKIM2] `; new MI `rh` recipe |
| `reflector-body@dkim2.com` | footer appended; new MI `rb` recipe |
| `reflector-both@dkim2.com` | subject + footer |
| `reflector-redacted@dkim2.com` | footer appended; MI body recipe `"b":null` (not undoable) |
| `reflector-damage@dkim2.com` | a line appended *after* signing — fails body-hash verification |
| `reflector-dsn@dkim2.com` | returns a fresh DKIM2-signed DSN (`multipart/report`) for the message, regardless of whether it arrived signed (draft-03 §12.1) — verifies as a new one-hop message |
| `reflector-brand-nd@dkim2.com` | like `reflector-brand`, but the i=1 brand hop uses the `nd=` "imaginary hop" encoding (draft-03 §9.3) instead of `mf=`/`rt=`; the chain still verifies (nd= matches i=2's d=) |

> **Not part of this table:** `reflector-delayedbounce@dkim2.com` is a
> separate demo address — a genuinely **Postfix-originated** delayed bounce,
> not a `dkim2-reflect` pipe transform. See "Signing Postfix-generated
> (delayed) DKIM2 bounces" under Postfix (§1) above.

#### `reflector-bounces@dkim2.com` — envelope sender on reflector-sent mail

`reflector-bounces@dkim2.com` is the envelope `MAIL FROM` the reflector
wrapper uses on every message it sends (all modes). It is a plain alias to an
mbox (see `deploy/reflector-aliases`): bounces/DSNs for undeliverable reflected
mail come back here and are captured for inspection rather than double-bouncing.

Always adds `Authentication-Results` + `X-DKIM2-Reflector` (mode/auth/signed).
If the incoming chain did not verify, the transform is still applied but no
reflector signature is added (`X-DKIM2-Reflector: ... signed=no`).

**Delivery — pipe(8) transport, NOT a local(8) alias.** The reflector addresses
are routed by a `pipe(8)` transport, *not* `/etc/aliases` `|command` entries.

> **Historical note (no longer the reason):** the original motivation was that
> a `local(8)` alias prepends a `Delivered-To:` header, which the reflector
> would hash into its Message-Instance and break verification. As of
> draft-ietf-dkim-dkim2-spec-04 §4.1, **`Delivered-To` IS in the DKIM2 skip
> list** (added with RFC 9228), so it no longer affects the hash and that
> motivation is obsolete.

`pipe(8)` is still preferred for two independent reasons that remain valid: it
exposes the recipient localpart and envelope sender as `${user}`/`${sender}`
macros (how the wrapper learns the mode and return-path — `pipe(8)` does not
export `$SENDER`), and it avoids `local(8)`'s mailbox/alias semantics for these
command addresses. Switching back to a `local(8)` alias is therefore possible
but unnecessary; leave the `pipe(8)` transport as-is.

Setup (sources in `deploy/`):
```bash
# 1. pipe service
cat deploy/postfix-dkim2-reflect.master.cf >> /etc/postfix/master.cf
# 2. transport + recipient map (same file serves both roles)
install -m 644 deploy/postfix-dkim2-transport /etc/postfix/dkim2-transport
postmap /etc/postfix/dkim2-transport
# 3. main.cf: append the map to BOTH lists, and one invocation per recipient
postconf -e \
  "transport_maps = regexp:/var/lib/mailman3/data/postfix_lmtp hash:/etc/postfix/dkim2-transport hash:/etc/postfix/dkim2-delayedbounce" \
  "local_recipient_maps = proxy:unix:passwd.byname \$alias_maps regexp:/var/lib/mailman3/data/postfix_lmtp hash:/etc/postfix/dkim2-transport hash:/etc/postfix/dkim2-delayedbounce" \
  "dkim2-reflect_destination_recipient_limit = 1"
# 4. remove the old reflector-* |command lines from /etc/aliases (keep
#    reflector-bounces), then:
newaliases && postfix reload
```
`transport_maps` routes the addresses to the pipe so `local(8)` never runs;
`local_recipient_maps` lists them so they still pass RCPT (they are no longer in
`$alias_maps`). The wrapper takes the mode from `${user}` (the localpart, e.g.
`reflector-both`) and the envelope sender from `${sender}` (pipe(8) does not
export `$SENDER`). Only `reflector-bounces` remains an alias (the bounce mbox).

**Code:** `Mail::DKIM2::Reflector` (in this repo, installed system-wide with the
other libs) + wrapper `perl/bin/dkim2-reflector.pl` deployed to
`/usr/local/bin/dkim2-reflect`. Signs `dkim2.com` / `sel1` / `rsa-sha256` with
`/etc/dkim2/keys/dkim2.com/sel1.key`.

**Signing-key access:** the pipe transport runs the reflector as `nobody:nogroup`
(`user=nobody:nogroup`), and like `local(8)` it sets only the primary uid/gid —
it does **not** apply supplementary groups, so adding `nobody` to a group cannot
grant key access. The main signing key tree is `dkim2:postfix` `drwxr-x---` / `-rw-r-----`,
unreadable by `nobody`. So the reflector uses a dedicated copy owned by `nobody`:
```bash
install -d -m 755 -o root -g root /etc/dkim2/reflector
install -m 600 -o nobody -g nogroup /etc/dkim2/keys/dkim2.com/sel1.key \
    /etc/dkim2/reflector/sel1.key
```
The wrapper signs with `/etc/dkim2/reflector/sel1.key` (same `dkim2.com`/`sel1`
key, just readable by uid `nobody`). Re-copy if the published `sel1` key rotates.
Without it the reflector logs `reflect failed: ... non-existing file` and
reflects nothing. The wrapper logs failures and a success line to syslog
(`LOG_MAIL`, tag `dkim2-reflector`) and dumps a failing message to
`/var/tmp/dkim2-reflector-lasterror.eml`.

**No-milter injector:** the wrapper submits the finished (already-signed) reply
over SMTP to `127.0.0.1:10588`, a `master.cf` service with `smtpd_milters=` and
`non_smtpd_milters=` emptied, so the outbound milter does **not** re-sign it.

**DKIM1 bridge (inbound verification):** the reflector also signs a message that
has **no DKIM2 chain** but a valid classic-DKIM (DKIM1) signature aligned
(relaxed) with its `From:` domain. It learns the DKIM1 result by reading an
`Authentication-Results` header, trusting only those whose authserv-id is
`mail.dkim2.com` (passed by `dkim2-reflect`). That header is produced by
OpenDKIM, which must verify inbound mail:
- `/etc/opendkim.conf`: set `Mode sv` (was `s` — sign only) and add
  `AuthservID mail.dkim2.com`. OpenDKIM signs for internal hosts and verifies
  for external ones, so the same instance covers both directions.
- A-R trust boundary: OpenDKIM prepends its genuine `Authentication-Results`
  on top of the message, so the reflector trusts only the **topmost** A-R
  bearing our authserv-id and ignores any sender-supplied copy below it
  (`_dkim1_aligned`). This is a test host with no reputation, so it is a
  correctness nicety rather than a security boundary; we do **not** strip
  inbound A-R at the MTA. (OpenDKIM has no `RemoveOldAuthenticationResults`
  directive — do not add one; it fails the config check.)
- `/etc/postfix/main.cf`: add the OpenDKIM socket to `smtpd_milters` (it is
  already in `non_smtpd_milters` for outbound signing), e.g.
  `smtpd_milters = unix:var/run/dkim2-milter-in.sock, inet:localhost:8891`.
  `milter_default_action = accept` ensures inbound mail still flows if OpenDKIM
  is unavailable.
- Reload after changes: `systemctl reload opendkim postfix`.
- Keep the authserv-id in `opendkim.conf` and in `dkim2-reflect`
  (`authserv_id => 'mail.dkim2.com'`) in sync.

**Deploy / update:**
```bash
ssh dkim2 'cd /root/interop && git pull && \
    cd perl && perl Makefile.PL && make && make install && \
    install -m 755 bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect'
# aliases (once):
ssh dkim2 'cat /root/interop/deploy/reflector-aliases >> /etc/aliases && newaliases'
# injector service (once): add the 127.0.0.1:10588 block to /etc/postfix/master.cf
#   with smtpd_milters= and non_smtpd_milters= emptied, then: systemctl reload postfix
```

---

### 7. DKIM2 Validator (web form)

**Role:** A web page at `https://dkim2.com/validate/` to paste an email and get
a per-level breakdown — each DKIM2-Signature and each Message-Instance (with
undo). Two-column: paste left, results right.

**Components:**
- **Page:** static `index.html` + `validate.css` + `validate.js` under
  `/var/www/dkim2.com/validate/` (source in `deploy/www/validate/`). Vanilla JS
  POSTs the pasted message to the API and renders the JSON.
- **API:** `POST /validate/api` (raw `text/plain` → JSON). nginx routes it via
  **fcgiwrap** to the CGI `/usr/local/bin/dkim2-validate.cgi` (source
  `perl/bin/validate.cgi`), which calls `Mail::DKIM2::Validate::report`.
- **Reporter:** `Mail::DKIM2::Validate` (installed with the other libs).
- **DNS:** the CGI validates against **live DNS only** — exactly like the milter
  and any real-world verifier — so a broken/stale key record is surfaced, not
  masked (and the result matches the client-side `/verify/` tool). The interop
  test domains (`test{1..5}.dkim2.com`) are published in real DNS. A `dns.json`
  override exists **only for offline testing** (`t/validate-cgi.t` sets
  `DKIM2_DNS_JSON`); it is deliberately NOT configured in production nginx, and
  `validate.cgi` does not default it. Do not add it back to the vhost.

**nginx** (`/etc/nginx/sites-available/dkim2.com`, the 443 `default_server`):
```
location = /validate/api {
    client_max_body_size 512k;
    include /etc/nginx/fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /usr/local/bin/dkim2-validate.cgi;
    fastcgi_pass unix:/run/fcgiwrap.socket;
    # NB: no DKIM2_DNS_JSON here — production uses live DNS (see above).
}
```
The static `/validate/` files are served by the existing `root` + `location /`.

**Deploy / update:**
```bash
ssh dkim2 'cd /root/interop && git pull && \
    cd perl && perl Makefile.PL && make && make install && \
    install -m 755 bin/validate.cgi /usr/local/bin/dkim2-validate.cgi && \
    install -m 644 ../deploy/www/validate/* /var/www/dkim2.com/validate/'
# one-time: apt-get install -y fcgiwrap; systemctl enable --now fcgiwrap.socket
```

---

### 8. DKIM2 Browser Verifier (static, no backend)

**Role:** A second web page at `https://dkim2.com/verify/`, sibling to
`/validate/` above, that verifies a pasted DKIM2 message **entirely
client-side** — parsing, canonicalization, hashing, and signature
cryptography all run in the browser (vanilla JS ES modules). Public keys are
fetched directly from the browser over DNS-over-HTTPS (`cloudflare-dns.com`);
the message body never leaves the browser and never touches this server.

**Components:**
- **Page:** static `index.html` + `verify.css` + `main.js` + the verifier
  modules (`parse.js`, `canon.js`, `recipes.js`, `crypto.js`, `b64.js`,
  `doh.js`, `report.js`) under `/var/www/dkim2.com/verify/` (source in
  `deploy/www/verify/`).
- **No CGI, no fastcgi, no backend process.** Unlike `/validate/api`, there
  is nothing for nginx to proxy and no `fcgiwrap` route to add — the page is
  pure static assets served the same way as `index.html`/`style.css`.
  `deploy/www/verify/tests/` is the local conformance-harness fixture tree
  used to validate the code against the Turscar vectors and is **not**
  deployed to the web root.
- **nginx:** no config change needed. The existing static `root` +
  `location /` on the `dkim2.com` vhost (the same one that already serves
  `/validate/`'s static files) covers `/verify/` automatically as soon as the
  files are installed under `/var/www/dkim2.com/verify/`.

**Deploy / update:** installed by `deploy/deploy.sh` (step 2b) alongside the
landing page and the validator's static assets — no separate command needed;
just run the standard deploy:
```bash
ssh dkim2 'cd /root/interop && git pull --ff-only && deploy/deploy.sh'
```

---

## Updating Code on the Server

### Library + milters + reflector + validator (Perl, this repo) — USE THE SCRIPT

Always deploy the Perl side with `deploy/deploy.sh`. Do **not** hand-run
`git pull && make && make install`: that has bitten us with **stale artifacts**
(e.g. a CLI rebuilt only with `make test` — which does NOT build the CLIs — or a
`blib/` that retained a removed module). The script does a clean rebuild, gates
on `make test`, installs the lib + reflector + validator + transport map,
restarts the milters, and runs a post-deploy **smoke test** (sign + verify
against live DNS) so a stale/broken deploy fails loudly.

```bash
ssh dkim2 'cd /root/interop && git pull --ff-only && deploy/deploy.sh'
```

If you only changed a `Mail::DKIM2::*` module, the script still does the right
thing — the milters are restarted (daemons), while the reflector wrapper and
validator CGI pick up the new lib per-invocation. The validator's
`Mail::DKIM2::Validate` report module is part of the lib, so it is covered by
`make install`; there is no separate validator build step.

Staleness rule of thumb: any change under `perl/lib/` or `perl/bin/` ⇒ run
`deploy/deploy.sh` (never a partial manual install). For the C reference tree,
`make test` does not build the CLIs — use `make check` (or `make tools`).

### DKIM2 milter — manual fallback (only if the script is unavailable)
```bash
ssh dkim2 'cd /root/interop && git pull && cd perl && \
    make clean && perl Makefile.PL && make && make test && make install && \
    systemctl restart dkim2-milter-inbound dkim2-milter-outbound'
```

### Mailman handlers (Python, brong/mailman repo)

From your local `~/src/mailman` working directory:
```bash
DEST=root@dkim2.com:/opt/mailman/venv/lib/python3.13/site-packages/mailman
rsync -av src/mailman/handlers/message_instance.py $DEST/handlers/
rsync -av src/mailman/mta/message_instance.py $DEST/mta/
ssh dkim2 systemctl restart mailman3 mailman-web
```

If the database model changed (new Alembic migration):
```bash
ssh dkim2 'MAILMAN_CONFIG_FILE=/etc/mailman3/mailman.cfg \
    /opt/mailman/venv/bin/alembic \
    -c /opt/mailman/venv/lib/python3.13/site-packages/mailman/config/alembic.cfg \
    upgrade head'
```

### Sympa Message.pm (Perl, brong/sympa repo)

From your local `~/src/sympa` working directory:
```bash
scp src/lib/Sympa/Message.pm \
    root@dkim2.com:/usr/share/sympa/lib/Sympa/Message.pm
ssh dkim2 systemctl restart sympa sympa-bulk sympa-archived sympa-bounced
```

---

## Server configuration snapshot (`deploy/config/`)

`deploy/` covers the DKIM2 mail path, but until 2026-07-29 the nginx vhosts, both
list managers' configuration, the live Postfix state and
`/usr/local/bin/sympa-sendmail` existed **only** in `/etc` on the box —
recoverable after a loss only by re-deriving them from this document. They are
now tracked:

```
deploy/config/nginx/{dkim2.com,mail.dkim2.com,mailman.dkim2.com,sympa.dkim2.com}
deploy/config/mailman3/{mailman.cfg,mailman-hyperkitty.cfg,web-settings.py}
deploy/config/sympa/{sympa.conf,aliases}
deploy/config/postfix/{main.cf.live,master.cf.live}
deploy/config/aliases
deploy/sympa-sendmail
```

`postfix/main.cf.live` is `postconf -n` output, which records the real
`transport_maps` and `local_recipient_maps` — both several maps deep, and both
deliberately omitted from `deploy/postfix-main.cf.patch` because `main.cf` takes
only one value per setting.

**Refresh the snapshot** (run locally; fetches over ssh):
```bash
deploy/capture-server-config.sh            # default host: dkim2
git diff deploy/                           # review, then commit
```

**Drift** between live and tracked is reported by `deploy/check-server-config.sh`,
which `deploy.sh` runs last. It is a **warning, not a gate**: a stale snapshot
must be visible on every deploy, but must never block shipping a signing fix.

### Secrets

This repo is **public**. `deploy/capture-server-config.sh` replaces credentials
with placeholders on the way in, keyed on the setting *name* so rotating a value
on the box cannot silently defeat the redaction, and aborts if any survives.

| File | Setting | Placeholder |
|---|---|---|
| `mailman3/mailman.cfg` | `admin_pass` | `__MAILMAN_REST_PASS__` |
| `mailman3/mailman-hyperkitty.cfg` | `api_key` | `__HYPERKITTY_API_KEY__` |
| `mailman3/web-settings.py` | `SECRET_KEY` | `__DJANGO_SECRET_KEY__` |
| `mailman3/web-settings.py` | `MAILMAN_REST_API_PASS` | `__MAILMAN_REST_PASS__` |
| `mailman3/web-settings.py` | `MAILMAN_ARCHIVER_KEY` | `__HYPERKITTY_API_KEY__` |

Each Mailman secret appears under **two** names — once in the Mailman
core/archiver config and once on the Django side — and both must be redacted or
the value is still published by the file that was missed.

`sympa.conf` (SQLite, no password), the nginx vhosts (certificate *paths*, not
keys) and the Postfix state contain no credentials and are captured verbatim.
**Check any file you add here for secrets before committing.**

### Restoring after a loss

Not a script — rebuilding also means installing Postfix, nginx, Mailman 3 and
Sympa, which no captured config replaces. Follow "Software Components" above for
the packages and one-time setup, then:

1. `install -m644 deploy/config/nginx/* /etc/nginx/sites-available/` and symlink
   the four into `sites-enabled/`.
2. `install` the Mailman and Sympa configs to `/etc/mailman3/` (rename
   `web-settings.py` → `web/settings.py`) and `/etc/sympa/sympa/`.
3. Substitute the placeholders. The two Mailman secrets must match between the
   Mailman core config and the Django settings, or HyperKitty archiving and the
   web UI fail to talk to the REST API. Generate the Django key with
   `openssl rand -hex 32` and paste the **result** — check that the value in
   `settings.py` is 64 hex characters, not the command that generates them.
4. `install -m644 deploy/config/aliases /etc/aliases && newaliases`;
   `postalias /etc/sympa/sympa/aliases`.
5. Restore `master.cf` from `deploy/config/postfix/master.cf.live`, apply
   `main.cf.live` with `postconf -e`, then `postfix check`.
6. `install -m755 deploy/sympa-sendmail /usr/local/bin/sympa-sendmail`.
7. `deploy/deploy.sh` for the library, milters, reflector, validator and web
   assets, then `deploy/check-server-config.sh` to confirm no drift.

---

## Quick Health Check
```bash
ssh dkim2 systemctl status dkim2-milter-inbound dkim2-milter-outbound \
    mailman3 mailman-web sympa postfix nginx
```

## Log Tailing
```bash
# DKIM2 milter
ssh dkim2 journalctl -fu dkim2-milter-inbound
ssh dkim2 journalctl -fu dkim2-milter-outbound

# Mailman
ssh dkim2 tail -f /var/log/mailman3/mailman.log /var/log/mailman3/dkim2.log

# Postfix
ssh dkim2 tail -f /var/log/mail.log

# Sympa
ssh dkim2 journalctl -fu sympa
```

## DKIM2 list smoke test (Mailman + Sympa, no-spam local capture)

Confirm both list managers stamp `draft-ietf-dkim-dkim2-spec-04` end-to-end and
produce chains that verify, **without emailing real subscribers**. Run on the box:

```bash
ssh dkim2 'cd /root/interop && deploy/dkim2-list-smoke.sh'
```

It injects a message (from the capture address) through each test list, captures
the outbound list-modified + milter-signed copy locally, and asserts `-04` +
`verify=pass` for each. Expected output: two `PASS` lines.

### One-time infra (already set up 2026-07-06)

- **Local capture** (byte-exact; mbox `>From ` escaping corrupts signed bytes, so
  use Maildir): `/etc/aliases`: `dkim2capture:  /var/spool/dkim2-capture/Maildir/`
  then `newaliases`. `dkim2.com` is in `mydestination`, so `dkim2capture@dkim2.com`
  delivers to that local Maildir.
- **Mailman list** `dkim2test@mailman.dkim2.com`, sole member `dkim2capture@`, via
  the REST API (`localhost:8001`, `restadmin:dkim2demo`): create with style
  `legacy-default`; set `subject_prefix`, `default_member_action=accept`,
  `advertised=false`; subscribe `dkim2capture@` pre-verified/confirmed/approved.
  **Gotcha:** after creating a Mailman list you MUST run
  `mailman --run-as-root aliases && postfix reload`, or Postfix rejects it
  ("User unknown in local recipient table").
- **Sympa list** `dkim2test@sympa.dkim2.com`, sole member `dkim2capture@`.
  Create XML (`discussion_list`), then `sympa create --input-file=X.xml sympa.dkim2.com`.
  Three gotchas (all resolved):
  1. `<topic>` is REQUIRED by the template and must exist in the RUNTIME
     `/etc/sympa/topics.conf` — use `computers` (`computing` is only in the
     *default* topics.conf → opaque `create_list [intern]`).
  2. The robot dir `/var/lib/sympa/list_data/sympa.dkim2.com/` was `root:root`
     (install anomaly), so the `sympa` user couldn't create the list —
     `chown sympa:sympa` it (non-recursive).
  3. `sympa create`'s alias hook can't rebuild the map as non-root. Append the
     six list aliases to `/etc/sympa/sympa/aliases` (mirror the `test:` lines),
     rebuild with **`postalias`** (NOT `postmap` — the file is alias-format
     `key: value`; `postmap` mis-builds the `.db` → RCPT "User unknown in local
     recipient table"), then `postfix reload`. Finally
     `echo dkim2capture@dkim2.com | sympa add dkim2test@sympa.dkim2.com`.

### Two capture caveats (artifacts of reading mail back out of a mailbox — NOT signature bugs)

1. **`local $/` leak:** slurping the captured file with an unscoped `local $/`
   leaves `$/` undef, which breaks Net::DNS key lookups inside the verifier
   (query "times out"). Scope it: `my $raw = do { local $/; <$fh> };`. (Same
   class as the earlier delayed-bounce red herring.)
2. **CRLF→LF:** local MDA delivery rewrites line endings to bare LF, but the
   milter signed CRLF → body-hash mismatch. Normalise back to CRLF before
   verifying: `$raw =~ s/\r\n/\n/g; $raw =~ s/\n/\r\n/g;`.

Both are handled inside `deploy/dkim2-list-smoke.sh`.
