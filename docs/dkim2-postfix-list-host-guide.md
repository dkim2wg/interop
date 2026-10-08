# DKIM2 for a Postfix mailing-list host

- **Spec:** draft-ietf-dkim-dkim2-spec-06
- **Audience:** a Postfix operator who runs Mailman 3 or Sympa and wants list
  mail to verify as DKIM2 downstream
- **Status (2026-10-08):** the dkim2.com host runs this configuration: Ubuntu
  25.10, Postfix 3.10, Mailman from the `dkim2` fork branch, Sympa 6.2.78
  built from the patched source (the always-wrap series in step 8, with
  `dkim2_message_instance on` for the test lists), Mail::DKIM2 0.15, the
  standalone milter. The authentication_milter path
  has not been tested end to end.

This guide builds the host in order. Each step ends with a check you can
run. For what DKIM2 is and why, read the [operator
guide](dkim2-operator-guide.md) first; this document assumes it.

---

## 1. What you get

A list host does three DKIM2 jobs. It verifies the chain on mail it
receives. Its list manager records every change it makes to a message in a
`Message-Instance` header, with a Recipe that lets a verifier undo the
change. And it signs every copy it sends, with a `DKIM2-Signature` that
covers the Message-Instance and every signature that came before.

```
  Internet ──▶ Postfix :25 ──▶ inbound milter ──▶ Postfix ──▶ list manager
                                verify chain                    (Mailman / Sympa)
                                Authentication-Results          changes the message
                                Message-Instance m=1            Message-Instance m=2 + Recipe
                                snapshot                              │
                                                                      ▼
  recipients ◀── Postfix ◀── outbound milter ◀── Postfix 127.0.0.1:10587 ◀─┘
                              DKIM2-Signature i=N            one recipient per transaction
```

A receiving verifier that gets `dkim2=pass` on a list copy knows which hops
handled the message, that each change was declared by the hop that made
it, and that the envelope at each hop matched the one before. It does not
know that the message is wanted, that it is not spam, or that a declared
change was benign. DKIM2 is evidence of custody, not of content.

## 2. Prerequisites

- Debian 12 or Ubuntu 22.04 or later, with Postfix 3.x (the distribution
  package has milter support) and root access.
- Perl 5.20 or later, `cpanminus`, and a compiler for CryptX:
  `apt-get install build-essential libssl-dev cpanminus`.
- DNS control for the list domain, to publish the public key.
- One of: Mailman 3 installed in a virtualenv from upstream master, or
  Sympa 6.2.78 (source build or distribution package of that version).
- A clone of the interop repository, for the templates and patch series:
  `git clone https://github.com/dkim2wg/interop`.

## 3. Keys and DNS

DKIM2 publishes keys as DKIM TXT records; nothing new is needed in DNS.
Generate keys as described in the operator guide's [Generating
keys](dkim2-operator-guide.md#generating-keys) section, then lay them out
the way both milters read them:

```
/etc/dkim2/keys/
    lists.example.org/
        sel1.key          # the selector is the file name
```

The milter runs as a `dkim2` user in the `postfix` group (created here;
step 5 uses it), and the keys are readable by that user only:

```bash
groupadd -r dkim2 2>/dev/null; useradd -r -U -G postfix -s /usr/sbin/nologin dkim2
install -d -m 750 -o dkim2 -g postfix /etc/dkim2/keys/lists.example.org
openssl genpkey -algorithm ed25519 -out /etc/dkim2/keys/lists.example.org/sel1.key
chown dkim2:postfix /etc/dkim2/keys/lists.example.org/sel1.key
chmod 640 /etc/dkim2/keys/lists.example.org/sel1.key
openssl pkey -in /etc/dkim2/keys/lists.example.org/sel1.key -pubout -outform DER | tail -c 32 | base64
```

Publish the output:

```
sel1._domainkey.lists.example.org. IN TXT "v=DKIM1; k=ed25519; p=<output>"
```

The signing domain is the directory name. The milter signs for the envelope sender's domain,
walking up parent domains until it finds a key directory, so one key for
`lists.example.org` also signs `bounces.lists.example.org`.

Check: `dig +short TXT sel1._domainkey.lists.example.org` returns the record.

## 4. Install Mail::DKIM2

The Perl distribution carries the library, both milters and the
command-line tools.

Mail::DKIM2 is on CPAN:

```bash
cpanm Mail::DKIM2
cpanm Sendmail::PMilter        # for the standalone milter (step 5a)
```

This installs `dkim2sign`, `dkim2verify`, `dkim2-milter` and
`dkim2-split-lmtp` into `/usr/local/bin`, and the `Mail::DKIM2` modules
plus the `Mail::Milter::Authentication::Handler::DKIM2Sign` and
`DKIM2Verify` handlers for step 5b. Sendmail::PMilter is a recommended
dependency rather than a required one, which is why `cpanm Mail::DKIM2`
does not pull it in. To install from the repository instead (for a change
not yet released), `cpanm .` in `perl/`. The repository checkout is still
needed for the templates and patch series in the steps below.

Check: `dkim2verify --help` prints usage. If you have any DKIM2-signed
message to hand (mail from a dkim2.com reflector, step 9, is one), `dkim2verify
message.eml` prints its verdict.

## 5. The milter

Two paths, each complete on its own. Choose one.

### 5a. The standalone `dkim2-milter`

One program, run twice: an inbound instance that verifies, adds
`Authentication-Results`, stamps `m=1` and keeps a snapshot; an outbound
instance that computes the Recipe against the snapshot and signs.

The sockets live inside the Postfix chroot, in a directory the
distribution's Postfix does not create; the units create it (and the
snapshot directory) with the right owner before dropping privileges, and
this creates it now so the first start is clean:

```bash
install -d -m 750 -o dkim2 -g postfix /var/spool/postfix/var/run
install -d -m 750 -o dkim2 -g postfix /var/spool/dkim2/snapshots
cp interop/deploy/examples/dkim2-milter-inbound.service \
   interop/deploy/examples/dkim2-milter-outbound.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dkim2-milter-inbound dkim2-milter-outbound
```

The units are `deploy/examples/dkim2-milter-inbound.service` and
`deploy/examples/dkim2-milter-outbound.service`. The sockets are
`/var/spool/postfix/var/run/dkim2-milter-in.sock` and `-out.sock`, which
Postfix sees as `unix:var/run/dkim2-milter-in.sock` and `-out.sock`. The
outbound unit reads `/etc/dkim2/keys`; a key directory it cannot read is
skipped with a log line, and the next domain up is tried. `dkim2-milter --help` lists the
options; `--mode both` on one socket is also possible
(`deploy/examples/dkim2-milter.service`) but gives Postfix no way to keep
the inbound stamp off the list's own copies, so the two-instance layout is
what this guide wires up.

**Null body Recipes.** A list that rewrites a body (content filtering, DMARC
wrap) records a null body Recipe in its Message-Instance: the previous body is
gone. The list manager adds that instance unsigned, for the outbound milter
to sign, and `dkim2-milter` does not sign an unsigned null top unless started
with `--allow-null-body-recipe`, which is off by default in the program. The
outbound example unit turns it on, since it is for list hosts. With it on, the
message is still signed only if the upstream signatures verify and the header
history below the null Recipe checks out; the milter adds
`X-DKIM2-Info: action=null-body-recipe;` when it signs one.

The option is only for the host that introduces the null. A null top that
arrives already signed — a list post the list host signed, now relayed
unchanged by a forwarder such as a mailbox provider — is signed without it,
since a DKIM2-Signature with that instance's `m=` already vouches for it. The
milter adds the same informational `action=null-body-recipe` tag then too.

**Null senders.** `dkim2-milter` requires Sendmail::PMilter 1.28 or later
and refuses to start with an older one. 1.27 never answered a `MAIL
FROM:<>` command, so Postfix waited out `milter_command_timeout` (30
seconds) and every bounce went out unsigned. `cpanm Sendmail::PMilter`
installs the current release. To check a running milter answers a null
sender:

```bash
perl interop/deploy/smoke-null-sender-milter.pl /var/spool/postfix/var/run/dkim2-milter-out.sock
```

(`deploy/smoke-null-sender-milter.pl` speaks enough of the milter protocol
to send one null-sender envelope and fails within about eight seconds if
the milter does not answer.)

Check: `systemctl status dkim2-milter-inbound dkim2-milter-outbound` shows
both active, and `journalctl -u dkim2-milter-outbound -n 5` shows
`signing enabled via keydir /etc/dkim2/keys`.

### 5b. authentication_milter with the DKIM2 handlers

If you run (or want) Mail::Milter::Authentication for SPF, DKIM and DMARC,
the two DKIM2 handlers go into it instead. We have not tested this path end
to end; the dkim2.com host runs 5a. What follows is what the handlers' code
and configuration say.

Run two instances, as in 5a: one that verifies, on the socket port 25 uses,
and one that only signs, on the socket the list listener and
`non_smtpd_milters` use. Each has its own configuration file and socket.

```bash
cpanm Mail::Milter::Authentication
install -d -m 750 -o nobody -g nogroup /var/spool/dkim2/snapshots
chgrp nogroup /etc/dkim2/keys/lists.example.org /etc/dkim2/keys/lists.example.org/sel1.key
```

(`nobody` is authentication_milter's default `runas` user; use yours.)
`deploy/examples/authentication_milter.json.fragment` holds both handler
blocks: put `DKIM2Verify` in the inbound instance's `"handlers"` object and
`DKIM2Sign` in the outbound one's, with your domain and key path. The two
name the same `snapshot_directory`, which is how the signer finds the copy
the verifier kept. `sign_local` is what makes mail arriving on the loopback
list listener get signed; `sign_authenticated` covers SASL submission if
you have it.

One difference from 5a: `DKIM2Verify` stamps `m=1` only on mail whose
chain verified, so an unsigned post gets its `m=1` from the list manager
instead. The subscriber sees the same result.

Check: both instances are active, and a message through port 25 produces
an `Authentication-Results` line with `dkim2=`.

## 6. Postfix

Apply `deploy/examples/postfix-main.cf.fragment` with `postconf -e` for each
line, or paste it into `main.cf`:

```
smtpd_milters = unix:var/run/dkim2-milter-in.sock
non_smtpd_milters = unix:var/run/dkim2-milter-out.sock
milter_default_action = accept
milter_protocol = 6
internal_mail_filter_classes = bounce
disable_mime_output_conversion = yes
```

If `main.cf` already lists milters (OpenDKIM, rspamd), append them after
the DKIM2 sockets rather than replacing them, for instance
`smtpd_milters = unix:var/run/dkim2-milter-in.sock, inet:localhost:8891`;
the DKIM2 signer goes before a DKIM signer so its headers exist when the
DKIM signature is made. Do the same on the list listener below.

In turn: port 25 mail goes through the inbound milter; mail Postfix
generates itself, which is bounces, goes through the outbound milter so
bounces are signed; if a milter is down, mail flows unsigned rather than
stopping; protocol 6 carries the macros the milters need; bounces are
filtered at all (Postfix does not by default); and a body that was signed
as 8bit is never downgraded to 7bit on the way to a server without
8BITMIME, because that rewrites `Content-Transfer-Encoding` after signing
and the body hash no longer matches.

Append `deploy/examples/postfix-master.cf.fragment` to `master.cf`. Its
first listener is the one every list copy will be submitted to:

```
127.0.0.1:10587 inet n  -       y       -       -       smtpd
  -o syslog_name=postfix/dkim2-list
  -o cleanup_service_name=cleanup-dkim2
  -o local_header_rewrite_clients=
  -o smtpd_milters=unix:var/run/dkim2-milter-out.sock
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
```

Only the signing milter runs here. If the inbound milter ran too, the
list's copy would get an `Authentication-Results` and a second
`Message-Instance` before being signed, and the Recipe the list wrote
would no longer describe the message.

`local_header_rewrite_clients=` (empty) matters for the same reason. The
list manager submits from this host, and for local clients Postfix
rewrites addresses in headers (quoting an odd local part, appending your
domain to an unqualified one) and adds missing `Resent-From`,
`Resent-Date` and `Resent-Message-ID` when a message has any `Resent-`
field. All of that happens after the list recorded its
`Message-Instance`, so the signer finds the instance no longer matches and
refuses to sign. The list has already produced the headers it means to
send; Postfix should leave them alone.

### Keep Bcc, Resent-Bcc and Content-Length on mail you receive or forward

Since Postfix 3.0, `cleanup` removes `Bcc`, `Resent-Bcc`,
`Content-Length` and `Return-Path` from every message, before any milter
sees it (`message_drop_headers`). DKIM2 excludes `Return-Path` from the
header hash but hashes the other three. A signed message that carries
one of them, even an empty `Bcc:`, stops verifying at the first Postfix
that removes it, and the list's own signature can then no longer be
added.

Removing `Bcc` is right where a message is first submitted, and there it
happens before signing. On mail that arrives already signed, or that a
list or forwarder sends on, it is the sending side's job, not yours: do
not strip these headers on ingress, and do not strip them on the egress
of forwarded mail. The fragment's first entry is a second `cleanup`
service that drops only `Return-Path`:

```
cleanup-dkim2 unix n     -       y       -       0       cleanup
  -o message_drop_headers=return-path
```

Point every listener that receives mail or carries forwarded mail at it
with `-o cleanup_service_name=cleanup-dkim2`: the port 25 `smtp inet ...
smtpd` line already in your `master.cf` (add the option under it), the
`10587` list listener above (the fragment already has it), and the split
gateway's listeners if you use them. Leave submission (587) and the local
`sendmail` path on the default `cleanup`.

Then `postfix reload`, and check with
`postconf -P | grep -E 'cleanup_service_name|message_drop_headers'`.

Mailman removes `Bcc` and `Resent-Bcc` itself before sending (Python's
`smtplib` does it on its way to Postfix); with the patches below it does
so before computing its `Message-Instance`, so the removal is in the
Recipe and the chain still verifies. Sympa (with the patches below, on a
list with the switch on) does the same.

### Recipient privacy

A DKIM2-Signature records the RCPT TO of the transaction it was made in,
in its `rt=` tag, base64 but readable by anyone. A list manager that
hands Postfix a message with fifty recipients in one transaction gets one
signature naming all fifty, and every subscriber can read the whole list
from any copy. The fix is one recipient per transaction:

- Mailman: `max_recipients: 1` in `[mta]` (step 7).
- Sympa: `nrcpt 1` in `sympa.conf` (step 8).

Each copy is then its own transaction and its own signature, and the cost
is one extra SMTP transaction per recipient, which VERP-enabled lists
already pay.

If other software submits list-like mail to this host and cannot be set
that way, use the split gateway instead: the second, commented pair of
listeners in the fragment turns `10587` into an entry that hands every
message to `dkim2-split-lmtp` on `10590`, which groups the recipients
named in `To:`/`Cc:` into one copy and gives every other recipient a copy
of their own, re-injecting each to `10589` where the signing milter runs.
Install `deploy/examples/dkim2-split.service` and `systemctl enable --now
dkim2-split`. If the split daemon is down Postfix defers with a 451; mail
is delayed, never sent unsigned.

Check: `postfix check` is quiet; `ss -ltnp | grep 10587` shows the
listener.

## 7. Mailman 3

Mailman adds the `Message-Instance` headers; the milter signs. The
changes are three patches, described in `mailman/README.md`, carried on
three branches of <https://github.com/brong/mailman>: `dkim2-3.3.10` on
the current 3.3.10 release, `dkim2-3.3.8` on the 3.3.8 release that Debian
12 and Ubuntu 24.04 package, and `dkim2` on upstream master. Install the
one matching your Mailman. The 3.3.10 branch also carries two small
upstream fixes without which 3.3.10 does not install or decorate on Python
3.13, the default on Debian 13 and Ubuntu 25.04 and later; they are
harmless on older Pythons.

This assumes Mailman installed the upstream way, in a virtualenv. A
distribution `mailman3` package needs the series applied to the package
source instead; the README says what that involves.

Install into the Mailman virtualenv, either from the branch:

```bash
/opt/mailman/venv/bin/pip install 'git+https://github.com/brong/mailman@dkim2-3.3.10'
# or, on Mailman 3.3.8:
/opt/mailman/venv/bin/pip install 'git+https://github.com/brong/mailman@dkim2-3.3.8'
```

or by applying the matching series to a checkout of the release:

```bash
git clone https://gitlab.com/mailman/mailman.git && cd mailman
git checkout v3.3.10        # or: git checkout 3.3.8
git -c user.name=ops -c user.email=ops@example.org am /path/to/interop/mailman/patches-3.3.10/*.patch
                            # or: .../mailman/patches-3.3.8/*.patch
/opt/mailman/venv/bin/pip install .
```

(On upstream master, branch `dkim2` and `mailman/patches-master/` are the
same change; they are for following upstream, not for a list host.)

Stop Mailman, configure, then run any `mailman` command as the Mailman
user, which applies the pending migration for the per-list column, and
start it again. Comments in `mailman.cfg` go on their own lines: Mailman's
config parser keeps an inline comment as part of the value.

```bash
systemctl stop mailman3
```

```ini
[mta]
incoming: mailman.mta.postfix.LMTP
outgoing: mailman.mta.deliver.deliver
smtp_host: localhost
# The signing listener from step 6.
smtp_port: 10587
# Record the list's changes in Message-Instance headers.
message_instance: yes
# One recipient per transaction (step 6, "Recipient privacy").
max_recipients: 1
```

```bash
sudo -u mailman /opt/mailman/venv/bin/mailman -C /etc/mailman3/mailman.cfg info
systemctl start mailman3
```

You stay on 3.3.10 plus these three changes, so Postorius and HyperKitty
keep working.

What happens: the `message-instance-ingress` handler runs first in the
posting pipeline and records the message as it arrived (if the inbound
milter already stamped `m=1`, that is kept and used as the baseline). After
decoration, personalisation and ARC signing, the delivery mixin compares
the message with the baseline and, if anything changed, adds `m=2` with a
Recipe for the subject prefix, the list headers and the footer. Each
instance gets an `X-DKIM2-Info` line beside it saying what Mailman did.

On such a list a header or footer is always added by MIME-wrapping: the
body exactly as it arrived becomes the middle part of a `multipart/mixed`,
with the list header and footer as `text/plain` parts around it, so the
body Recipe is one copy range plus the added lines whatever the original
encoding. Subscribers see the footer as a separate part. A body Mailman
rewrites itself (content filtering, DMARC wrap) gets a null body Recipe;
see "Null body Recipes" above.

A list can opt out through the REST API:

```bash
curl -u restadmin:PASSWORD -X PATCH -H 'Content-Type: application/json' \
     http://localhost:8001/3.1/lists/LIST.DOMAIN/config \
     -d '{"dkim2_message_instance": false}'
```

The Message-Instance handlers log to the mailman3 journal
(`journalctl -u mailman3`). The baseline for each Recipe is pickled with the queued
message, only when Message-Instance support is enabled (and not for a list
that opts out); there is no cache directory (a `mi-cache/` left by an earlier
build can be deleted). Messages queued by this build cannot be unpickled
by a build without the DKIM2 wrap, so drain the queues before downgrading.

Check: post to a test list from an outside address and read the copy you
get back (step 9).

## 8. Sympa

Sympa 6.2.78 only. The changes are three patches, described in
`sympa/README.md`, exported from the `dkim2` branch of
<https://github.com/brong/sympa>. `Sympa::DKIM2` uses the Mail::DKIM2
library from step 4, 0.15 or later (from `perl/` until 0.15 is on CPAN),
to compute the headers. Nothing changes until a list has the
`dkim2_message_instance` switch on (below).

Either build from patched source:

```bash
git clone https://github.com/sympa-community/sympa.git && cd sympa
git checkout 6.2.78
git -c user.name=ops -c user.email=ops@example.org am /path/to/interop/sympa/patches-6.2.78/*.patch
autoreconf -i && ./configure && make && make install
```

(`./configure --enable-fhs` with the same prefix options as the install it
replaces; `sympa/README.md` has the line the dkim2.com host used to build
into the Debian package's layout, and the three extra Perl modules 6.2.78
needs.) Or overlay the patched files onto an installed 6.2.78; the file
list is in `sympa/README.md`. A distribution package of an older Sympa is
not a supported base.

Sympa submits outbound mail through a `sendmail` command. Install the
wrapper that submits to the signing listener instead:

```bash
install -m 755 interop/deploy/examples/sympa-sendmail /usr/local/bin/sympa-sendmail
```

(`deploy/examples/sympa-sendmail` speaks SMTP to `127.0.0.1:10587`; set
`DKIM2_SIGN_PORT` in the service environment to change the port.) Then in
`sympa.conf`:

```
sendmail /usr/local/bin/sympa-sendmail
nrcpt 1
```

```bash
systemctl restart sympa sympa-bulk sympa-archived sympa-bounced sympa-task_manager wwsympa
```

Then turn the switch on for each list that should record its changes, in
the list's `config` (or the list's web admin, with the other DKIM
parameters):

```
dkim2_message_instance on
```

The same line in `robot.conf` or `sympa.conf` makes it the default for a
robot or the whole site. It is off by default, and a list with it off
behaves exactly as stock 6.2.78.

What happens on a list with it on: `ProcessIncoming` records the message as
received (before S/MIME decryption) and keeps its header block in a
pseudo-header that travels with it through the spools. A header or footer
is added by MIME-wrapping: the body exactly as it arrived becomes the
middle part of a `multipart/mixed`, so the body Recipe is one copy range.
`ProcessOutgoing`, after all transformations and before DKIM signing, adds
the next `m=` to each copy. A body Sympa rewrites (txt, html, urlize and
notice reception modes, full-body personalisation, S/MIME) gets a null
body Recipe, so the outbound milter needs `--allow-null-body-recipe` (step
5, "Null body Recipes"; the example outbound unit has it). Anonymous lists
and archive resends drop the upstream chain, and the outbound milter
starts a new one. Sympa adds nothing to notifications, digests and direct
sends; the outbound milter gives them `m=1`.

Check: post to a test list and read the copy you get back (step 9).

## 9. Check it works

Post to a list from an address that is DKIM2-signed if you have one and
plain otherwise, and read the copy a subscriber receives:

```bash
grep -iE '^(X-DKIM2-Info|Message-Instance|DKIM2-Signature|Authentication-Results):' copy.eml
```

For a plain upstream you should see one `Authentication-Results` with
`dkim2=none` from the inbound milter, `Message-Instance` `m=1` (inbound
milter) and `m=2` (the list), and one `DKIM2-Signature` with `i=1`,
`m=2`, your domain in `d=` and one address in `rt=`. For a signed
upstream, `i=1` is the sender's, yours is `i=2`, and the
`Authentication-Results` says `dkim2=pass`.

Verify the copy yourself:

```bash
dkim2verify copy.eml
# pass (i=1..1 verified)        plain upstream: your signature only
# pass (i=1..2 verified)        signed upstream: theirs and yours
```

Paste it into <https://dkim2.com/validate/> for a per-hop breakdown with
each Recipe undone, and mail the list from, or forward a list copy to,
`reflector-both@dkim2.com`: the dkim2.com host verifies the chain with its
own implementation, adds a hop, and returns the message so you can see a
third-party verdict. The other reflector addresses are listed at
<https://dkim2.com/>.

A real test: subscribe an address at a provider that verifies DKIM2 and
confirm `dkim2=pass` in the `Authentication-Results` it adds.

## 10. Operations

**Key rotation.** Generate a new key under a new selector, publish its
TXT record, drop the file into the domain's key directory: the milter
uses the newest file and `dkim2-milter` needs a restart to notice a new
one. Keep the old record published for 14 days, the signature validity
window, then remove the old file and record.

**Snapshots.** The inbound milter keeps one snapshot per message it
stamped so the outbound milter can diff against it. Expire them:

```
# /etc/cron.d/dkim2-snapshot-cleanup
0 3 * * * root find /var/spool/dkim2/snapshots -type f -mtime +7 -delete
```

**Logs.** `journalctl -u dkim2-milter-inbound -u dkim2-milter-outbound`;
each message logs `verify ... result=`, `signed ... d= a= sel=` or `no
signing key for`. Mailman: the mailman3 journal (`journalctl -u mailman3`). Sympa logs through its usual `sympa.log`.

**Troubleshooting.**

| Symptom | Cause | Fix |
|---|---|---|
| Your own list copies fail with a header-hash mismatch, and the copy carries a `Delivered-To:` | Something signed inside a Postfix `local(8)` delivery (an alias `\|command`), which prepends `Delivered-To` after the hash was taken | Sign in a milter, or from a `pipe(8)` transport, never from an alias command |
| Copies to some hosts fail with a body-hash mismatch; `Content-Transfer-Encoding` differs from what you sent | Postfix converted 8bit to 7bit after signing | `disable_mime_output_conversion = yes` (step 6) |
| `dkim2=temperror` | A key lookup failed for a transient reason: timeout, SERVFAIL, refused | Retryable; check the resolver and the record |
| `dkim2=fail (... timestamp ...)` on old mail | Signatures are valid for 14 days from `t=` | Expected; verifiers may relax it locally |
| `permerror Message-Instance m=2 is not signed` | The list stamped `m=2` but no signature was added over it: the copy did not go through the signing listener | Point the list manager's submission at `127.0.0.1:10587` (steps 7 and 8) |
| Bounces go out unsigned; Postfix logs a 30 second milter timeout on `MAIL FROM:<>` | Sendmail::PMilter older than 1.28 | `cpanm Sendmail::PMilter`, restart the milters (step 5a) |
| Every subscriber's address visible in `rt=` | Many recipients per transaction | `max_recipients: 1` / `nrcpt 1`, or the split gateway (step 6) |

## 11. What this guide does not cover

The reflector addresses, the web validator, DSN propagation
(spec section 12) and the `test1`..`test5.dkim2.com` domains are the
dkim2.com demonstration machinery; `deploy/SERVER.md` describes that host.
The C, Go and Python implementations in the repository are for
interoperability testing and are not deployed on a list host.
