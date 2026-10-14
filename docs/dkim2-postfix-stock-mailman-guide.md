# DKIM2 for stock Mailman on Postfix

- **Spec:** draft-ietf-dkim-dkim2-spec-06
- **Audience:** a Postfix operator who runs Mailman 3 as released (3.3.8 or
  3.3.10, no patches, no plugins) and wants DKIM2 on some lists only
- **Status (2026-10-14):** built and tested against the program's own test
  suite; end-to-end acceptance on dkim2.com is in progress.

This guide turns DKIM2 on for chosen lists of a stock Mailman. Mailman is
not changed: two DKIM2 milters do all the DKIM2 work, and Postfix routes
only the chosen lists' mail through them. Every other list, domain and
message on the host is handled exactly as it is today.

If you can install a patched Mailman, the [Postfix mailing-list host
guide](dkim2-postfix-list-host-guide.md) is the other route: there Mailman
records its own changes. Read the [operator guide](dkim2-operator-guide.md)
for what DKIM2 is and why; this document assumes it.

---

## 1. What you get

```
  Internet ──▶ Postfix :25 (no DKIM2 milter)
                 ├─ post to a DKIM2 list ──▶ 127.0.0.1:10026 ──▶ wrap milter ──▶ Mailman LMTP
                 └─ everything else ───────▶ as today

  Mailman ──▶ 127.0.0.1:10025 (no milter)
                 ├─ a DKIM2 list's copy ──▶ FILTER ──▶ 127.0.0.1:10587 ──▶ signing milter ──▶ out
                 └─ everything else ───────────────────────────────────────────────────────▶ out
```

A post to a DKIM2 list arrives, and the **wrap milter**:

1. verifies any DKIM2 chain it carries and adds `Authentication-Results`;
2. stamps `Message-Instance` `m=1` if the post has none (a sender that
   does not sign DKIM2);
3. keeps a snapshot of the post exactly as it arrived;
4. if the post is a single part, wraps it (section 2) and records the wrap
   as the next `Message-Instance`, keeping a snapshot of the wrapped post.

Mailman then does what it always does: subject prefix, `List-*` headers,
footer. Each copy goes back to Postfix, and the **signing milter**
compares it with the wrapped snapshot, records Mailman's changes as one
more `Message-Instance`, and adds a `DKIM2-Signature` for your list
domain. A receiver that verifies DKIM2 can undo each step back to what the
sender signed.

A receiving verifier that gets `dkim2=pass` knows which hops handled the
message, that each change was declared by the hop that made it, and that
the envelope at each hop matched the one before. It does not know that the
message is wanted or that a declared change was benign.

## 2. Why the wrap

Mailman adds a list header or footer one of three ways:

- to a **single-part `text/plain`** post, by pasting it into the text. It
  decodes the body, adds the footer and encodes it again, often as base64.
  Every line of the body changes, and the only honest record of that is a
  "null" body Recipe: the original body cannot be recovered.
- to a **`multipart/mixed`** post, as an extra part. The original parts are
  untouched.
- to anything else (a text and HTML post, say), by wrapping it in a
  `multipart/mixed` itself.

So the wrap milter turns every single-part post into a `multipart/mixed`
with one part before Mailman sees it. The part carries the post's own
`Content-Type`, `Content-Transfer-Encoding` and other `Content-*` fields
and its body, byte for byte. Mailman then takes the second route and adds
its footer as a part of its own. Subscribers see the footer as a separate
part, as they already do for HTML mail. The Recipe for the list's changes
is a handful of lines plus "copy the body", whatever the post's charset or
encoding.

The wrap is its own `Message-Instance`, marked
`X-DKIM2-Info: ... action=wrap-single-part;`, and Mailman's changes are the
next one, so a post from a DKIM2-signing sender reaches subscribers with
three: `m=1` (the sender), `m=2` (the wrap), `m=3` (the list). Paste a copy
into <https://dkim2.com/validate/> to see each step undone on its own.

## 3. Keys, DNS and Mail::DKIM2

As in the list-host guide, [step 2 (prerequisites)](dkim2-postfix-list-host-guide.md#2-prerequisites),
[step 3 (keys and DNS)](dkim2-postfix-list-host-guide.md#3-keys-and-dns) and
[step 4 (install Mail::DKIM2)](dkim2-postfix-list-host-guide.md#4-install-maildkim2).
You need Mail::DKIM2 0.20 or later (the first with `--wrap-single-part`)
and Sendmail::PMilter 1.28 or later:

```bash
cpanm Mail::DKIM2 Sendmail::PMilter
```

The signing domain is the domain of the list's envelope sender
(`LIST-bounces@lists.example.org`), so the key goes in
`/etc/dkim2/keys/lists.example.org/`.

Check: `dkim2-milter --help` mentions `--wrap-single-part`.

## 4. The milters

Two units from `deploy/examples/`: `dkim2-milter-wrap.service` (inbound for
DKIM2 lists: verify, stamp, wrap) and `dkim2-milter-outbound.service`
(sign). Do not install `dkim2-milter-inbound.service`: in this setup port
25 runs no DKIM2 milter.

```bash
install -d -m 750 -o dkim2 -g postfix /var/spool/postfix/var/run
install -d -m 750 -o dkim2 -g postfix /var/spool/dkim2/snapshots
cp interop/deploy/examples/dkim2-milter-wrap.service \
   interop/deploy/examples/dkim2-milter-outbound.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dkim2-milter-wrap dkim2-milter-outbound
```

Both share `/var/spool/dkim2/snapshots`; that is how the signing milter
finds the wrapped post. The sockets are
`/var/spool/postfix/var/run/dkim2-milter-wrap.sock` and
`dkim2-milter-out.sock`, which Postfix (chrooted) sees as
`unix:var/run/dkim2-milter-wrap.sock` and `unix:var/run/dkim2-milter-out.sock`.

The outbound unit runs with `--allow-null-body-recipe`, for a list that
rewrites bodies itself (section 9). The signing milter adds nothing at all
to mail from a sender it has no key for.

Check: `journalctl -u dkim2-milter-wrap -n 5` shows `wrapping single-part
posts`; `journalctl -u dkim2-milter-outbound -n 5` shows `signing enabled
via keydir /etc/dkim2/keys`.

## 5. Postfix

### main.cf

From `deploy/examples/postfix-stock-mailman-main.cf.fragment`:

```
transport_maps = hash:/etc/postfix/dkim2-lists, hash:/var/lib/mailman3/data/postfix_lmtp
disable_mime_output_conversion = yes
```

`transport_maps` lists the DKIM2 list map first and then the map you have
now; keep your existing entries and their types (Mailman's map may be
`regexp:` on your host). `disable_mime_output_conversion` stops Postfix
converting an 8bit body to 7bit on its way to a server without 8BITMIME:
that rewrites `Content-Transfer-Encoding` after signing and breaks the
signature.

Leave `smtpd_milters` and `non_smtpd_milters` as they are: no DKIM2 milter
goes on port 25 or on locally submitted mail.

### The maps

`/etc/postfix/dkim2-lists` (from `deploy/examples/postfix-dkim2-lists`),
one line per DKIM2 list, its posting address:

```
dkim2-test@lists.example.org    smtp:[127.0.0.1]:10026
```

`/etc/postfix/dkim2-list-senders` (from
`deploy/examples/postfix-dkim2-list-senders`), one line per DKIM2 list,
matching the envelope senders Mailman uses for it: the list address, its
`-bounces` address, and the VERP form of that:

```
/^dkim2-test(-bounces(\+.*)?)?@lists\.example\.org$/    FILTER smtp:[127.0.0.1]:10587
```

```bash
postmap /etc/postfix/dkim2-lists
```

(The sender map is a `regexp:` table, built into every Postfix, and needs
no `postmap`.)

### master.cf

Append `deploy/examples/postfix-stock-mailman-master.cf.fragment`. It
defines `cleanup-dkim2` (skip it if you have it from the list-host guide)
and three loopback listeners:

- **10026, the wrap listener.** `transport_maps` sends the DKIM2 lists'
  posts here. Its milter is the wrap milter, and `content_filter` hands
  every message it accepts straight to Mailman's LMTP (`127.0.0.1:8024`,
  Mailman's default; use your `lmtp_host`/`lmtp_port`). Transport is chosen
  per recipient, so if a post is addressed to a DKIM2 list and to someone
  else on this host, only the list's copy comes through here.
- **10025, Mailman's submission listener.** No milter. Its
  `check_sender_access` sends a DKIM2 list's copies to the signer and lets
  everything else go out as it does today.
- **10587, the signer.** The signing milter, for the DKIM2 lists' copies
  only.

The sender map is on 10025 only, a listener nothing but this host can
reach. On port 25 it would let anyone put a list's bounce address in
`MAIL FROM` and have the host sign their mail.

The wrap listener and the signer each set their own `myhostname`. Each of
those hops is Postfix's SMTP client talking to Postfix's own smtpd, and
without a distinct name in the greeting the client refuses the delivery as
"mail for [127.0.0.1]:10026 loops back to myself".

The signer and the wrap listener use `cleanup-dkim2`, which keeps
`Bcc`, `Resent-Bcc` and `Content-Length` on mail that is signed (see the
list-host guide, "Keep Bcc, Resent-Bcc and Content-Length").

```bash
postfix check && postfix reload
```

Check: `postconf -M | grep -E '127.0.0.1:(10025|10026|10587)'` shows the
three listeners; `ss -ltn | grep -E ':(10025|10026|10587) '` shows them
listening.

## 6. Mailman

In `mailman.cfg`, two stock settings (comments on their own lines: Mailman's
config parser keeps an inline comment as part of the value):

```ini
[mta]
# The routing listener (section 5).
smtp_port: 10025
# One recipient per transaction.
max_recipients: 1
```

`max_recipients: 1` matters twice. A `DKIM2-Signature` records the
transaction's recipients in `rt=`, readable by anyone who gets a copy, so
with many recipients per transaction every subscriber could read the
roster. And the sender map routes whole transactions, which is only exact
when each one carries one list's copy to one subscriber.

```bash
systemctl restart mailman3
```

Nothing else changes in Mailman, and nothing is set per list: a list is a
DKIM2 list because it is in the two maps.

## 7. Adding and removing a list

To add `announce@lists.example.org`: one line in each map,

```
announce@lists.example.org    smtp:[127.0.0.1]:10026
/^announce(-bounces(\+.*)?)?@lists\.example\.org$/    FILTER smtp:[127.0.0.1]:10587
```

then `postmap /etc/postfix/dkim2-lists && postfix reload`. To remove it,
delete both lines and do the same. A list whose domain has no key in
`/etc/dkim2/keys` is wrapped but not signed; add the key first.

Keep every DKIM2 list in both maps. The signing milter can only record
Mailman's changes against a snapshot the wrap milter kept, so a list in
`dkim2-list-senders` alone gets its copies signed only when the post came
from a sender that does not sign DKIM2 (as a new message, `m=1`); a
DKIM2-signed post's copies would go out unsigned.

## 8. Check it works

Post to the list, from a DKIM2-signing address if you have one, and read
the copy a subscriber receives:

```bash
grep -iE '^(X-DKIM2-Info|Message-Instance|DKIM2-Signature|Authentication-Results):' copy.eml
```

From a plain sender: `Message-Instance` `m=1` (stamped on arrival), `m=2`
(the wrap, beside an `X-DKIM2-Info` with `action=wrap-single-part`), `m=3`
(the list), and one `DKIM2-Signature` with `i=1`, `m=3` and your domain in
`d=`. From a DKIM2-signing sender: the sender's `m=1` and `i=1`, then
`m=2`, `m=3` and your `i=2`.

```bash
dkim2verify copy.eml
# pass (i=1..1 verified)        plain sender
# pass (i=1..2 verified)        DKIM2-signing sender
```

The footer is its own MIME part. Paste the copy into
<https://dkim2.com/validate/> for each hop undone in turn, or mail the list
from, or forward a copy to, `reflector-both@dkim2.com` for a third-party
verdict (the other reflector addresses are listed at <https://dkim2.com/>).

Then post to a list that is not in the maps: its copies carry no
`Message-Instance`, `DKIM2-Signature` or DKIM2 `X-DKIM2-Info` at all.

## 9. Limits and troubleshooting

- **Postfix's own bounces** for the list domain are not signed in this
  setup (no `non_smtpd_milters`). The list-host guide's
  `internal_mail_filter_classes = bounce` setup signs them, at the cost of
  running the signing milter on all locally generated mail.
- **Content filtering.** A list that strips attachments or converts HTML
  rewrites the body, and the list's instance then has a null body Recipe.
  The outbound unit's `--allow-null-body-recipe` signs it; a receiver can
  verify the chain up to the list but not undo the body change.
- **A post whose DKIM2 chain is already broken** when it arrives is not
  wrapped (`not wrapping ...: no arrival snapshot` in the wrap milter's
  log). It is still delivered; its footer is pasted inline, and its copies
  are not signed.

| Symptom | Cause | Fix |
|---|---|---|
| `loops back to myself` in the mail log | A loopback listener greets with your own `myhostname` | Keep the `-o myhostname=` lines on 10026 and 10587 |
| A DKIM2 list's copies go out unsigned; `no signing key for` in `journalctl -u dkim2-milter-outbound` | No key directory for the envelope sender's domain | Add `/etc/dkim2/keys/<domain>/<selector>.key` and restart the milter |
| A DKIM2 list's copies have no `Message-Instance` at all | The copy did not go through 10587 | Check `smtp_port: 10025` and the sender map's pattern for that list |
| Posts reach Mailman without the wrap | The post did not go through 10026 | Check `dkim2-lists`, `postmap`, and that it comes first in `transport_maps` |
| Copies fail with a body-hash mismatch at some hosts | 8bit converted to 7bit after signing | `disable_mime_output_conversion = yes` |
| Every subscriber's address in `rt=` | Many recipients per transaction | `max_recipients: 1` |
