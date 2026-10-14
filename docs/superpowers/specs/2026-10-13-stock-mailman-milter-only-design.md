# DKIM2 for stock Mailman: milters and Postfix only

- **Date:** 2026-10-13
- **Asked by:** the mailop team: document a Postfix + Mailman 3 host where
  Mailman is unpatched and only chosen lists use DKIM2.
- **Spec:** draft-ietf-dkim-dkim2-spec-06

## Goal

A Postfix operator running stock Mailman 3 (3.3.8 or 3.3.10, no patches, no
plugin) can turn DKIM2 on for chosen lists. Subscribers see those lists
exactly as they do today, and every list copy verifies downstream with the
full upstream chain extended. Every list, domain and message not chosen
passes through untouched: no DKIM2 milter sees it.

## What stock Mailman does that matters

- `handlers/decorate.py` adds the header and footer three ways: inline into
  a single-part `text/plain` (decoding and re-encoding the body, often to
  base64), as extra parts of a `multipart/mixed`, and by MIME-wrapping
  anything else. The inline path rewrites the whole body, so a body Recipe
  becomes a null Recipe. The `multipart/mixed` path leaves the original
  parts byte-for-byte alone apart from Python's re-serialization (part
  header refolding and the like).
- Unknown headers, including `Message-Instance`, `DKIM2-Signature` and
  `Authentication-Results`, survive the posting pipeline (with the default
  `remove_dkim_headers: no`).
- All list mail leaves through one `[mta] smtp_host`/`smtp_port`.
  `max_recipients` is stock (default 10); `1` gives one transaction, and so
  one `rt=`, per subscriber.

So if every post reaches Mailman as `multipart/mixed`, stock decoration
produces a change the outbound milter can describe with a small, exact
Recipe.

## Design

### 1. Inbound: wrap at ingress (`dkim2-milter --wrap-single-part`)

New option, inbound mode only (startup error with `--mode outbound`, or
without `--snapshot-dir`).

In `cb_eom`, unchanged first: verify, add `Authentication-Results` and
`X-DKIM2-Info`, stamp `m=1` if the message has no `Message-Instance`, and
store the snapshot of the message as it arrived, keyed by its top instance.

Then, only if the snapshot was stored and the message is not `multipart/*`
(a missing `Content-Type` counts as single-part `text/plain`):

- Body becomes:

  ```
  --BOUNDARY
  <every Content-* field of the original, verbatim, in order, as folded>

  <original body, byte for byte>
  [CRLF, only if the original body did not end with one]
  --BOUNDARY--
  ```

  An original with no `Content-*` fields gives a part with no headers,
  which MIME reads as `text/plain; charset=us-ascii`, the same default.
- Outer headers: every `Content-*` field deleted; `Content-Type:
  multipart/mixed; boundary="BOUNDARY"` added; `MIME-Version: 1.0` added
  if absent.
- The boundary is random and checked not to occur in the body.
- The wrap adds no `Message-Instance` of its own. The top instance no
  longer matches the content, but the outbound milter diffs against the
  arrival snapshot and records the wrap and all of Mailman's changes in one
  instance, `m=k+1`. One instance per host, as with the patched build.
- An `X-DKIM2-Info: action=wrap-single-part;` line records the wrap.
- Registration adds `SMFIF_CHGHDRS` and `SMFIF_CHGBODY`.
- Fail closed: any error while wrapping leaves the message unwrapped (it
  still flows; its footer will be inline and its Recipe may be null).

The wrap itself is a pure function in the library (`Mail::DKIM2::Wrap`,
taking header fields and body, returning header edits and the new body) so
it is unit-tested without a milter. `X-DKIM2-Info` is excluded from the
hash, so where it sits never matters.

**authentication_milter:** `DKIM2Verify` gets the same option only if
Mail::Milter::Authentication lets a handler replace the body. If it does
not, the guide documents the stock-Mailman setup with `dkim2-milter` only
and says so.

### 2. Outbound: add nothing without a key

Independent of the above, and on for everyone: `dkim2-milter` in outbound
mode looks up the signing key first. With no key for the sender, it adds no
`Message-Instance`, no `X-DKIM2-Info` and stores no snapshot; it logs
`no signing key` and accepts. Today it adds an unsigned `Message-Instance`
before discovering there is no key, which a receiver then reports as
`permerror` ("m=N is not signed"). (`DKIM2Sign` already returns early with
no key; it is checked, not changed.)

### 3. Postfix routing: only chosen list traffic reaches a milter

Port 25 runs no DKIM2 milter.

**Inbound, per recipient.** A transport map listed before Mailman's own:

```
# main.cf
transport_maps = hash:/etc/postfix/dkim2-lists, hash:/var/lib/mailman3/data/postfix_lmtp

# /etc/postfix/dkim2-lists: one line per DKIM2 list posting address
dkim2-test@lists.example.org   smtp:[127.0.0.1]:10026
```

`master.cf` listener `127.0.0.1:10026`: `smtpd_milters` = inbound milter
socket, `content_filter=lmtp:[127.0.0.1]:8024` (Mailman's LMTP, every
message here goes to Mailman), `cleanup_service_name=cleanup-dkim2`,
`receive_override_options=no_address_mappings,no_unknown_recipient_checks,no_header_body_checks`,
loopback-only client restrictions, and a distinct `myhostname` so the
Postfix SMTP client does not refuse the hop as "loops back to myself".
Transport is chosen per recipient, so a co-recipient of a list post is
never wrapped or stamped.

**Outbound, per envelope sender.** Mailman submits to a loopback-only
listener `127.0.0.1:10025` with no milter. Its restrictions include
`check_sender_access pcre:/etc/postfix/dkim2-list-senders`:

```
/^dkim2-test(-bounces(\+.*)?)?@lists\.example\.org$/   FILTER smtp:[127.0.0.1]:10587
```

which sends a chosen list's mail to `127.0.0.1:10587`, the outbound-milter
listener (as in the existing guide, plus the distinct `myhostname`);
everything else from Mailman is delivered as it is today. With
`max_recipients: 1` each transaction is one copy of one list's mail, so the
per-message `FILTER` is exact. The sender map lives on the loopback
listener, never on port 25: on port 25 anyone could put a list's bounce
address in `MAIL FROM` and have us sign their mail.

Bounces Postfix itself generates for the list domain are not signed in this
setup (no `non_smtpd_milters`); the guide says so.

**Mailman (`mailman.cfg`, stock options only):**

```ini
[mta]
smtp_port: 10025
max_recipients: 1
```

### 4. The guide

`docs/dkim2-postfix-stock-mailman-guide.md`, for the mailop audience. It
refers to the existing list-host guide for keys, DNS and installing
Mail::DKIM2, and covers: why the wrap; the two milter units (inbound with
`--wrap-single-part` on the 10026 socket, outbound on 10587); the Postfix
maps and listeners; the two `mailman.cfg` lines; adding and removing a
list (one line in each map, `postmap`, reload); what subscribers see
(footer as its own part, as for HTML mail today); what it does not cover
(Postfix-generated bounces, content filtering lists get a null body Recipe
and need `--allow-null-body-recipe`, on in the example unit); checks. The
existing guide gets a pointer to it. `deploy/examples/` gets the map
templates, the master.cf fragment and the inbound unit variant.

## Testing

- `t/wrap.t`: the wrap function. Body copied byte for byte; original
  `Content-*` order and folding kept; no trailing CRLF; no `Content-*`
  fields; boundary collision; any `multipart/*` left alone; a
  `Content-Type` with a broken or missing boundary parameter left alone.
- `t/milter.t` (or a new milter test): `--wrap-single-part` wraps a
  single-part post, keeps the arrival snapshot, leaves multipart alone;
  startup errors for the bad option combinations; outbound with no key
  adds nothing.
- Stock decoration, real code: run stock Mailman 3.3.10's
  `decorate.process` (in a venv, a small Python driver with a stand-in
  list carrying a header and footer) over the inbound milter's output for
  the 88-message charset corpus, then the outbound milter, then every
  verifier in the repo. Bar: every message that the patched build passes
  also passes here, with a non-null body Recipe.
- Acceptance on dkim2.com: a new list with `dkim2_message_instance: false`
  (the patched Mailman then behaves exactly as stock), routed by the new
  maps and listeners. Post plain and DKIM2-signed mail, check
  `dkim2verify` and the reflectors; check a list not in the maps comes
  through with no DKIM2 headers at all.

## Release and deploy

Mail::DKIM2 0.20 (tarball for CPAN; Bron uploads). Deploy the milter and
the new routing for the test list on dkim2.com. hm's vendored copy is a
separate follow-up.

## Out of scope

Patched-Mailman and Sympa setups (unchanged), the C, Go and Python
implementations (interop tools, not deployed milters), signing
Postfix-generated bounces in this setup.
