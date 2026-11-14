# Mailman Message-Instance, light form — design

Date: 2026-11-13. Status: approved by Bron 2026-11-13.

## Intent

Mailman adds DKIM2 Message-Instance headers today (fork branches `dkim2`,
`dkim2-3.3.10`, `dkim2-3.3.8`) by keeping the octets every post arrived with
(`msg.original_bytes`), pickled through every queue, and diffing against them
at delivery. That roughly doubles queue files (1.8-2.0x) and is the main
thing upstream (Steve Turnbull) would object to.

The light form computes the same Message-Instances without keeping the
received message:

- **Body:** decoration only ever wraps (upstream branch
  `decorate-always-wrap`, setting `decorate_plain_text_in_place`), so the
  previous body sits intact inside the current one. The body Recipe comes
  from that structure, not from a diff against stored octets.
- **Headers:** Mailman's `Message` class keeps a change log: the first time
  code touches a header field name, it saves that name's values as they were.
  The header Recipe restores logged names; every other field is unchanged.
- **Hashes of the message as received:** the LMTP runner hashes the received
  octets on arrival and keeps only the two digests.

Cost target: queue files and per-message time within noise of stock Mailman
(no second copy, no quadratic diff). Pickled extra state is the change log
(only touched names, typically a few hundred bytes) plus 64 bytes of digests.

## Goals

- Message-Instances that verify downstream for every post the current series
  handles, with the exceptions listed under "Accepted losses".
- No `original_bytes`; no body line diff; no stored copy of the body.
- A series small and clear enough to send upstream after
  `decorate-always-wrap`.
- Replaces the existing 7-commit series on `dkim2`, `dkim2-3.3.10` and
  `dkim2-3.3.8`; production moves to it.

## Non-goals

- Signing. Mailman still doesn't sign; the host's DKIM2 milter does.
- Recovering bodies Mailman rewrote (content filtering, DMARC wrap): they
  get `"b": null`, as now.
- Any change to the stock-Mailman route (wrap milter + Postfix).

## Anti-goals

- A Message-Instance whose Recipe does not rebuild the previous instance.
  Every Recipe is checked before it is emitted (below).
- A null header Recipe. The spec has none; see "Header mismatch".
- Queue growth proportional to message size.

## Approaches considered

Header tracking (Bron chose 2):

1. *Snapshot at ingress* — copy all hashed header fields as received into
   msgdata, compare at delivery. Simple, catches changes from any code, but
   records state rather than changes.
2. **Change log in `Message` (chosen)** — record a field name's original
   values the first time it is touched. Precise and minimal; relies on every
   header mutation going through the class (see coverage below).

Branches (Bron chose): a new branch from upstream master, stacked on
`decorate-always-wrap`, written as the upstream series; once it passes the
charset corpus it replaces the three `dkim2*` branches. Alternative rejected:
keep the current series in production and treat this as a proposal only.

## Design

### 1. Header change log (`mailman/email/message.py`)

- `Message` gains a log: `{lower-case name: [original raw values in
  document order]}` (empty list = the name was absent). It exists only once
  started; `start_header_log()` starts it (idempotent: a running log is
  never reset).
- On the first mutation of a name, all current raw values of that name
  (`raw_items()` form, i.e. what the parser stored, not `Header`-decoded)
  are saved; later mutations of the name record nothing.
- Python's compat32 `email.message.Message` edits `_headers` directly in
  exactly six methods: `__setitem__`, `__delitem__`, `add_header`,
  `replace_header`, `set_boundary`, `set_raw`. Everything else (`set_param`,
  `del_param`, `set_type`, `set_charset`, `set_payload(..., charset)`) goes
  through those. Override all six. No Mailman code outside the class touches
  `_headers` today except the fork's `_prepend_header` (which adds the
  excluded Message-Instance / X-DKIM2-Info and must stay unlogged — give it
  a deliberate unlogged path).
- The parser fills headers through `set_raw`, so the log must start *after*
  parsing, never in `__init__`.
- The log is an ordinary instance attribute: pickled with the message
  through the queues, and carried by `copy.deepcopy` (personalised
  delivery). `__setstate__` must cope with messages pickled without it.
- Names excluded from the hash (spec §4 list plus `X-*`/`Received-*`) may be
  logged or skipped; skipping keeps the log small. Builder's call.

### 2. Ingress

- **LMTP runner:** right after parsing, compute the header and body digests
  of `envelope.content` exactly as the current `compute_header_hash_raw` /
  `compute_body_hash_raw` do, store them on the message (with the instance
  number found, see below), and start the header log — all before the
  Message-ID repair and `X-MailFrom` lines and before the message store's
  Message-ID-Hash stamp, so those are logged changes. Only when the site has
  `[mta] message_instance` on.
- **Other entry points** (`mailman inject`, internal paths, a queue entry
  from before the upgrade): the ingress handler finds no digests, computes
  them from the parsed message and starts the log there. Mailman's
  Message-ID-Hash stamp precedes this on the inject path; handle it as the
  current `_strip_stamped` does (hash without it, then log it as a change).
- **`message-instance-ingress` handler:** keeps today's decisions
  unchanged — digest skip; per-list `dkim2_message_instance` off → drop the
  digests and stop the log; unsigned post → drop unsigned sender/milter
  instances, snapshot version 0 (single `m=1` at egress, ruling 17);
  signed post → never modify its instances, snapshot version = highest
  `m=`. The arrival check (below) has already run; the handler only logs
  a warning when its status is a mismatch.
- **Arrival check (Bron, 2026-11-13):** a post that arrives with a
  Message-Instance is validated on the way in, in the LMTP runner while it
  still has the received octets: parse the highest `m=` instance and
  compare its `h=` and `b=` with the two digests just computed (no extra
  hashing). Record the outcome as an internal data item stored with the
  digests on the message — `none` (no instance), `match`, `mismatch`, or
  `malformed` (unparseable, duplicate `m=`) — so it travels through the
  queues. Messages from other entry points get the status computed against
  the parsed message at the ingress handler. Egress writes the status into
  the X-DKIM2-Info header beside the instance it adds (e.g.
  `arrival=match;`), so it is visible downstream and in archives without a
  new header. (Internal item rather than a header, and the X-DKIM2-Info
  tag, are my calls.) `msgdata['mi_snapshot']` keeps the same
  shape (version, header_hash, body_hash) so egress and retries work as now.

### 3. Decoration

On a list with Message-Instance on, `decorate` always wraps single-part
text/plain (as `decorate_plain_text_in_place = no`), whatever the site
setting. It records in msgdata what it did — the shape (wrapped, or
header/footer parts added to an existing multipart/mixed) and the boundary —
so egress can find the original body without searching. The fork's
received-octets splice (`_ReceivedPart`) goes away.

### 4. Egress (`message-instance-egress`, same place in Deliver/BulkDelivery)

Unchanged behaviour carried over: Bcc/Resent-Bcc removed so the Recipe
records it; exploded hint; retry guard (already stamped above the snapshot
version → nothing); originator `m=1` for virgin-pipeline mail; "nothing
changed → no instance" for signed posts; X-DKIM2-Info beside every instance;
hashes over the message as smtplib sends it (`_wire_bytes`).

New:

- **Header Recipe:** previous headers = current hashed fields, with each
  logged name's values replaced by its logged originals. Feed current and
  previous to the existing `compute_header_recipe` (per-name, small). Hash
  the previous headers; it must equal `mi_snapshot['header_hash']`.
- **Body Recipe:** from decorate's msgdata record, the line range of the
  original body in the wire body: the wrapped part's body, or the existing
  multipart/mixed body without the inserted header/footer parts (two copy
  ranges); with no decoration, the whole body. smtplib's generator turns
  body lines starting `From ` into `>From `; build the previous body by
  serialising that region's message object without mangling, align it line
  for line with the wire region (same line count), and emit copy ranges
  with literals only where lines differ. Hash the result; it must equal
  `mi_snapshot['body_hash']`.
- **Body mismatch** (Mailman rewrote the body — mime-delete, DMARC wrap —
  or a re-serialisation quirk in an old multipart post): `"b": null`.
  The `body-modified` msgdata flags are dropped; the hash check replaces
  them.
- **Header mismatch:** no null header Recipe exists. Log an error naming
  the logged names and the digests. Then, by snapshot version:
  - *Signed post (version >= 1):* add **no** Message-Instance. The outbound
    signing milter sees a change it cannot account for and sends that copy
    unsigned (current gate behaviour).
  - *Unsigned post (version 0):* still add `m=1`, with the header Recipe
    left out. The Recipe on a first instance is a MAY (-09 §12.1) and
    nothing verifies the state before `m=1`, so the copy can still be
    signed; only the record of what Mailman changed on arrival is lost.
    (My call: the alternative, no instance, would have the milter sign it
    as fresh mail without the list's record.)
  This should not occur if the six overrides cover everything; the
  full-pipeline test (below) guards it.

### 5. What goes away

`original_bytes` and its LMTP storage, `without_received_bytes` (archive /
NNTP), `_ReceivedPart` and the octet splice, the capped Myers body diff and
`message_instance_max_recipe_lines`, the `body-modified` flags in
`mime_delete.py` / `dmarc.py`. `DKIM2-MESSAGE-INSTANCE.md` is updated to
the new design and resource impact.

### 6. What stays

`[mta] message_instance` (site switch), per-list `dkim2_message_instance`
(and its migration), hashing / canonicalisation / folding / parsing code,
`compute_header_recipe`, X-DKIM2-Info, the -09 draft constants, the DMARC
From rewrite and "u" step.

## Switch-over

Queue entries already past ingress when the new code is deployed carry the
old state (`original_bytes`, no header log) and would all hit a header
mismatch. No legacy egress path: dkim2.com is the only site running the old
series (Bron). The deploy runbook stops Mailman's incoming side, lets the
out and retry queues drain, then installs; a missed entry costs one
unsigned copy.

## Accepted losses

- Multipart posts whose sub-part headers don't survive re-serialisation
  (trailing space dropped, refolded): body hash mismatch → `"b": null`.
  The current series rebuilt these from stored octets (3 of 88 in the
  charset corpus, all 2003-era). Report the count after the corpus run.
- A header mismatch drops the instance (and so the signature) for that copy.

## Testing

- Development on the new branch only, TDD there (see
  feedback_mailman_develop_on_master_backport). Keep the existing test
  modules' coverage where behaviour carries over; delete tests for removed
  machinery.
- Unit: each of the six overrides logs once with the right originals;
  stdlib paths (`set_param`, `set_charset`, `set_boundary`) logged; pickle
  and deepcopy carry the log; parser doesn't log.
- Full pipeline: a list with every header-changing feature on (subject
  prefix, reply-to munging, DMARC munge_from, avoid-duplicates, cleanse,
  rfc-2369, personalisation/VERP, decoration) — every copy's Recipe must
  rebuild the previous instance (undo via `mi_support.py`).
- `From ` mangling case; already-multipart/mixed case; inject path
  (Message-ID-Hash); retry of a stamped message; digest skipped.
- Box: Mailman suite once on the dev branch; charset corpus
  (`util/charset-corpus.sh`, Mailman lists) — expect 85/88 or better
  verify, report null-body count; queue file sizes vs stock (short run,
  per feedback_short_benchmarks). Then backport: 3.3.10 apply + one suite
  run; 3.3.8 cherry-pick only. Re-export patch series
  (`util/export-list-patches.sh --check`), deploy 3.3.10 to the box,
  prod smoke (`deploy/dkim2-list-smoke.sh`).

## Left to the builder

Commit split for the upstream series; names of the log API and msgdata
keys; whether excluded names are logged; how decorate's record is shaped;
whether `_strip_stamped` survives or the inject path is restructured.
