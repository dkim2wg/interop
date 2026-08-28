# DKIM2 §11.9 replay check — design

**Spec:** draft-ietf-dkim-dkim2-spec-06 §11.9 "Check for unexpected replay"
**Date:** 2026-08-28
**Status:** approved design, pending implementation plan

## What the spec asks for

draft-06 adds §11.9, the first rule in DKIM2 that requires a Verifier to
remember anything between messages:

> If a Verifier receives multiple copies of the same message and there is no
> indication that the message has been exploded then all of the messages
> SHOULD be rejected. Although, as [RFC1047] explains this could be a protocol
> level issue, these are rare on today's Internet -- it is most likely that a
> malicious replay attack has been detected.
>
> The hash values from the m=1 Message-Instance header field MAY be used to
> identify whether messages are the same. Of course, it may not be practical
> to reject the first copy of a group of identical messages or those that
> arrive some time after the first one.

New error string: `FAIL: Duplicate message with no exploded flag`.

The "indication that the message has been exploded" is the `exploded` flag in
a DKIM2-Signature `f=` tag (§7.9). Per §7.9, if that flag is absent from every
signature in the chain, an MTA MAY assume only one copy of the message is
intended to exist.

This is not a wire-format change. Nothing about signing, canonicalization or
hashing moves, so unlike the -05 `Received-*` rule there is no cross-
implementation interop risk and no need to land it everywhere simultaneously.

## Scope

Perl, Python, Go and C get an optional replay-store hook. Behaviour with no
store configured is byte-identical to today, so the CLIs and existing test
suites stay stateless.

Out of scope, deliberately:

- **Browser verifier** (`deploy/www/verify/`) — verifies one pasted message
  with no cross-message context. There is nothing for it to remember.
- **Mailman and Sympa** — they sign, they do not verify.
- **Copy-count thresholds.** Considered and rejected: letting the first N
  replays through to accommodate senders who forgot the `exploded` flag makes
  the conformance story fuzzy and rewards the broken sender.
- **Retroactively rejecting the first copy.** §11.9 concedes this is
  impractical; we accept copy 1 and reject from copy 2.

## The dedup key

`sha256_hex` of the canonicalized **topmost DKIM2-Signature header value**,
signature data included.

### Why not the m=1 hashes

§11.9 suggests the m=1 Message-Instance hashes. Those identify the *original
message content*, which is wrong for our purposes: a message that legitimately
reaches a recipient by two paths — a mailing list copy plus a direct Cc, or
two forwarding routes — carries identical m=1 hashes but two entirely
different signature chains. Keying on m=1 would flag one of those legitimate
copies as a replay.

The topmost signature is identical only when someone re-injects the same
fully-signed bytes, which is precisely the DKIM replay attack: obtain one
message signed by a reputable domain, then re-send those exact bytes to many
recipients.

The choice also sharpens the `exploded` interaction. A list that signs once
and sends identical bytes to 500 subscribers produces 500 identical topmost
signatures — exactly the case the flag exists to excuse. A list that signs
per-recipient (differing `rt=`) produces distinct topmost signatures and never
needs the flag at all.

### Canonicalization

Unfold continuation lines (`\r?\n[ \t]` → space), collapse WSP runs to a
single space, trim leading and trailing whitespace, then SHA-256 and hex.

This is the normalization `Mail::DKIM2::MessageStore::_key_for_mi` already
applies to MI values (`perl/lib/Mail/DKIM2/MessageStore.pm:19`). Reusing it
means a hop that refolds the header differently still yields the same key.

"Topmost" is the signature with the highest `i=`, a value every verifier
already computes — `$max_i` in `perl/lib/Mail/DKIM2/Verifier.pm:175`, the same
number the milter reports as `header.i`.

## The store interface

Two methods: `seen(key) -> bool` and `record(key)`. Optional everywhere;
absent means the check does not run.

| Language | Shape |
|---|---|
| Perl | `Mail::DKIM2::ReplayStore`; `$verifier->set_replay_store($store)` |
| Python | `replay_store=None` keyword on `verify_message()` (the module is function-based, not a class) |
| Go | `type ReplayStore interface { Seen(string) (bool, error); Record(string) error }`, as a field on the existing `VerifyOptions` (`go/dkim2/signature.go:68`) |
| C | two function pointers plus `void *replay_ctx`, added to the "Verifier options" block of `dkim2_ctx_t` (`c/dkim2_internal.h:90`) |

The computed key is exposed on the verification result so the caller can
record without recomputing it:

- Perl: `$verifier->replay_key`
- Python: field on `VerifyResult` (`python/dkim2verify.py:632`)
- Go: field on `VerifyResult`
- C: `char replay_key[65]` on `dkim2_verify_result_t` (`c/dkim2_verify.h:4`)

The key is empty/undef whenever the check was skipped.

## Check ordering

Within a verification, after the chain is otherwise good:

1. Verify the chain exactly as today.
2. If the result is not PASS, stop. No key, no check, no record. A message
   failing for other reasons must not be able to poison the store.
3. If any signature in the chain carries the `exploded` flag, skip the check
   and leave the key empty. All four implementations already parse this flag
   for the §11.8 `donotexplode` check
   (`perl/lib/Mail/DKIM2/Verifier.pm:283`, `python/dkim2verify.py:276`,
   `go/dkim2/verify.go:253`).
4. Compute the key. If `seen(key)` is true, the result becomes
   `FAIL: Duplicate message with no exploded flag`.
5. Otherwise PASS, with `replay_key` populated for the caller.

### Store errors fail open

If `seen()` errors — unreadable directory, full disk, permissions — the
verifier logs and treats the message as unseen, leaving the result unchanged.
A `record()` failure is likewise logged and swallowed.

This is deliberate. §11.9 is a SHOULD, and a broken replay cache must not
become a mail outage. The cost is that replays pass undetected while the store
is unavailable, which is the right trade against rejecting or deferring
legitimate mail. It also keeps store failures out of the verification result,
so a storage problem can never be misreported as a signature problem.

## Recording happens on accept, never inside the library

The library computes the key and reads the store. It never writes. `record()`
is called by the integration at the point the message is accepted.

This split is the single most important correctness property of the design.
An SMTP retry after a 4xx is byte-identical to the original, so its topmost
signature — and therefore its key — is identical. If the library recorded at
verify time, every legitimate retry would flag itself as a replay on the next
attempt. Recording only on accept leaves just the RFC 1047 lost-250 case,
which §11.9 explicitly reasons is rare enough to accept.

In the milter, the record call goes in `eom_callback` where the result is
pass, beside the existing `_add_mi_and_store()` call
(`perl/lib/Mail/Milter/Authentication/Handler/DKIM2Verify.pm:182`).

## Filesystem backend

A reference `ReplayStore` in each language, mirroring `MessageStore`'s shape:

- `directory` is required.
- Path is `<directory>/<first 2 chars of key>/<key>`, the two-character prefix
  subdirectory avoiding filesystem crowding.
- `record` creates a zero-byte marker file, tolerating one that already
  exists. File mtime is the first-seen time.
- `seen` is a plain existence test.
- Expiry is an mtime sweep: a `sweep(max_age_seconds)` method in the library,
  plus a documented systemd timer on the box. Default retention 7 days.

Zero-byte markers mean one inode per accepted message; at 7 days retention
that is comfortable for the deployment.

## Testing

Four cases per language:

1. Same message verified twice against one store → the second FAILs with
   `Duplicate message with no exploded flag`.
2. `exploded` present in the chain → both copies pass.
3. **Same m=1 hashes but a different topmost signature → both pass.** This is
   the legitimate two-paths case and the test that justifies the key choice.
4. A non-PASS result records nothing.

Cross-implementation coverage needs a new runner, because replay is not a
single-message vector and so cannot live in `util/negative-vectors.sh`. New
`util/replay-matrix.sh`: 12 cells (4 verifiers × 3 scenarios), asserting its
own cell count so a trimmed list fails loudly rather than silently covering
less — the convention `util/hash-matrix.sh` and `util/negative-vectors.sh`
already follow.

## Files touched

New:

- `perl/lib/Mail/DKIM2/ReplayStore.pm`
- `python/dkim2replay.py`
- `go/dkim2/replay.go`
- `c/dkim2_replay.c`, `c/dkim2_replay.h`
- `util/replay-matrix.sh`
- per-language tests

Modified:

- `perl/lib/Mail/DKIM2/Verifier.pm` — `set_replay_store`, `replay_key`, check
- `perl/lib/Mail/Milter/Authentication/Handler/DKIM2Verify.pm` — wire store, record on accept
- `python/dkim2verify.py` — `replay_store` kwarg, `VerifyResult.replay_key`
- `go/dkim2/signature.go` — `ReplayStore` on `VerifyOptions`
- `go/dkim2/verify.go` — check
- `c/dkim2_internal.h`, `c/dkim2_verify.h`, `c/dkim2_verify.c`
- `deploy/SERVER.md` — store directory, systemd timer, retention
- `c/INTEROP-NOTES.md` — record the browser verifier as a deliberate §11.9 gap

## Open risk

Retention length is a policy guess. Seven days covers realistic retry windows
and typical replay campaigns; §11.9 itself notes copies "that arrive some time
after the first one" may not be practical to reject, so a bounded window is
conformant. If the store proves cheap in production the window can grow
without any code change.
