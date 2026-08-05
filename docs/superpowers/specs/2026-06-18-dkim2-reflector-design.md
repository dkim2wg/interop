# DKIM2 Reflector — Design

**Date:** 2026-06-18
**Status:** Approved (pending spec review)
**Spec basis:** draft-ietf-dkim-dkim2-spec-02
**Author:** brong + Claude

## Goal

Add a set of **reflector addresses** to the `dkim2.com` demo server. Each
verifies an incoming message, applies a defined transformation, and sends the
message back to the original sender so the sender can observe DKIM2 chain
behaviour end-to-end. Six addresses expose six behaviours (`raw`, `subject`,
`body`, `both`, `redacted`, `damage`).

The reflector signs as `dkim2.com` (adding the next link in the DKIM2 chain)
**only when incoming authentication passed**; it always applies the mode's
transformation and always adds an explanation header.

## Authentication model

- **Always** verify the incoming message and add explanation headers.
- **Always** apply the mode's transformation, regardless of the auth result.
- Add the reflector's **DKIM2 signature only if incoming auth passed**, where
  *passed* = the incoming DKIM2 chain verified. This is **DKIM2-only**: SPF and
  DKIM1 are not consulted. A message with no valid DKIM2 chain is "not passed".
- On auth failure: forward the (transformed) message **without** a reflector
  signature and without a new Message-Instance.

## Approach

A standalone Perl script, `brong/bin/dkim2-reflector.pl`, invoked from postfix
aliases with the mode as an argument. It uses the existing `Mail::DKIM2`
libraries directly (`Verifier`, `MessageInstance`, `Signer`) rather than
re-injecting through the outbound milter — direct use is required for the
`damage` (mutate-after-signing) and `redacted` (null body recipe) behaviours,
and for auth-conditional signing.

Rejected alternatives: re-injecting through the outbound milter (the milter
decides signing on its own rules — can't express damage/redacted/conditional);
a hybrid milter+wrapper (two inconsistent code paths).

## Transport & envelope

Postfix aliases in `/etc/aliases`:
```
reflector-raw:      |"/usr/local/bin/dkim2-reflect raw"
reflector-subject:  |"/usr/local/bin/dkim2-reflect subject"
reflector-body:     |"/usr/local/bin/dkim2-reflect body"
reflector-both:     |"/usr/local/bin/dkim2-reflect both"
reflector-redacted: |"/usr/local/bin/dkim2-reflect redacted"
reflector-damage:   |"/usr/local/bin/dkim2-reflect damage"
```
(`/usr/local/bin/dkim2-reflect` is the deployed copy of
`brong/bin/dkim2-reflector.pl`.)

- The mode is `$ARGV[0]`.
- Postfix local delivery exports `$SENDER` and `$RECIPIENT` to the pipe. The
  reflector replies **to `$SENDER`** (the incoming SMTP MAIL FROM), with
  envelope **MAIL FROM = `reflector-bounces@dkim2.com`**.
- **Injection bypasses the milters.** The reflector does its own signing, so
  the reply must not pass through the outbound milter (which would add a
  second signature). Add a dedicated postfix injection service in `master.cf`,
  e.g. on `127.0.0.1:10588`, with `smtpd_milters=` and `non_smtpd_milters=`
  emptied. The reflector submits the finished message there over SMTP.
- If `$SENDER` is empty (null return-path, e.g. a bounce), the reflector logs
  and drops the message — there is nowhere to reflect to.

## Per-message flow

1. Read the message from stdin; read `$SENDER`; mode from `$ARGV[0]`.
2. **Verify** with `Mail::DKIM2::Verifier` (DKIM2-only): a verified DKIM2
   chain → `passed`; anything else (no DKIM2, broken chain, failed hashes) →
   not passed. SPF/DKIM1 are not consulted.
3. **Transform** per mode (see table). Always applied.
4. **If `passed`:** compute the Message-Instance (per the mode) and sign with
   `Mail::DKIM2::Signer` as `d=dkim2.com`, **a single signature** with selector
   `sel1` / `rsa-sha256` (key `/etc/dkim2/keys/dkim2.com/sel1.key`) — one
   `Signer` instance produces one `DKIM2-Signature` (the lib signs one
   algorithm per instance, matching the milter). Produces the next `i=N+1`
   with `mf=reflector-bounces@dkim2.com` and `rt=` the reply recipient.
   (The `ed25519.key` also exists; multi-algorithm signing is a possible
   later enhancement and out of scope here.) **If not passed:** skip MI and
   signature.
5. For `damage` only: after signing, append the damage line to the body
   (post-signature mutation — see table).
6. Add explanation headers (both excluded from the DKIM2 header hash by
   `should_skip()`, so they never affect the signature):
   - `Authentication-Results: dkim2.com; dkim2=<pass|fail|none> ...`
   - `X-DKIM2-Reflector: mode=<mode>; auth=<verdict>; signed=<yes|no>; note=<text>`
7. Submit to `127.0.0.1:10588`: MAIL FROM `reflector-bounces@dkim2.com`,
   RCPT TO `$SENDER`.

## Modes

The "signature line" is a textual footer (like a mailing-list footer), default:
```
-- 
Reflected and signed by the DKIM2 reflector at dkim2.com
```

| Mode | Transform (always) | Message-Instance when signed | Signature when signed | Expected outcome at sender |
|---|---|---|---|---|
| `raw` | none | **reuse the existing top `m=`** — no new MI (content unchanged) | new `i=N+1` over the same instance | verifies cleanly |
| `subject` | prefix `Subject:` with `[DKIM2] ` | new `m=N+1` with `rh` recipe for `Subject` | new `i=N+1` | verifies; `undo()` restores the subject |
| `body` | append footer line | new `m=N+1` with `rb` recipe | new `i=N+1` | verifies; `undo()` restores the body |
| `both` | subject prefix + footer | new `m=N+1` with `rh` + `rb` | new `i=N+1` | verifies; `undo()` restores both |
| `redacted` | append footer line | new `m=N+1` with body recipe field set to JSON **`null`** (spec §4.2: body changed, not recreatable) | new `i=N+1` | verifies; body **cannot** be undone |
| `damage` | none before signing; **after** signing, append a line `damage line, breaks the signature` | reuse the existing top `m=` (as `raw`) | new `i=N+1` over the pre-damage instance | **fails** body-hash verification at the sender |

Notes:
- `raw` and `damage` add a signature without a new MI: a new chain link over
  an unchanged message instance, recording the new envelope (`mf=`/`rt=`).
- `redacted` records that the body changed (`m` increments, new hashes) but
  emits `r={"b": null}` so a verifier knows the change happened and is not
  reversible.

## Library change required

`Mail::DKIM2::MessageInstance` currently emits a body recipe only as an encoded
list (`as_string` builds `$recipe_json{b}` from a list). To support `redacted`,
add the ability to emit the body recipe field as JSON `null`:
- Introduce a sentinel (e.g. `$mi->set_tag('rb', \'null')` or a dedicated
  `set_null_body_recipe()` method) that causes `as_string` to output
  `"b": null` in the `r=` JSON.
- `parse()` already tolerates and `verify()`/`undo()` already handle missing
  reconstruction data; confirm `undo()` on a `"b": null` recipe behaves
  sensibly (cannot recreate — leaves body as-is or reports non-reversible)
  and add a test.

This is the only change to the shared library; the rest of the feature lives
in the new reflector script and deployment config.

## Files

- Create: `brong/bin/dkim2-reflector.pl` — the reflector script.
- Modify: `brong/lib/Mail/DKIM2/MessageInstance.pm` — emit `"b": null`.
- Create: `brong/t/reflector.t` — unit tests.
- Create: `brong/tests/emails/reflector-*.eml` — sample inputs as needed.
- Modify: `deploy/SERVER.md` — document aliases, the no-milter injection
  service, deployment, and the reflector addresses.
- Create: `deploy/reflector-aliases` — the `/etc/aliases` snippet (reference).
- Modify (server, documented in SERVER.md, not in repo): `/etc/postfix/master.cf`
  injection service; `/etc/aliases`.

## Error handling

- Empty `$SENDER` → log and exit 0 (nothing to reflect; avoid bounce loops).
- Unparseable message → log, exit 0 (do not bounce).
- Missing signing key → log; still reflect, but unsigned with
  `X-DKIM2-Reflector: ... signed=no; note=no-key`.
- The reflector never bounces; failures are logged to the postfix/syslog
  stream and the message is dropped or forwarded unsigned as above.

## Testing

**Unit (`brong/t/reflector.t`, no real mail):** For each mode, feed a sample
DKIM2-signed message and assert:
- the transformation (subject prefix / footer / damage line / none);
- the MI outcome (no new MI for `raw`/`damage`; `rh`/`rb` present for
  `subject`/`body`/`both`; `r={"b": null}` for `redacted`);
- signed vs unsigned decision for passed vs failed input;
- presence/!content of `Authentication-Results` and `X-DKIM2-Reflector`.
Plus a `MessageInstance` test for emitting and round-tripping `"b": null`.

**End-to-end (manual, on the server):** Send a DKIM2-signed message to each
`reflector-*@dkim2.com`; capture the reply; verify with the existing tooling
(`verify-sig.pl` / `Verifier`):
- `raw`, `subject`, `body`, `both`, `redacted` → chain verifies; `undo()`
  restores the prior version for `subject`/`body`/`both`; `redacted` body is
  non-recreatable; `damage` → body-hash verification fails.
- Auth-fail input (unsigned / failing) → reply has no reflector signature and
  `X-DKIM2-Reflector: ... signed=no`.

## Out of scope

- SPF and DKIM1 entirely. Auth is DKIM2-only: input without a verified DKIM2
  chain is treated as not-passed and reflected unsigned.
- Web UI or listing of reflector addresses on the dkim2.com landing page
  (may be added later).
