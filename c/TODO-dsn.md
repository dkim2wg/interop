# TODO: DSN handling (-08 §16) — not yet implemented in C

The C reference implementation does **not** implement DSN propagation
(`Mail::DKIM2::DSN->propagate` / `dkim2dsn.py` / `dkim2.Propagate` in the Perl,
Python and Go trees) or the -08 §16.4 authentication of an inbound DSN
(`Mail::DKIM2::DSN->authenticate` / `dkim2dsn.authenticate` / `dkim2.Authenticate`).

Reason: the C tree has no MIME multipart parser, so handling a
`multipart/report` DSN (locate the `message/rfc822` part, undo the embedded
message's top Message-Instance, strip the Forwarder's DKIM2-Signature, rebuild
the part, and re-sign the whole DSN) would require building one. The C code is
reference-only and is **not** deployed — the live demo server signs and verifies
with the Perl `Mail::DKIM2` library — so this was deliberately deferred.

To implement later, build on the existing primitives:
- `dkim2_message.c` / `dkim2_recipe.c` for undoing a Message-Instance,
- `dkim2_header.c` for parsing/formatting DKIM2-Signature (incl. the new `nd=`),
- `dkim2_sign.c` for re-signing as a new message with MAIL FROM `<>`,
- `dkim2_verify.c` for authenticating the returned original,

plus a minimal `multipart/report` boundary splitter to extract and replace the
embedded `message/rfc822` part.

-08 §16.4 additionally needs:

- a headers-only verify mode: with the returned original echoed back as
  `text/rfc822-headers` there is no body, so of the Message-Instance content
  check only the top instance's header hash can run. The other three trees
  spell this `headers_only` / `HeadersOnly` on the verifier;
- a second verify pass over the DSN itself, since point 1 compares the DSN's
  own `d=` against the returned message's top `rt=` and an unverified `d=` is
  whatever the sender typed. The comparison is the -08 §7 relaxed match with `rt=`
  as the address domain (`d=` may be a parent of the delivery domain, never a
  child); see INTEROP-NOTES §19, as the spec says neither of those;
- the propagation entry point must refuse to propagate a DSN that fails any of
  this: §16.4 says such a DSN "MUST NOT be propagated any further";
- -08 §16: never generate or propagate a DSN when the top signature's mf=
  decodes to `<>`, nor for a message that was not Provisionally Verified
  (§13.2: top signature valid and top Message-Instance hashes match), and a
  DSN's d= must relaxed-match the reported message's top rt= (§16.2,
  contract D11).

Propagation itself must distinguish the two ways an undo can fail (see
INTEROP-NOTES §20): -08 §16.3's "null Recipe" (a present `"b"` that is JSON
null) is the upstream declaring the previous body unrecoverable, and gets
`text/rfc822-headers` back with the Forwarder's Message-Instance stripped
along with its signature; any other reconstruction failure means refusing to
propagate at all.

See `lib/Mail/DKIM2/DSN.pm` (Perl, deployed) for the reference algorithm and
`go/dkim2/dsn.go` / `python/dkim2dsn.py` for the other reference implementations.
