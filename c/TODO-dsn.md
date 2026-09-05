# TODO: DSN handling (draft-06 §12.1) — not yet implemented in C

The C reference implementation does **not** implement DSN propagation
(`Mail::DKIM2::DSN->propagate` / `dkim2dsn.py` / `dkim2.Propagate` in the Perl,
Python and Go trees) or the §12.1.2 authentication of an inbound DSN
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

§12.1.2 additionally needs a headers-only verify mode: with the returned
original echoed back as `text/rfc822-headers` there is no body, so of the
Message-Instance content check only the top instance's header hash can run.
The other three trees spell this `headers_only` / `HeadersOnly` on the verifier.

See `lib/Mail/DKIM2/DSN.pm` (Perl, deployed) for the reference algorithm and
`go/dkim2/dsn.go` / `python/dkim2dsn.py` for the other reference implementations.
