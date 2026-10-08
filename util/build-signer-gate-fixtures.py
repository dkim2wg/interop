#!/usr/bin/env python3
"""Build the INPUT messages for util/signer-gate.sh.

Each fixture is a message as it arrives at the next hop, test3.dkim2.com, which
is about to sign it (i=N+1) with its sel1 key.  A signer that already sees a
DKIM2 chain must verify it first (outbound mode: the unsigned top
Message-Instance is the one about to be signed) and refuse to sign a chain
that does not check out.

  fresh.eml              no chain at all                          -> SIGN
  valid-chain.eml        i=1/m=1 signed; unsigned m=2 with an
                         ordinary Recipe (Subject tag + footer)   -> SIGN
  broken-signature.eml   i=1 signature does not verify (t= altered
                         after signing)                           -> REFUSE
  broken-mi-chain.eml    signatures fine; unsigned m=2 changed To:
                         but its Recipe does not say so           -> REFUSE
  null-top.eml           unsigned m=2 with a null body Recipe and a
                         valid header Recipe                      -> REFUSE,
                                       SIGN with --allow-null-body-recipe
                         (i=1 covers only m=1: no signature has m=2,
                         so this null is one THIS hop would introduce)
  null-top-forged.eml    like null-top but the header Recipe hides
                         a To: change                             -> REFUSE
                                       even with the flag
  null-top-signed.eml    the list domain test2 made the null m=2 AND
                         signed it (i=2, m=2, rt= the next hop); test3 just
                         forwards it unchanged                    -> SIGN
                                       (a signed null top needs no flag)
  fake-cover-*.eml       null-top plus one extra DKIM2-Signature that claims
                         m=2 but cannot be keyed or verified, so it must
                         NOT count as covering the null top.  Every
                         verifier must PERMERROR on it, so these are
                                                                  -> REFUSE,
                                       REFUSE even with the flag:
    fake-cover-no-i         "m=2; d=evil.example" -- no i= at all
    fake-cover-i0           i=0 (not a positive integer)
    fake-cover-i-abc        i=abc (not an integer)
    fake-cover-m-rewritten  the real i=1 signature with "i=1; m=1;"
                            rewritten to "m=2;" (no i=)
    fake-cover-unparseable  "m=2; i=2; garbage without equals" (not a
                            tag-list)
  null-below-unsigned-top.eml
                         valid i=1/m=1, then an UNSIGNED null m=2, then an
                         UNSIGNED ordinary m=3 on top (a hop that added its
                         own instance over an unsigned null)      -> REFUSE,
                                       SIGN with --allow-null-body-recipe
                         (the null is not the top any more, but no
                         signature covers it: highest valid m= is 1)
  null-below-signed.eml  the null m=2 is covered by a valid i=2/m=2 (as in
                         null-top-signed), then an UNSIGNED ordinary m=3
                                                                  -> SIGN
                                       (a covered null needs no flag)
  mi-only.eml            NO DKIM2-Signature: a list added unsigned m=1 and
                         unsigned m=2 (ordinary Recipe), as Mailman does
                                                                  -> SIGN
  mi-only-broken.eml     like mi-only, m=2's Recipe hides a To: change
                                                                  -> REFUSE
  mi-only-null.eml       like mi-only, m=2 has a null body Recipe -> REFUSE,
                                       SIGN with --allow-null-body-recipe

  nd-to-us.eml           i=1 (test1, rt= test2) then a §9.3 bridge i=2 made by
                         test2 with nd=test3.dkim2.com: the next hop IS the
                         signer                                   -> SIGN
  nd-to-other.eml        same, but nd=test4.dkim2.com: the bridge names some
                         other domain                             -> REFUSE
                                       ("top signature nd=X names another domain")

  signature-gap.eml      i=1 and i=3, no i=2; otherwise valid     -> REFUSE
  instance-gap.eml       m=1 and m=3, no m=2; otherwise valid     -> REFUSE

Reuses the machinery in build-negative-vectors.py (loaded by path: its name
has a hyphen).  Usage: build-signer-gate-fixtures.py <output-dir>
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "bnv", os.path.join(HERE, "build-negative-vectors.py"))
bnv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bnv)
ds = bnv.ds

NEXT_DOM = "test3.dkim2.com"
LIST_RT = f"list@{NEXT_DOM}"


def _signed_bottom(headers, body):
    """i=1/m=1 signed by test1, rt= the next hop.  Returns (mi1, sig1)."""
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    priv, alg = ds.load_private_key(bnv.key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [], [], mi1, bnv.DOM, "sel1", priv, alg,
        mailfrom=bnv.MF, rcptto=[LIST_RT], seq=1, mi_version=1,
        timestamp=bnv.TS)
    return mi1, sig1


def _with_unsigned_top(headers1, body1, headers2, body2, recipe_fn):
    """Signed i=1/m=1 over state 1, then an UNSIGNED m=2 over state 2 whose
    Recipe is recipe_fn(h1, b1, h2, b2)."""
    mi1, sig1 = _signed_bottom(headers1, body1)
    mi2 = ds.build_message_instance(headers2, body2, version=2, algs=["sha256"],
                                    recipe=recipe_fn(headers1, body1, headers2, body2))
    msg = mi2.encode() + b"\r\n" + sig1.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in headers2:
        msg += h + b"\r\n"
    return msg + b"\r\n" + body2


def _mi_only(headers1, body1, headers2, body2, recipe_fn):
    """NO DKIM2-Signature at all: a list (as Mailman does) adds an unsigned
    m=1 over the post as received and an unsigned m=2 over the list's output
    with Recipe recipe_fn(h1, b1, h2, b2)."""
    mi1 = ds.build_message_instance(headers1, body1, version=1, algs=["sha256"])
    mi2 = ds.build_message_instance(headers2, body2, version=2, algs=["sha256"],
                                    recipe=recipe_fn(headers1, body1, headers2, body2))
    msg = mi2.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in headers2:
        msg += h + b"\r\n"
    return msg + b"\r\n" + body2


def build_mi_only():
    h, b = bnv.load_base()
    return _mi_only(h, b, bnv._subject_prefixed(h, b"list"),
                    b + b"footer\r\n", ds.build_recipes)


def build_mi_only_broken():
    h, b = bnv.load_base()
    return _mi_only(h, b, bnv._to_changed(bnv._subject_prefixed(h, b"list")),
                    b + b"footer\r\n", bnv._forged_plain_recipe)


def build_mi_only_null():
    h, b = bnv.load_base()
    return _mi_only(h, b, bnv._subject_prefixed(h, b"list"),
                    b + b"rewritten by list\r\n", bnv._null_body_recipe)


def build_fresh():
    return open(bnv.SRC, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def build_valid_chain():
    h, b = bnv.load_base()
    return _with_unsigned_top(h, b, bnv._subject_prefixed(h, b"list"),
                              b + b"footer\r\n", ds.build_recipes)


def build_broken_signature():
    h, b = bnv.load_base()
    mi1, sig1 = _signed_bottom(h, b)
    tampered = sig1.replace(f"t={bnv.TS};", f"t={bnv.TS + 1};")
    assert tampered != sig1
    return bnv.assemble(tampered, mi1, h, b)


def build_broken_mi_chain():
    h, b = bnv.load_base()
    return _with_unsigned_top(h, b, bnv._to_changed(bnv._subject_prefixed(h, b"list")),
                              b + b"footer\r\n", bnv._forged_plain_recipe)


def build_null_top():
    h, b = bnv.load_base()
    return _with_unsigned_top(h, b, bnv._subject_prefixed(h, b"list"),
                              b + b"rewritten by list\r\n", bnv._null_body_recipe)


def build_null_top_forged():
    h, b = bnv.load_base()
    return _with_unsigned_top(h, b, bnv._to_changed(bnv._subject_prefixed(h, b"list")),
                              b + b"rewritten by list\r\n", bnv._forged_recipe)


def build_null_top_signed():
    """i=1/m=1 by test1 (rt= test2), then the list domain test2 adds m=2 with
    a Subject tag and a rewritten body (null body Recipe, valid header Recipe)
    and SIGNS it: i=2, m=2, rt= user@test3.dkim2.com.  The next hop forwards
    the message unchanged.  Its signature covers the null, so the forwarder
    must sign without --allow-null-body-recipe."""
    return bnv.build_positive_null_body()


def _ordinary_hop(h2, b2):
    """The state an ordinary hop makes from (h2, b2): a second Subject tag
    and a footer, with real Recipes back to (h2, b2)."""
    return bnv._subject_prefixed(h2, b"fwd"), b2 + b"footer\r\n"


def build_null_below_unsigned_top():
    """Valid i=1/m=1 by test1 (rt= the next hop); an UNSIGNED m=2 with a null
    body Recipe (Subject tag, rewritten body); an UNSIGNED ordinary m=3 on
    top of it (another Subject tag, a footer).  The null is no longer the
    top instance, but no signature covers it (the highest valid m= is 1), so
    whoever signs this is the first to vouch for it: REFUSE without the
    option, exactly as for null-top."""
    h1, b1 = bnv.load_base()
    h2, b2 = bnv._subject_prefixed(h1, b"list"), b1 + b"rewritten by list\r\n"
    h3, b3 = _ordinary_hop(h2, b2)
    mi1, sig1 = _signed_bottom(h1, b1)
    mi2 = ds.build_message_instance(h2, b2, version=2, algs=["sha256"],
                                    recipe=bnv._null_body_recipe(h1, b1, h2, b2))
    mi3 = ds.build_message_instance(h3, b3, version=3, algs=["sha256"],
                                    recipe=ds.build_recipes(h2, b2, h3, b3))
    msg = b"\r\n".join(x.encode() for x in (mi3, mi2, sig1, mi1)) + b"\r\n"
    for h in h3:
        msg += h + b"\r\n"
    return msg + b"\r\n" + b3


def build_null_below_signed():
    """null-top-signed (the list domain test2 made the null m=2 and signed it
    i=2/m=2, rt= user@test3.dkim2.com), then an UNSIGNED ordinary m=3 on top
    (another Subject tag, a footer) for test3 to sign.  The null is covered
    by a valid signature, so no option is needed: SIGN."""
    signed = bnv.build_positive_null_body()
    head, b2 = signed.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    # unfold, then split the DKIM2 fields off the content fields
    fields = []
    for ln in lines:
        if ln[:1] in (b" ", b"\t"):
            fields[-1] += b"\r\n" + ln
        else:
            fields.append(ln)
    dkim2 = [f for f in fields if f.lower().startswith((b"dkim2-signature:", b"message-instance:"))]
    h2 = [f for f in fields if f not in dkim2]
    h3, b3 = _ordinary_hop(h2, b2)
    mi3 = ds.build_message_instance(h3, b3, version=3, algs=["sha256"],
                                    recipe=ds.build_recipes(h2, b2, h3, b3))
    msg = mi3.encode() + b"\r\n" + b"\r\n".join(dkim2) + b"\r\n"
    for h in h3:
        msg += h + b"\r\n"
    return msg + b"\r\n" + b3


def _fake_cover(fake_sig_fn):
    """null-top (unsigned null m=2 over a valid i=1/m=1) with one extra
    DKIM2-Signature prepended that names m=2 but is not a signature any
    verifier can key.  fake_sig_fn(sig1) returns that header (no CRLF)."""
    h, b = bnv.load_base()
    mi1, sig1 = _signed_bottom(h, b)
    msg = build_null_top()
    assert sig1.encode() in msg
    fake = fake_sig_fn(sig1)
    assert fake.startswith("DKIM2-Signature:")
    return fake.encode() + b"\r\n" + msg


def _m_rewritten(sig1):
    out = sig1.replace("i=1; m=1;", "m=2;")
    assert out != sig1
    return out


FAKE_COVER = {
    "fake-cover-no-i.eml": lambda s: "DKIM2-Signature: m=2; d=evil.example",
    "fake-cover-i0.eml":
        lambda s: "DKIM2-Signature: i=0; m=2; t=1; d=evil.example; s=sel1:rsa-sha256:AAAA",
    "fake-cover-i-abc.eml": lambda s: "DKIM2-Signature: i=abc; m=2; d=evil.example",
    "fake-cover-m-rewritten.eml": _m_rewritten,
    "fake-cover-unparseable.eml":
        lambda s: "DKIM2-Signature: m=2; i=2; garbage without equals",
}


def _nd_bridge(nd):
    """i=1 test1 -> test2, then test2's §9.3 bridge i=2 carrying nd=<nd>."""
    raw = open(bnv.SRC, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    msg = ds.sign_message(raw, "sel1", "test1.dkim2.com", bnv.key("sel1", "test1.dkim2.com"),
                          mailfrom="sender@test1.dkim2.com",
                          rcptto=["user@test2.dkim2.com"], timestamp=bnv.TS)
    return ds.sign_message(msg, "sel1", "test2.dkim2.com", bnv.key("sel1", "test2.dkim2.com"),
                           next_domain=nd, timestamp=bnv.TS + 100,
                           skip_upstream_check=True)


def build_nd_to_us():
    return _nd_bridge(NEXT_DOM)


def build_nd_to_other():
    return _nd_bridge("test4.dkim2.com")


FIXTURES = {
    "signature-gap.eml": bnv.build_signature_gap,
    "instance-gap.eml": bnv.build_instance_gap,
    "fresh.eml": build_fresh,
    "valid-chain.eml": build_valid_chain,
    "broken-signature.eml": build_broken_signature,
    "broken-mi-chain.eml": build_broken_mi_chain,
    "null-top.eml": build_null_top,
    "null-top-forged.eml": build_null_top_forged,
    "null-top-signed.eml": build_null_top_signed,
    "null-below-unsigned-top.eml": build_null_below_unsigned_top,
    "null-below-signed.eml": build_null_below_signed,
    "mi-only.eml": build_mi_only,
    "mi-only-broken.eml": build_mi_only_broken,
    "mi-only-null.eml": build_mi_only_null,
    "nd-to-us.eml": build_nd_to_us,
    "nd-to-other.eml": build_nd_to_other,
}
for _name, _fn in FAKE_COVER.items():
    FIXTURES[_name] = (lambda fn: lambda: _fake_cover(fn))(_fn)


def main():
    if len(sys.argv) != 2:
        print("usage: build-signer-gate-fixtures.py <output-dir>", file=sys.stderr)
        sys.exit(2)
    os.makedirs(sys.argv[1], exist_ok=True)
    for name, builder in FIXTURES.items():
        with open(os.path.join(sys.argv[1], name), "wb") as f:
            f.write(builder())


if __name__ == "__main__":
    main()
