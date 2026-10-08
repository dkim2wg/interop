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
  null-top-forged.eml    like null-top but the header Recipe hides
                         a To: change                             -> REFUSE
                                       even with the flag
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
    "fresh.eml": build_fresh,
    "valid-chain.eml": build_valid_chain,
    "broken-signature.eml": build_broken_signature,
    "broken-mi-chain.eml": build_broken_mi_chain,
    "null-top.eml": build_null_top,
    "null-top-forged.eml": build_null_top_forged,
    "mi-only.eml": build_mi_only,
    "mi-only-broken.eml": build_mi_only_broken,
    "mi-only-null.eml": build_mi_only_null,
    "nd-to-us.eml": build_nd_to_us,
    "nd-to-other.eml": build_nd_to_other,
}


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
