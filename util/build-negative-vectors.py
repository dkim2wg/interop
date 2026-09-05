#!/usr/bin/env python3
"""Build hand-crafted §8.9/§11.2 negative (and one positive-control) fixture
messages for util/negative-vectors.sh (Task 21).

Each negative fixture is constructed so it is otherwise cryptographically
VALID -- correct header/body hashes, correct signature bytes -- and violates
exactly ONE rule. That matters: if the corresponding duplicate/malformed-JSON
check were silently unreachable from the real verify path (the exact bug
class found during this upgrade -- a parser that returned the right error
while the calling code discarded it), a fixture built any looser way could
still get rejected for an unrelated reason (e.g. a broken crypto signature)
and the gap would go undetected. See task-21-brief.md's CONTROLLER RULING.

Uses dkim2sign.py's internal signing primitives -- the SIGNER's own API --
to build these. That is legitimate fixture construction, not the thing the
controller ruling prohibits (calling a VERIFIER's parsing helper directly
instead of its real entry point); each fixture this script writes is then
fed through every verifier's real CLI/API in util/negative-vectors.sh.

Usage: python3 util/build-negative-vectors.py <output-dir>
Writes:
  dup-hash-algorithm.eml           -- h= repeats an algorithm (sha256 twice)
  dup-selector.eml                 -- s= repeats a Selector (sel1 twice)
  too-many-signatures.eml          -- s= has one algorithm 3+ times
  malformed-json-r.eml             -- r= decodes to malformed JSON
  nd-bridge-wrong-domain.eml       -- a §9.3 nd= bridge made with a key for a
                                         domain the message never arrived at
  positive-control-two-selectors.eml -- s= has one algorithm twice with
                                         DISTINCT selectors (sel1, sel2);
                                         §8.9 explicitly permits this
  positive-control-bottom-recipe.eml -- m=1 (bottom) Message-Instance
                                         carries a VALID r= Recipe; §9.1
                                         explicitly permits this
  positive-control-nd-bridge.eml   -- the same §9.3 bridge made with a key for
                                         the domain the message DID arrive at
"""
import base64
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "python"))

import dkim2sign as ds  # noqa: E402

KEYS = os.path.join(REPO, "keys")
SRC = os.path.join(REPO, "perl/tests/emails/brong-orig.eml")
DOM = "test1.dkim2.com"
MF = "brong@test1.dkim2.com"
RT = ["user@test2.dkim2.com"]
TS = 1787721393  # arbitrary fixed timestamp; verifiers run with --ignore-timestamps


def key(sel, domain=DOM):
    return os.path.join(KEYS, f"{sel}._domainkey.{domain}.pem")


def build_multi_sig(mi_headers_full, sig_headers, seq, mi_version, timestamp,
                     domain, mailfrom, rcptto, entries):
    """entries: list of (selector, keyfile). Every verifier here reconstructs
    the signing input for a multi-entry s= tag by blanking ALL entries'
    signature bytes simultaneously into ONE incomplete header, then checking
    each entry's signature against that same blob -- so build that blob once
    and sign it separately with each selector's own key (spec-06 §8.9
    multi-signature dexterity: e.g. overlapping old/new selector during a
    key rotation)."""
    mf_b64 = ds.b64(ds.to_rfc5321_path(mailfrom).encode("utf-8"))
    rt_b64 = ",".join(ds.b64(ds.to_rfc5321_path(r).encode("utf-8")) for r in rcptto)

    loaded = [(sel, *ds.load_private_key(kf)) for sel, kf in entries]  # (sel, privkey, algorithm)
    blanked = ",".join(f"{sel}:{alg}:" for sel, _, alg in loaded)
    incomplete = (
        f"DKIM2-Signature: i={seq}; m={mi_version}; t={timestamp}; "
        f"d={domain}; mf={mf_b64}; rt={rt_b64}; s={blanked};"
    )

    parts = []
    for sel, priv, alg in loaded:
        sig_bytes = ds.compute_signature(mi_headers_full, sig_headers, incomplete, priv, alg)
        parts.append(f"{sel}:{alg}:{ds.b64(sig_bytes)}")
    s_complete = ",".join(parts)
    return (
        f"DKIM2-Signature: i={seq}; m={mi_version}; t={timestamp}; "
        f"d={domain}; mf={mf_b64}; rt={rt_b64}; s={s_complete};"
    )


def assemble(sig_hdr, mi_hdr, content_headers, body):
    out = sig_hdr.encode() + b"\r\n"
    out += mi_hdr.encode() + b"\r\n"
    for h in content_headers:
        out += h + b"\r\n"
    out += b"\r\n" + body
    return out


def load_base():
    raw = open(SRC, "rb").read()
    return ds.parse_message(raw)


def build_dup_hash():
    """h= repeats an algorithm: sha256 appears twice, BOTH tuples correct."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256", "sha256"])
    priv, alg = ds.load_private_key(key("sel1"))
    sig_hdr = ds.build_dkim2_signature(
        [], [], mi_hdr, DOM, "sel1", priv, alg,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS,
    )
    return assemble(sig_hdr, mi_hdr, headers, body)


def build_dup_selector():
    """s= repeats a Selector: sel1 appears twice (same algorithm), both
    entries genuinely sign correctly against sel1's real key."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    sig_hdr = build_multi_sig(
        [mi_hdr], [], seq=1, mi_version=1, timestamp=TS, domain=DOM,
        mailfrom=MF, rcptto=RT,
        entries=[("sel1", key("sel1")), ("sel1", key("sel1"))],
    )
    return assemble(sig_hdr, mi_hdr, headers, body)


def build_too_many():
    """s= has rsa-sha256 three times, across three DISTINCT selectors (so
    this isn't also a duplicate-selector violation) -- all three signatures
    genuinely valid."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    sig_hdr = build_multi_sig(
        [mi_hdr], [], seq=1, mi_version=1, timestamp=TS, domain=DOM,
        mailfrom=MF, rcptto=RT,
        entries=[("sel1", key("sel1")), ("sel2", key("sel2")), ("sel3", key("sel3"))],
    )
    return assemble(sig_hdr, mi_hdr, headers, body)


def build_malformed_json():
    """r= decodes to malformed JSON. The bad r= is baked in BEFORE hashing
    and signing (not patched in afterwards), so the resulting two-hop
    message is genuinely, cryptographically valid throughout -- only the
    §11.2 JSON-validity check can catch it. (A post-hoc corruption would
    also break the i=2 crypto signature, since r= sits inside the signed MI
    header, and would mask whether the invalid-JSON check itself is
    reachable -- exactly the "unreachable but correct" bug class this task
    exists to catch.)"""
    headers, body = load_base()
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    priv1, alg1 = ds.load_private_key(key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [], [], mi1, DOM, "sel1", priv1, alg1,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS,
    )

    new_headers = [b"Received: from test1.dkim2.com by relay.example.com; Mon, 25 Aug 2026 00:00:00 +0000"] + headers
    hh = ds.b64(ds.compute_header_hash(new_headers, "sha256"))
    bh = ds.b64(ds.compute_body_hash(body, "sha256"))
    bad_r = base64.b64encode(b'{"h": ').decode()  # valid base64, malformed JSON
    mi2 = f"Message-Instance: m=2; h=sha256:{hh}:{bh}; r={bad_r};"

    priv2, alg2 = ds.load_private_key(key("sel1", "test2.dkim2.com"))
    sig2 = ds.build_dkim2_signature(
        [mi1], [sig1], mi2, "test2.dkim2.com", "sel1", priv2, alg2,
        mailfrom="relay@test2.dkim2.com", rcptto=["final@example.com"],
        seq=2, mi_version=2, timestamp=TS + 100,
    )

    msg = sig2.encode() + b"\r\n" + sig1.encode() + b"\r\n"
    msg += mi2.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in new_headers:
        msg += h + b"\r\n"
    msg += b"\r\n" + body
    return msg


def build_positive_control():
    """POSITIVE CONTROL: rsa-sha256 twice, with DISTINCT selectors (sel1,
    sel2) -- §8.9 explicitly permits this (e.g. key-rotation overlap). MUST
    be accepted."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    sig_hdr = build_multi_sig(
        [mi_hdr], [], seq=1, mi_version=1, timestamp=TS, domain=DOM,
        mailfrom=MF, rcptto=RT,
        entries=[("sel1", key("sel1")), ("sel2", key("sel2"))],
    )
    return assemble(sig_hdr, mi_hdr, headers, body)


def build_positive_bottom_recipe():
    """POSITIVE CONTROL: the m=1 (bottom) Message-Instance carries a VALID
    r= Recipe. spec-06 §9.1 explicitly permits this ("if it is wished to
    record any changes made to a message as it enters the DKIM2 ecosystem"),
    e.g. an origin MSA stripping a header before the message ever entered
    the DKIM2 chain. This never gets "undone" -- there is no earlier state
    for the bottom instance to reconstruct -- but its r= MUST still parse as
    valid base64 + valid JSON like any other instance's (Task 18 widened the
    C and JS verifiers to check the bottom MI's r= too, since it used to be
    skipped entirely, gated the same as the -- inapplicable here -- undo
    step). A verifier that got that widening wrong (e.g. by requiring an
    undo that cannot exist at m=1) would newly reject this otherwise
    completely conformant message. MUST be accepted."""
    headers, body = load_base()
    recipe = {"h": {"x-original-to": []}}
    mi_hdr = ds.build_message_instance(
        headers, body, version=1, algs=["sha256"], recipe=recipe)
    priv, alg = ds.load_private_key(key("sel1"))
    sig_hdr = ds.build_dkim2_signature(
        [], [], mi_hdr, DOM, "sel1", priv, alg,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS,
    )
    return assemble(sig_hdr, mi_hdr, headers, body)


def build_unsigned_mi():
    """An extra Message-Instance above a fully valid chain, covered by no
    signature: spec-06 §11's "there MUST NOT be a Message-Instance field with
    a higher m= value than occurs in any DKIM2-Signature field", reported as
    "PERMERROR Message-Instance m=<x> is not signed".

    The i=1/m=1 signature and its MI are genuinely correct, so a verifier that
    never compares the topmost MI against the signatures accepts this and
    reports a clean pass -- which is what Perl's validate.pl did, walking the
    unsigned instance and printing "OK Message-Instance". The hashes in the
    extra m=2 header are deliberately bogus: nothing signs them, so nothing can
    tell whether they describe the message, which is precisely the
    accountability gap being tested."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    priv, alg = ds.load_private_key(key("sel1"))
    sig_hdr = ds.build_dkim2_signature(
        [], [], mi_hdr, DOM, "sel1", priv, alg,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS,
    )
    valid = assemble(sig_hdr, mi_hdr, headers, body)
    unsigned = "Message-Instance: m=2; h=sha256:%s:%s" % ("A" * 64, "B" * 64)
    return unsigned.encode() + b"\r\n" + valid


def _bridged_chain(bridge_domain):
    """A Forwarder's §9.3 bridge after a real hop.

    The message arrives at test2 (i=1 rt=); test2 sends it on from test3, and
    bridges the gap with an nd= hop before signing the real hop as test3.
    §9.3 requires that extra header to be made with a key for a domain in the
    RCPT TO the message arrived with, so `bridge_domain` is what decides
    whether the chain holds.
    """
    raw = open(SRC, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    msg = ds.sign_message(raw, "sel1", "test1.dkim2.com", key("sel1", "test1.dkim2.com"),
                          mailfrom="sender@test1.dkim2.com",
                          rcptto=["user@test2.dkim2.com"], timestamp=TS)
    msg = ds.sign_message(msg, "sel1", bridge_domain, key("sel1", bridge_domain),
                          next_domain="test3.dkim2.com", timestamp=TS)
    return ds.sign_message(msg, "sel1", "test3.dkim2.com", key("sel1", "test3.dkim2.com"),
                           mailfrom="srs0=x@bounce.test3.dkim2.com",
                           rcptto=["dest@test5.dkim2.com"], timestamp=TS)


def build_nd_bridge_wrong_domain():
    """A §9.3 bridge made with a key for a domain the message never arrived
    at: the nd= hop is signed by test4.dkim2.com while i=1's rt= says the
    message went to test2.dkim2.com.

    Every signature here is cryptographically valid and the nd=/d= adjacency
    with the hop above it matches, so a verifier that treats an nd= hop as
    "no mf=, nothing to check" accepts it -- and with it accepts a chain of
    custody bridged by a domain that was never in the path, which is the one
    thing the bridge is supposed to attest."""
    return _bridged_chain("test4.dkim2.com")


def build_positive_nd_bridge():
    """The same shape with the bridge made by test2.dkim2.com, the domain the
    message actually arrived at. §9.3 explicitly provides for this, so it MUST
    be accepted: a verifier that demands an mf= from an nd= hop rejects every
    legitimately bridged forward."""
    return _bridged_chain("test2.dkim2.com")


FIXTURES = {
    "dup-hash-algorithm.eml": build_dup_hash,
    "dup-selector.eml": build_dup_selector,
    "too-many-signatures.eml": build_too_many,
    "malformed-json-r.eml": build_malformed_json,
    "unsigned-mi.eml": build_unsigned_mi,
    "nd-bridge-wrong-domain.eml": build_nd_bridge_wrong_domain,
    "positive-control-two-selectors.eml": build_positive_control,
    "positive-control-bottom-recipe.eml": build_positive_bottom_recipe,
    "positive-control-nd-bridge.eml": build_positive_nd_bridge,
}


def main():
    if len(sys.argv) != 2:
        print("usage: build-negative-vectors.py <output-dir>", file=sys.stderr)
        sys.exit(2)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    for name, builder in FIXTURES.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(builder())


if __name__ == "__main__":
    main()
