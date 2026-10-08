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
  recipe-descending-ranges.eml     -- body Recipe copy ranges out of order
  recipe-overlapping-ranges.eml    -- body Recipe copy ranges overlap
  positive-control-b-literal.eml   -- Recipe "b" items carry non-UTF-8 octets
  positive-control-bottom-recipe.eml -- m=1 (bottom) Message-Instance
                                         carries a VALID r= Recipe; §9.1
                                         explicitly permits this
  positive-control-null-body.eml   -- list hop with a null body Recipe ("b": null)
                                         and a real header Recipe; ACCEPT
  positive-control-null-body-over-recipe.eml -- same, over an ordinary m=2; ACCEPT
  null-body-forged-history.eml     -- null body Recipe whose header Recipe hides
                                         a To: change; REJECT at m=1
  positive-control-null-below.eml  -- ordinary m=3 over a null-body m=2; ACCEPT
  positive-control-empty-body-chain.eml -- empty body, Subject change; ACCEPT
  empty-body-forged-history.eml    -- empty body, To: change hidden from Recipe; REJECT
  positive-control-nd-bridge.eml   -- the same §9.3 bridge made with a key for
                                         the domain the message DID arrive at
"""
import base64
import json
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


def _two_hop(prev_headers, prev_body, cur_headers, cur_body, recipe):
    """A genuine two-hop chain: m=1/i=1 (test1) over the PREVIOUS content,
    then m=2 carrying `recipe` (a dict, encoded here by hand so the vector
    does not depend on any signer's own Recipe builder) and i=2 (test2)
    over the CURRENT content. Everything is cryptographically valid; only
    the Recipe's content is under test."""
    mi1 = ds.build_message_instance(prev_headers, prev_body, version=1, algs=["sha256"])
    priv1, alg1 = ds.load_private_key(key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [], [], mi1, DOM, "sel1", priv1, alg1,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS,
    )
    hh = ds.b64(ds.compute_header_hash(cur_headers, "sha256"))
    bh = ds.b64(ds.compute_body_hash(cur_body, "sha256"))
    r = base64.b64encode(json.dumps(recipe, separators=(",", ":")).encode("ascii")).decode()
    mi2 = f"Message-Instance: m=2; h=sha256:{hh}:{bh}; r={r};"
    priv2, alg2 = ds.load_private_key(key("sel1", "test2.dkim2.com"))
    sig2 = ds.build_dkim2_signature(
        [mi1], [sig1], mi2, "test2.dkim2.com", "sel1", priv2, alg2,
        mailfrom="relay@test2.dkim2.com", rcptto=["final@example.com"],
        seq=2, mi_version=2, timestamp=TS + 100,
    )
    msg = sig2.encode() + b"\r\n" + sig1.encode() + b"\r\n"
    msg += mi2.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in cur_headers:
        msg += h + b"\r\n"
    msg += b"\r\n" + cur_body
    return msg


CUR_BODY = b"alpha\r\nbeta\r\ngamma\r\n"


def build_recipe_descending():
    """Body Recipe whose copy ranges are out of order. spec-06 §5.2: "The
    start value of each "c" step MUST be in ascending order and MUST be
    greater than the end value of all preceding "c" steps." The previous
    body was [gamma, alpha, beta]; the current is [alpha, beta, gamma], so
    {"c":[3,3]},{"c":[1,2]} rebuilds it EXACTLY -- a verifier that applies
    ranges without checking their order reconstructs m=1, matches its
    hashes, and accepts. A conformant producer must write the moved line
    literally instead. MUST be rejected."""
    headers, _ = load_base()
    prev_body = b"gamma\r\nalpha\r\nbeta\r\n"
    return _two_hop(headers, prev_body, headers, CUR_BODY,
                    {"b": [{"c": [3, 3]}, {"c": [1, 2]}]})


def build_recipe_overlapping():
    """Body Recipe whose copy ranges overlap: previous body [alpha, beta,
    beta, gamma], current [alpha, beta, gamma], Recipe {"c":[1,2]},{"c":[2,3]}.
    Again an exact reconstruction, so only the §5.2 ordering rule can reject
    it (and without the rule a few bytes of Recipe can name a copy of the
    body many times over). MUST be rejected."""
    headers, _ = load_base()
    prev_body = b"alpha\r\nbeta\r\nbeta\r\ngamma\r\n"
    return _two_hop(headers, prev_body, headers, CUR_BODY,
                    {"b": [{"c": [1, 2]}, {"c": [2, 3]}]})


def build_positive_b_literal():
    """POSITIVE CONTROL for the "b" Recipe step: literals whose octets are
    not UTF-8 -- a Latin-1 e-acute, an EUC-KR Hangul pair, plus a valid UTF-8
    CJK character -- carried as base64 of the raw bytes inside the JSON
    string, for one header value and one body line that the hop removed.
    "d" cannot carry them: JSON text is Unicode, and the three producers we
    had disagreed (raw octets, \\udcXX surrogate escapes, U+FFFD). MUST be
    accepted, with the exact bytes restored."""
    headers, _ = load_base()
    octets = b"caf\xe9 \xb1\xa4 \xe4\xb8\xad"
    b = base64.b64encode(octets).decode()
    prev_headers = headers + [b"Comments: " + octets]
    prev_body = octets + b"\r\n" + CUR_BODY
    return _two_hop(prev_headers, prev_body, headers, CUR_BODY,
                    {"h": {"comments": [{"b": [b]}]},
                     "b": [{"b": [b]}, {"c": [1, 3]}]})


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


def _subject_prefixed(headers, tag):
    out = []
    for h in headers:
        if h.lower().startswith(b"subject:"):
            h = b"Subject: [" + tag + b"] " + h[len(b"subject:"):].lstrip()
        out.append(h)
    return out


def _to_changed(headers):
    return [b"To: other@example.org" if h.lower().startswith(b"to:") else h
            for h in headers]


def _null_body_chain(hops):
    """A DKIM2 chain over successive message states.

    hops[0] is (headers, body) for m=1.  Each later hop is (headers, body,
    recipe_fn): the Message-Instance m=N is built over that state with the
    Recipe recipe_fn(prev_headers, prev_body, headers, body) returns (a dict
    or None).  Instance N is signed i=N by test<N>.dkim2.com (sel1), rt= the
    next domain, so every signature is valid and the only thing under test is
    what the verifier does with the Recipes.  DKIM2-Signatures cover only
    Message-Instance and DKIM2-Signature fields (§9.6), so nothing else
    protects the header Recipe."""
    mis, sigs = [], []
    for n, hop in enumerate(hops, 1):
        headers, body = hop[0], hop[1]
        recipe = hop[2](*hops[n - 2][:2], headers, body) if n > 1 else None
        mi = ds.build_message_instance(headers, body, version=n, algs=["sha256"],
                                       recipe=recipe)
        dom = f"test{n}.dkim2.com"
        priv, alg = ds.load_private_key(key("sel1", dom))
        sig = ds.build_dkim2_signature(
            mis, sigs, mi, dom, "sel1", priv, alg,
            mailfrom=f"hop{n}@{dom}", rcptto=[f"user@test{n + 1}.dkim2.com"],
            seq=n, mi_version=n, timestamp=TS + 100 * n)
        mis.append(mi)
        sigs.append(sig)
    top_headers, top_body = hops[-1][0], hops[-1][1]
    msg = b""
    for sig in reversed(sigs):
        msg += sig.encode() + b"\r\n"
    for mi in reversed(mis):
        msg += mi.encode() + b"\r\n"
    for h in top_headers:
        msg += h + b"\r\n"
    return msg + b"\r\n" + top_body


def _null_body_recipe(*a):
    r = ds.build_recipes(*a) or {}
    r["b"] = None  # the previous body is not recoverable
    return r


def _forged_recipe(*a):
    r = _null_body_recipe(*a)
    r["h"] = {k: v for k, v in r["h"].items() if k.lower() != "to"}
    return r


def _footer_recipe(*a):
    return ds.build_recipes(*a)


def build_positive_null_body():
    """POSITIVE CONTROL: m=1 signed by the originator, then a list hop that
    changes Subject (a real header Recipe) and rewrites the body, recording a
    NULL body Recipe ("b": null: the previous body is not recoverable), then
    signed i=2 by the list domain. The header history below the null is
    still intact, so this MUST be accepted."""
    headers, body = load_base()
    return _null_body_chain([
        (headers, body),
        (_subject_prefixed(headers, b"list"), body + b"rewritten by list\r\n",
         _null_body_recipe),
    ])


def build_positive_null_body_over_recipe():
    """POSITIVE CONTROL: m=2 is an ordinary header+body hop (Subject tag and
    a footer, real Recipes); m=3 rewrites the body with a null body Recipe
    and a real header Recipe. The body Recipe below the null must be
    skipped (there is no body for it to apply to) while the header history
    is still walked. MUST be accepted."""
    headers, body = load_base()
    h2 = _subject_prefixed(headers, b"fwd")
    b2 = body + b"footer\r\n"
    return _null_body_chain([
        (headers, body),
        (h2, b2, _footer_recipe),
        (_subject_prefixed(h2, b"list"), b2 + b"rewritten by list\r\n",
         _null_body_recipe),
    ])


def build_null_body_forged_history():
    """NEGATIVE: like the null-body positive control, but the list hop also
    changes To: and its header Recipe omits that change. The top instance's
    hashes match the message it is on; only undoing the Recipe shows m=1's
    header hash no longer matches. A verifier that stops checking at the
    null body Recipe (instead of walking the header history below it)
    accepts a forged history. MUST be rejected."""
    headers, body = load_base()
    return _null_body_chain([
        (headers, body),
        (_to_changed(_subject_prefixed(headers, b"list")),
         body + b"rewritten by list\r\n", _forged_recipe),
    ])


def build_positive_null_below():
    """POSITIVE CONTROL: an ORDINARY top instance over a null one. m=2 is a
    list hop with a null body Recipe and a header Recipe; m=3 is a later hop
    that only adds a header (body unchanged, so no "b"). The verifier must
    undo m=3 normally and then walk the header history below m=2's null.
    MUST be accepted."""
    headers, body = load_base()
    h2 = _subject_prefixed(headers, b"list")
    b2 = body + b"rewritten by list\r\n"
    return _null_body_chain([
        (headers, body),
        (h2, b2, _null_body_recipe),
        (h2 + [b"Comments: added by a later hop"], b2, _footer_recipe),
    ])


def build_positive_empty_body():
    """POSITIVE CONTROL: a message with an EMPTY body: m=1, then m=2 changes
    Subject (header Recipe only), signed i=2. MUST be accepted."""
    headers, _ = load_base()
    return _null_body_chain([
        (headers, b""),
        (_subject_prefixed(headers, b"list"), b"", _footer_recipe),
    ])


def _forged_plain_recipe(*a):
    r = ds.build_recipes(*a) or {}
    r["h"] = {k: v for k, v in r["h"].items() if k.lower() != "to"}
    return r


def build_empty_body_forged_history():
    """NEGATIVE: empty body; m=2 changes Subject AND To but its header
    Recipe omits the To change. The top instance matches the message; only
    undoing the Recipe shows m=1's header hash no longer matches. MUST be
    rejected."""
    headers, _ = load_base()
    return _null_body_chain([
        (headers, b""),
        (_to_changed(_subject_prefixed(headers, b"list")), b"",
         _forged_plain_recipe),
    ])


FIXTURES = {
    "dup-hash-algorithm.eml": build_dup_hash,
    "dup-selector.eml": build_dup_selector,
    "too-many-signatures.eml": build_too_many,
    "malformed-json-r.eml": build_malformed_json,
    "unsigned-mi.eml": build_unsigned_mi,
    "nd-bridge-wrong-domain.eml": build_nd_bridge_wrong_domain,
    "positive-control-two-selectors.eml": build_positive_control,
    "positive-control-bottom-recipe.eml": build_positive_bottom_recipe,
    "recipe-descending-ranges.eml": build_recipe_descending,
    "recipe-overlapping-ranges.eml": build_recipe_overlapping,
    "positive-control-b-literal.eml": build_positive_b_literal,
    "positive-control-nd-bridge.eml": build_positive_nd_bridge,
    "positive-control-null-body.eml": build_positive_null_body,
    "positive-control-null-body-over-recipe.eml": build_positive_null_body_over_recipe,
    "null-body-forged-history.eml": build_null_body_forged_history,
    "positive-control-null-below.eml": build_positive_null_below,
    "positive-control-empty-body-chain.eml": build_positive_empty_body,
    "empty-body-forged-history.eml": build_empty_body_forged_history,
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
