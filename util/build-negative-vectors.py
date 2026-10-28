#!/usr/bin/env python3
"""Build hand-crafted negative (and positive-control) fixture
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
  order-sig-syntax-before-duplicate.eml  -- s= duplicate selector + a non-base64
                                     value: syntax first (D2/D3 order)
  order-hash-syntax-before-duplicate.eml -- h= duplicate sha256 + unpadded hash:
                                     syntax first
  order-duplicate-before-limit.eml -- 9 s= items, sel1 twice: duplicate before
                                     the limit
  too-many-signatures.eml          -- s= has 9 items (-08 local limit of 8;
                                         contract D3)
  too-many-instance-fields.eml     -- 33 Message-Instance (and 33 DKIM2-Signature)
                                      fields: C9 step a, instances first
  too-many-signature-fields.eml    -- 33 DKIM2-Signature fields: C9 step a
  malformed-json-r.eml             -- r= decodes to malformed JSON
  nd-bridge-wrong-domain.eml       -- a §12.3 nd= bridge made with a key for a
                                         domain the message never arrived at
  positive-control-two-selectors.eml -- s= has one algorithm twice with
                                         DISTINCT selectors (sel1, sel2);
                                         §10.9 explicitly permits this
  recipe-descending-ranges.eml     -- body Recipe copy ranges out of order
  recipe-overlapping-ranges.eml    -- body Recipe copy ranges overlap
  positive-control-u-literal.eml   -- Recipe "u" items carry non-UTF-8 octets
  positive-control-bottom-recipe.eml -- m=1 (bottom) Message-Instance
                                         carries a VALID r= Recipe; §12.1
                                         explicitly permits this
  positive-control-null-body.eml   -- list hop with a null body Recipe ("b": null)
                                         and a real header Recipe; ACCEPT
  positive-control-null-body-over-recipe.eml -- same, over an ordinary m=2; ACCEPT
  null-body-forged-history.eml     -- null body Recipe whose header Recipe hides
                                         a To: change; REJECT at m=1
  positive-control-null-below.eml  -- ordinary m=3 over a null-body m=2; ACCEPT
  positive-control-empty-body-chain.eml -- empty body, Subject change; ACCEPT
  empty-body-forged-history.eml    -- empty body, To: change hidden from Recipe; REJECT
  malformed-body-recipe-below-null.eml -- malformed body Recipe at m=2 below a
                                         null at m=3; REJECT
  duplicate-mi-version.eml         -- two Message-Instance headers both m=1
                                         in an otherwise valid chain; REJECT
  positive-control-unreferenced-lower-mi.eml -- unsigned m=1 under an m=2
                                         (with Recipe) covered by i=1; ACCEPT
  signature-gap.eml                -- i=1 and i=3, no i=2; otherwise valid; REJECT
  instance-gap.eml                 -- m=1 and m=3, no m=2; otherwise valid; REJECT
  positive-control-nd-bridge.eml   -- the same §12.3 bridge made with a key for
                                         the domain the message DID arrive at
  unkeyable-signature-no-i.eml     -- positive-control-null-body plus a junk
                                         "DKIM2-Signature: m=2; d=evil.example"
                                         (no i=); REJECT (PERMERROR)
  unkeyable-signature-i-abc.eml    -- the same with i=abc; REJECT (PERMERROR)
  lone-junk-signature.eml          -- an unsigned message whose only DKIM2 field
                                         is "DKIM2-Signature: m=1; d=evil.example";
                                         REJECT (PERMERROR, not "none")
  signature-i-33.eml               -- two real hops, the second signed as i=33
                                         (one more than MAX_CHAIN_LENGTH, 32);
                                         REJECT (PERMERROR) before any gap check
  signature-i-101.eml              -- the same with i=101 (one more than
                                         MAX_CHAIN_NUMBER, 100); REJECT (PERMERROR)
  signature-i-huge.eml             -- the same with i=99999999999999999999;
                                         REJECT (PERMERROR), no overflow, no hang
  signature-m-huge.eml             -- second hop i=2 over Message-Instance m=2,
                                         but its signature says m=4294967297;
                                         REJECT (PERMERROR)
  instance-m-huge.eml              -- second hop's Message-Instance
                                         m=99999999999999999999 (its signature
                                         says m=2); REJECT (PERMERROR)
  signature-m-malformed.eml        -- second hop's signature says m=4294967297x
                                         (not 1*DIGIT); REJECT (PERMERROR)
  instance-m-malformed.eml         -- second hop's Message-Instance
                                         m=4294967297x; REJECT (PERMERROR)
  recipe-duplicate-b-null-last.eml -- second hop's Recipe JSON is
                                         {"h":...,"b":[...],"b":null}; REJECT
                                         (PERMERROR invalid JSON), whichever
                                         value a parser would have kept
  recipe-duplicate-b-null-first.eml -- the same as {"b":null,"h":...,"b":[...]}
  recipe-duplicate-h-key.eml       -- the same with one "h" key given twice

draft -07 (shared tests in .superpowers/sdd/2026-10-18-dkim2-spec-07/common.md):
  positive-control-custody-bounce.eml -- C1: i=2 mf=<> by the domain of i=1's
                                         rt= (recorded <list@Lists.Test2.DKIM2.com.>)
  custody-bounce-d-mismatch.eml    -- C2: the same bounce signed by test3; REJECT
  positive-control-nd-subdomain-rt.eml -- C3: rt= mail.test2, nd= hop by test2
  nd-subdomain-swapped.eml         -- C3 swapped: rt= test2, nd= hop by
                                         mail.test2 (only p1 is shortened); REJECT
  nd-next-hop-mismatch.eml         -- C4: i=3 is not the nd= domain; REJECT
  custody-mf-domain-literal.eml    -- C5: rt=/mf= domain literals; REJECT
  mf-d-mismatch.eml                -- C6: i=1 mf= not under d=; REJECT
  from-not-authentic.eml           -- A1: From test1, i=1 d=test2; REJECT
  positive-control-from-folded-2047.eml -- A1: folded RFC 2047 From, one mailbox
  positive-control-from-changed.eml -- A2: list under test2 rewrites From, signs m=2
  from-changed-not-authentic.eml   -- A2: the rewrite goes to test5; REJECT
  positive-control-ingress-from-rewritten.eml -- Ruling 19: unsigned ingress
                                         m=1 with the author's From, rewritten
                                         in m=2, i=1 (test2) over m=2; ACCEPT
  from-not-authentic-at-signed-state.eml -- Ruling 19: i=1 over m=2, the From
                                         at state 2 is test1's, d=test2; REJECT
  positive-control-u-literal.eml   -- U2: "u" steps (incl. "Y2Fm6Q==")
  recipe-u-nonzero-pad.eml         -- U3: {"u":["QR=="]}; REJECT
  recipe-b-step.eml, recipe-two-step-keys.eml, recipe-empty-step.eml
                                   -- U4: bad step objects; REJECT
  recipe-uppercase-keys.eml        -- K1: "H"/"Subject"/"D" keys; accepted
                                         under -07, invalid JSON under -08 (D10)
  recipe-case-duplicate-key.eml    -- K2: "Subject" and "subject"; REJECT
  from-display-no-brackets.eml     -- T3: "From: Bron brong@test1..." (display
                                         text, no <>) is not one mailbox; REJECT

contract C9 (final review I1/I2), two faults each; the runner pins the
PRIMARY error (first in -07 §14 section order) and its state exactly:
  multi-from-tampered.eml          -- From changed after signing: §14.7 hash
                                         FAIL before the §14.8 From PERMERROR
  multi-header-and-body-tampered.eml -- Subject and body both changed: the
                                         header hash FAIL comes before the
                                         body hash FAIL (within §14.7)
  multi-expired-custody.eml        -- expired (§14.3) + mf= not under d= (§14.4)
  multi-custody-bad-signature.eml  -- mf= not under d= (§14.4) + bad signature (§14.6)
  multi-bad-signature-header-hash.eml -- bad signature (§14.6) + Subject
                                         changed after signing (§14.7)
  multi-tamper-two-instances.eml   -- m=2 and m=1 both mismatch: §14.7 goes
                                         top down, so m=2 is primary
  multi-expired-recipe-json.eml    -- malformed Recipe JSON (§14.2) + expired
  multi-expired-recipe-order.eml   -- descending "c" ranges (§14.2) + expired
  multi-expired-recipe-past-end.eml -- a copy past the end (found by the
                                         §14.7 walk) + expired: expired is primary
  multi-tamper-recipe-past-end.eml -- body cut after signing: the top body
                                         hash FAIL before the Recipe that no
                                         longer fits

contract C9 check order (perl/t/check-order.t, perl/t/spec07.t's C9 block):
  multi-signature-gap-recipe-json.eml -- i=1 missing (step h) + m=2 r= not
                                         base64 (content): the gap
  multi-instance-gap-signature-gap.eml -- m=1 and i=1 missing: m=1 (f < h)
  multi-instance-no-m-signature-twice.eml -- an instance with no m= + i=1
                                         given twice: no m= (b < e)
  multi-instance-twice-signature-no-i.eml -- m=1 twice + a signature with no
                                         i=: m=1 twice (c < d)
  multi-instance-twice-lowest.eml  -- m=2 and m=1 twice, m=2 met first: m=1
  multi-signature-twice-lowest.eml -- i=2 and i=1 twice, i=2 met first: i=1
  multi-instance-twice-junk-signature.eml -- junk "i=1;" signature + m=1
                                         twice: m=1 twice (c < e)
  multi-instance-gap-unsigned.eml  -- only m=2, no signature: m=1 missing
                                         (f < g), not "none"
  multi-instance-syntax-dup-alg.eml -- m=1 syntax error + m=2 duplicate hash
                                         algorithm: m=1 (ascending m=)
  multi-instance-dup-alg-recipe.eml -- m=2 duplicate hash algorithm + r= not
                                         base64: the algorithm (tags < Recipe)
  multi-instance-syntax-dup-selector.eml -- m=1 syntax error + i=1 duplicate
                                         selector: m=1 (instances < signatures)
  multi-header-sha512-body-sha256.eml -- h=sha256,sha512 with the sha256 body
                                         hash and the sha512 header hash wrong:
                                         -08 (D4) names the first failing set
                                         in h= order, sha256's body hash
  multi-expired-nd.eml             -- expired (§14.3) + top nd= (§14.4): expired
  multi-expired-header-hash.eml    -- expired + Subject changed: the hash FAIL
                                         (§14.7 < §14.3)
  multi-custody-header-hash.eml    -- mf= not under d= + Subject changed: the
                                         hash FAIL (§14.7 < §14.4)
  multi-body-hash-no-key.eml       -- selector with no key record + body
                                         changed: the body hash FAIL (§14.7 < §14.5)

draft -08 (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md):
  positive-control-eight-signatures.eml -- 8 s= items: at the limit; ACCEPT
  positive-control-three-same-algorithm.eml -- rsa-sha256 three times with
                                         distinct selectors (D2); ACCEPT
  positive-control-sig-group-pass.eml -- s= "bad | good" (D3); ACCEPT
  sig-group-fail.eml               -- s= "bad | bad": no group of signatures passed
  sig-group-bad-signature.eml      -- s= "good, bad": the bad selector is named
  sig-unknown-algorithm-and.eml    -- s= "good, x:mldsa44" (D8): algorithm unknown
  positive-control-sig-unknown-algorithm-or.eml -- s= "good | x:mldsa44"; ACCEPT
  sig-unknown-algorithm-only.eml   -- only mldsa44-ed25519-sha512: algorithm unknown
  sig-unknown-algorithm-not-base64.eml -- "good | x:future:@@@@": syntax error
  sig-empty-group.eml              -- "good || good": syntax error (D2)
  sig-duplicate-selector-across-groups.eml -- "sel1 | sel1": duplicate selector
  hash-group-fail.eml              -- h= "sha256(bad body) | sha512(bad
                                         header)": no group of hashes passed (D4)
  positive-control-hash-group-pass.eml -- h= "sha256(bad body) | sha512"; ACCEPT
  hash-unknown-algorithm.eml       -- h= "x-hash" only: algorithm x-hash unknown
  hash-unknown-algorithm-and.eml   -- h= "sha256, x-hash": algorithm x-hash unknown
  positive-control-hash-unknown-algorithm-or.eml -- h= "sha256 | x-hash"; ACCEPT
  hash-set-order.eml               -- h= "sha512(bad header), sha256(bad
                                         body)": sha512's header, h= order
  key-ed25519-spki.eml             -- Ed25519 key published as DER SPKI (D7):
                                         public key ed25519spki is malformed
  recipe-h-step.eml                -- Recipe h.subject[1] is invalid (D6)
  recipe-h-name-escaped.eml        -- Recipe h.x\x20caf\xC3\xA9[0] is invalid
  recipe-b-before-h.eml            -- bad b and h steps: b[1] is named first
  recipe-whole-before-step.eml     -- bad step + "h" not an object: invalid JSON
  recipe-number-exponent.eml       -- an unused "n":1e0: invalid JSON
  recipe-lone-surrogate.eml        -- a "d" string "\\udc80": invalid JSON
  auto-submitted-modified.eml      -- Auto-Submitted changed after signing (D1):
                                         header hash mismatch
  positive-control-auto-submitted.eml -- Auto-Submitted and VBR-Info, signed
                                         and unchanged; ACCEPT
  uppercase-tag.eml                -- "D=" for d= (D10): tag=d missing
  positive-control-uppercase-twin-tag.eml -- "M=2" beside m=1, "I=9" beside
                                         i=1 (D10): unknown tags; ACCEPT
  multi-key-error-above-bad-signature.eml -- i=1 bad signature + i=2 key
                                         missing: i=1's FAIL (D3 amends C9)
"""
import base64
import json
import os
import re
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
    and sign it separately with each selector's own key (-07 §10.9
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


def build_positive_three_same_algorithm():
    """POSITIVE CONTROL: s= has rsa-sha256 three times, across three
    DISTINCT selectors -- all three signatures genuinely valid.  -07 limited
    an algorithm to two items ("has more selectors than allowed"); -08
    §10.9 allows any number with distinct selectors (contract D2)."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    sig_hdr = build_multi_sig(
        [mi_hdr], [], seq=1, mi_version=1, timestamp=TS, domain=DOM,
        mailfrom=MF, rcptto=RT,
        entries=[("sel1", key("sel1")), ("sel2", key("sel2")), ("sel3", key("sel3"))],
    )
    return assemble(sig_hdr, mi_hdr, headers, body)


# The six real test1 keys, every one of which verifies.
SIX = ",".join(f"{sel}:{alg}:SIGN:{sel}" for sel, alg in (
    ("sel1", "rsa-sha256"), ("sel2", "rsa-sha256"), ("sel3", "rsa-sha256"),
    ("ed25519", "ed25519-sha256"), ("dkim2test", "rsa-sha256"),
    ("rsa1024", "rsa-sha256")))


def build_too_many():
    """Contract D3 local limit: s= with 9 items -- the six real test1 keys
    in one "," group (all verify), then "|" and three items of an
    unimplemented algorithm.  Without the limit it would pass (the first
    group does); with it, it is "has more than 8 signatures", before any
    key is fetched."""
    return _layout_message(SIX + "|a:x-alg:AAAA,b:x-alg:AAAA,c:x-alg:AAAA")


def build_positive_eight_signatures():
    """POSITIVE CONTROL: the same with 8 items (two unimplemented)."""
    return _layout_message(SIX + "|a:x-alg:AAAA,b:x-alg:AAAA")


def build_malformed_json():
    """r= decodes to malformed JSON. The bad r= is baked in BEFORE hashing
    and signing (not patched in afterwards), so the resulting two-hop
    message is genuinely, cryptographically valid throughout -- only the
    §14.2 JSON-validity check can catch it. (A post-hoc corruption would
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
    does not depend on any signer's own Recipe builder, or the raw JSON
    text as a str) and i=2 (test2)
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
    text = recipe if isinstance(recipe, str) else json.dumps(recipe, separators=(",", ":"))
    r = base64.b64encode(text.encode("utf-8")).decode()
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
    """Body Recipe whose copy ranges are out of order. -07 §5.2: "The
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


def build_positive_u_literal():
    """POSITIVE CONTROL for the "u" Recipe step (-07 §5, shared test U2):
    literals whose octets are not UTF-8 -- a Latin-1 e-acute, an EUC-KR
    Hangul pair, plus a valid UTF-8 CJK character -- carried as canonical
    base64 of the raw octets, for one header value and two body lines the hop
    removed (one of them exactly the U2 line 63 61 66 E9, "Y2Fm6Q==").
    "d" cannot carry them: JSON text is Unicode.  MUST be accepted, with the
    exact bytes restored."""
    headers, _ = load_base()
    octets = b"caf\xe9 \xb1\xa4 \xe4\xb8\xad"
    b = base64.b64encode(octets).decode()
    prev_headers = headers + [b"Comments: " + octets]
    prev_body = b"caf\xe9\r\n" + octets + b"\r\n" + CUR_BODY
    return _two_hop(prev_headers, prev_body, headers, CUR_BODY,
                    {"h": {"comments": [{"u": [b]}]},
                     "b": [{"u": ["Y2Fm6Q==", b]}, {"c": [1, 3]}]})


def build_positive_control():
    """POSITIVE CONTROL: rsa-sha256 twice, with DISTINCT selectors (sel1,
    sel2) -- §10.9 explicitly permits this (e.g. key-rotation overlap). MUST
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
    r= Recipe. -07 §12.1 explicitly permits this ("if it is wished to
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
    signature: -07 §14's "there MUST NOT be a Message-Instance field with
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
    """A Forwarder's §12.3 bridge after a real hop.

    The message arrives at test2 (i=1 rt=); test2 sends it on from test3, and
    bridges the gap with an nd= hop before signing the real hop as test3.
    §12.3 requires that extra header to be made with a key for a domain in the
    RCPT TO the message arrived with, so `bridge_domain` is what decides
    whether the chain holds.
    """
    raw = open(SRC, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    msg = ds.sign_message(raw, "sel1", "test1.dkim2.com", key("sel1", "test1.dkim2.com"),
                          mailfrom="sender@test1.dkim2.com",
                          rcptto=["user@test2.dkim2.com"], timestamp=TS)
    # Fixture builder: sign over whatever chain results, broken or not.
    msg = ds.sign_message(msg, "sel1", bridge_domain, key("sel1", bridge_domain),
                          next_domain="test3.dkim2.com", timestamp=TS,
                          skip_upstream_check=True)
    return ds.sign_message(msg, "sel1", "test3.dkim2.com", key("sel1", "test3.dkim2.com"),
                           mailfrom="srs0=x@bounce.test3.dkim2.com",
                           rcptto=["dest@test5.dkim2.com"], timestamp=TS,
                           skip_upstream_check=True)


def build_nd_bridge_wrong_domain():
    """A §12.3 bridge made with a key for a domain the message never arrived
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
    message actually arrived at. §12.3 explicitly provides for this, so it MUST
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
    Message-Instance and DKIM2-Signature fields (§12.8), so nothing else
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


def _bad_body_recipe(*a):
    r = ds.build_recipes(*a) or {}
    r["b"] = [{"c": [3, 4]}, {"c": [1, 2]}]  # descending: structurally invalid
    return r


def build_malformed_body_recipe_below_null():
    """NEGATIVE: m=2 is an ordinary hop whose body Recipe has descending copy
    ranges (malformed); m=3 records a null body Recipe, so the body Recipe
    at m=2 has no body to apply to. Recipe STRUCTURE must still be validated
    below a null. Everything is validly signed. MUST be rejected."""
    headers, body = load_base()
    h2 = _subject_prefixed(headers, b"list")
    b2 = body + b"footer\r\n"
    h3 = _subject_prefixed(h2, b"again")
    return _null_body_chain([
        (headers, body),
        (h2, b2, _bad_body_recipe),
        (h3, b2 + b"rewritten\r\n", _null_body_recipe),
    ])


def build_duplicate_mi_version():
    """NEGATIVE: a valid i=1/m=1 chain with a second Message-Instance header
    that also says m=1. The copy is byte-identical to the signed one, so every
    hash and signature still checks; only the rule that each m= occurs once
    (a duplicate is a PERMERROR) can reject it. A verifier that keys its
    instances by m= silently keeps one and accepts."""
    headers, body = load_base()
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    priv, alg = ds.load_private_key(key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [], [], mi1, DOM, "sel1", priv, alg,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS)
    out = sig1.encode() + b"\r\n" + mi1.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in headers:
        out += h + b"\r\n"
    return out + b"\r\n" + body


def build_positive_unreferenced_lower_mi():
    """POSITIVE CONTROL: what Mailman emits for an unsigned post: an unsigned
    m=1 over the message as received and an m=2 (with a real Recipe) over the
    list's output, and a single signature i=1 that covers m=2.  m=1 is
    referenced by no signature, but -07 §14 forbids only an instance whose
    m= is HIGHER than every signature's m=.  MUST be accepted."""
    headers, body = load_base()
    h2, b2 = _subject_prefixed(headers, b"list"), body + b"footer\r\n"
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    mi2 = ds.build_message_instance(h2, b2, version=2, algs=["sha256"],
                                    recipe=ds.build_recipes(headers, body, h2, b2))
    priv, alg = ds.load_private_key(key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [mi1], [], mi2, DOM, "sel1", priv, alg,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=2, timestamp=TS)
    out = sig1.encode() + b"\r\n" + mi2.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in h2:
        out += h + b"\r\n"
    return out + b"\r\n" + b2


def _gap_chain(sig2_seq, mi2_version, sig2_m=None):
    """Two real hops (m=1/i=1 by test1, then a Subject-tag + footer hop by
    test2) built with the second hop's i= and m= forced to the given values.
    build_dkim2_signature takes seq/mi_version directly, so the second hop is
    GENUINELY signed over a chain that never contained the skipped number:
    its signature covers exactly the headers present.  Hashes, Recipe and
    signatures are all valid; only the numbering has a hole."""
    headers, body = load_base()
    h2, b2 = _subject_prefixed(headers, b"list"), body + b"footer\r\n"
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    priv1, alg1 = ds.load_private_key(key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [], [], mi1, DOM, "sel1", priv1, alg1,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS)
    mi2 = ds.build_message_instance(h2, b2, version=mi2_version, algs=["sha256"],
                                    recipe=ds.build_recipes(headers, body, h2, b2))
    dom2 = "test2.dkim2.com"
    priv2, alg2 = ds.load_private_key(key("sel1", dom2))
    sig2 = ds.build_dkim2_signature(
        [mi1], [sig1], mi2, dom2, "sel1", priv2, alg2,
        mailfrom="relay@test2.dkim2.com", rcptto=["final@example.com"],
        seq=sig2_seq, mi_version=mi2_version if sig2_m is None else sig2_m,
        timestamp=TS + 100)
    out = sig2.encode() + b"\r\n" + sig1.encode() + b"\r\n"
    out += mi2.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in h2:
        out += h + b"\r\n"
    return out + b"\r\n" + b2


def build_signature_gap():
    """NEGATIVE: DKIM2-Signature i=1 and i=3, no i=2 (Message-Instance m=1,
    m=2, consecutive).  i=3 is genuinely signed over the chain as it stands
    (it never contained an i=2), its m=2 Recipe and hashes are right, and
    d=/rt= adjacency holds.  Only the missing i=2 is wrong: a chain of
    custody with a hole.  MUST be rejected."""
    return _gap_chain(sig2_seq=3, mi2_version=2)


def build_instance_gap():
    """NEGATIVE: Message-Instance m=1 and m=3, no m=2 (signatures i=1, i=2,
    consecutive).  The m=3 Recipe undoes straight to the m=1 state, so every
    hash checks, and i=2 (m=3) genuinely signs the headers present.  Only
    the missing m=2 is wrong.  MUST be rejected."""
    return _gap_chain(sig2_seq=2, mi2_version=3)


def _with_unkeyable_signature(fake):
    """POSITIVE CONTROL null-body chain (every signature and hash valid) with
    one extra DKIM2-Signature prepended that names m=2 but has no i= a
    verifier can key.  Silently skipping it would ACCEPT; it MUST be a
    PERMERROR.  (A signer gate counting coverage by m= was fooled by exactly
    this when the verifier ignored it.)"""
    return fake + b"\r\n" + build_positive_null_body()


def build_unkeyable_signature_no_i():
    return _with_unkeyable_signature(b"DKIM2-Signature: m=2; d=evil.example")


def build_unkeyable_signature_i_abc():
    return _with_unkeyable_signature(b"DKIM2-Signature: i=abc; m=2; d=evil.example")


def build_lone_junk_signature():
    """NEGATIVE: an otherwise unsigned message whose only DKIM2 field is a
    junk "DKIM2-Signature: m=1; d=evil.example" (no i=).  It is a PERMERROR
    like any other unkeyable signature -- not "no DKIM2 here", and certainly
    not a pass: a checker whose walk is driven by the i= values it can read
    sees no chain at all and has nothing to fail."""
    return b"DKIM2-Signature: m=1; d=evil.example\r\n" + open(SRC, "rb").read()


# Every i= and m= is a chain number: 1*DIGIT, at most three digits naming
# 1..MAX_CHAIN_NUMBER (100), and no more than MAX_CHAIN_LENGTH (32), in every
# implementation here.  Anything else is a PERMERROR before any gap/contiguity check walks
# 1..max -- which, for i=99999999999999999999, crashed Perl ("Range iterator
# outside integer range"), ran the browser verifier out of memory, and was
# undefined behaviour in C's atoi().  These chains are otherwise genuinely
# signed: _gap_chain signs the second hop with exactly these numbers.
HUGE = 99999999999999999999


def build_signature_i_33():
    return _gap_chain(sig2_seq=33, mi2_version=2)


def build_signature_i_101():
    return _gap_chain(sig2_seq=101, mi2_version=2)


def build_signature_i_huge():
    return _gap_chain(sig2_seq=HUGE, mi2_version=2)


def build_signature_m_huge():
    return _gap_chain(sig2_seq=2, mi2_version=2, sig2_m=4294967297)


def build_instance_m_huge():
    # The signature says m=2, so the out-of-range number is the instance's.
    return _gap_chain(sig2_seq=2, mi2_version=HUGE, sig2_m=2)


# A duplicate key anywhere in the Recipe JSON is a PERMERROR ("contains
# invalid JSON"): parsers disagree on which value wins (C took the first,
# the others the last), so {"b":[...],"b":null} meant a null body Recipe to
# some verifiers and gates and a real one to others.  Each vector is a
# genuine two-hop chain (Subject tag + footer, real Recipes, signed i=2)
# whose r= JSON text carries the duplicate; either reading of it verifies.
def _recipe_json_with_duplicate(recipe, where):
    """The Recipe as JSON text with one duplicated key (see above)."""
    h = json.dumps(recipe["h"], separators=(",", ":"))
    b = json.dumps(recipe["b"], separators=(",", ":"))
    if where == "b-null-last":
        return '{"h":%s,"b":%s,"b":null}' % (h, b)
    if where == "b-null-first":
        return '{"b":null,"h":%s,"b":%s}' % (h, b)
    if where == "h":
        k = next(iter(recipe["h"]))
        v = json.dumps(recipe["h"][k], separators=(",", ":"))
        inner = h[1:-1]
        return '{"h":{%s,"%s":%s},"b":%s}' % (inner, k, v, b)
    raise ValueError(where)


def duplicate_key_mi(h1, b1, h2, b2, version, where):
    """Message-Instance m=<version> over (h2, b2) with real Recipes back to
    (h1, b1), its r= JSON carrying a duplicate key."""
    recipe = ds._lowercase_recipe_keys(ds.build_recipes(h1, b1, h2, b2))
    mi = ds.build_message_instance(h2, b2, version=version, algs=["sha256"],
                                   recipe=recipe)
    dup = base64.b64encode(
        _recipe_json_with_duplicate(recipe, where).encode()).decode()
    head, sep, _ = mi.partition("; r=")
    assert sep
    return f"{head}; r={dup}"


def _duplicate_key_chain(where):
    headers, body = load_base()
    h2, b2 = _subject_prefixed(headers, b"list"), body + b"footer\r\n"
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    priv1, alg1 = ds.load_private_key(key("sel1"))
    sig1 = ds.build_dkim2_signature(
        [], [], mi1, DOM, "sel1", priv1, alg1,
        mailfrom=MF, rcptto=RT, seq=1, mi_version=1, timestamp=TS)
    mi2 = duplicate_key_mi(headers, body, h2, b2, 2, where)
    dom2 = "test2.dkim2.com"
    priv2, alg2 = ds.load_private_key(key("sel1", dom2))
    sig2 = ds.build_dkim2_signature(
        [mi1], [sig1], mi2, dom2, "sel1", priv2, alg2,
        mailfrom="relay@test2.dkim2.com", rcptto=["final@example.com"],
        seq=2, mi_version=2, timestamp=TS + 100)
    out = sig2.encode() + b"\r\n" + sig1.encode() + b"\r\n"
    out += mi2.encode() + b"\r\n" + mi1.encode() + b"\r\n"
    for h in h2:
        out += h + b"\r\n"
    return out + b"\r\n" + b2


def build_recipe_duplicate_b_null_last():
    return _duplicate_key_chain("b-null-last")


def build_recipe_duplicate_b_null_first():
    return _duplicate_key_chain("b-null-first")


def build_recipe_duplicate_h_key():
    return _duplicate_key_chain("h")


# Not 1*DIGIT: "4294967297x" is malformed, never its digit prefix (which the
# browser verifier's parseInt and C's atoi took, and walked 1..max to).
def build_signature_m_malformed():
    return _gap_chain(sig2_seq=2, mi2_version=2, sig2_m="4294967297x")


def build_instance_m_malformed():
    return _gap_chain(sig2_seq=2, mi2_version="4294967297x", sig2_m=2)


# ---------------------------------------------------------------------------
# draft -07 vectors (shared tests C1-C6, A1/A2, U2-U4, K1/K2 in common.md).
# Test domains map: example.com -> test1.dkim2.com, example.org ->
# test2.dkim2.com, lists.example.org -> lists.test2.dkim2.com, mail.example.org
# -> mail.test2.dkim2.com (dns.json carries test2's sel1 key for it),
# fwd.example.net -> test3.dkim2.com, other.net/other.example -> test3/test4,
# elsewhere.net -> test5.dkim2.com.
# ---------------------------------------------------------------------------

def _mi_raw(headers, body, m, recipe=None):
    """Message-Instance m=<m> over (headers, body).  `recipe` is a dict
    (encoded as given: key case is preserved) or raw JSON text."""
    hh = ds.b64(ds.compute_header_hash(headers, "sha256"))
    bh = ds.b64(ds.compute_body_hash(body, "sha256"))
    v = f"Message-Instance: m={m}; h=sha256:{hh}:{bh}"
    if recipe is not None:
        text = recipe if isinstance(recipe, str) else json.dumps(recipe, separators=(",", ":"))
        v += f"; r={base64.b64encode(text.encode()).decode()}"
    return v + ";"


def _chain(states, hops, ts=TS):
    """A chain over message states.  states[k-1] is (headers, body, recipe)
    for m=k.  hops[i-1] is a dict for DKIM2-Signature i: d, m, and either
    mf + rt (a list) or nd; "key" names the key's domain when it differs from
    d.  Every hash and signature is valid; only custody/From is under test.
    `ts` is i=1's t= (the multi-fault vectors give a real expired one)."""
    mis = [_mi_raw(h, b, k, r) for k, (h, b, r) in enumerate(states, 1)]
    sigs = []
    for i, hop in enumerate(hops, 1):
        m = hop["m"]
        priv, alg = ds.load_private_key(key("sel1", hop.get("key", hop["d"])))
        sigs.append(ds.build_dkim2_signature(
            mis[:m - 1], sigs, mis[m - 1], hop["d"], "sel1", priv, alg,
            mailfrom=hop.get("mf", ""), rcptto=hop.get("rt"), seq=i,
            mi_version=m, timestamp=ts + 100 * (i - 1),
            next_domain=hop.get("nd")))
    top_h, top_b = states[-1][0], states[-1][1]
    out = b"".join(x.encode() + b"\r\n" for x in reversed(sigs))
    out += b"".join(x.encode() + b"\r\n" for x in reversed(mis))
    for h in top_h:
        out += h + b"\r\n"
    return out + b"\r\n" + top_b


def _one_state():
    h, b = load_base()
    return [(h, b, None)]


def _bounce(d2):
    """C1/C2: i=1 test1 -> a list address under test2 (uppercase, trailing
    dot, as Postfix may record it); i=2 by <d2> with mf=<> back to the
    author (a bounce)."""
    return _chain(_one_state(), [
        dict(d=DOM, m=1, mf=MF, rt=["<list@Lists.Test2.DKIM2.com.>"]),
        dict(d=d2, m=1, mf="", rt=[MF]),
    ])


def build_positive_custody_bounce():
    return _bounce("test2.dkim2.com")


def build_custody_bounce_d_mismatch():
    return _bounce("test3.dkim2.com")


def _nd_hops(rt1, d2, d3):
    """C3/C4: i=1 test1 rt=<rt1>; i=2 an nd= hop by <d2> naming
    test3.dkim2.com; i=3 by <d3>."""
    return _chain(_one_state(), [
        dict(d=DOM, m=1, mf=MF, rt=[rt1]),
        dict(d=d2, key="test2.dkim2.com", m=1, nd="test3.dkim2.com"),
        dict(d=d3, m=1, mf=f"b@{d3}", rt=["dest@test5.dkim2.com"]),
    ])


def build_positive_nd_subdomain_rt():
    return _nd_hops("x@mail.test2.dkim2.com", "test2.dkim2.com", "test3.dkim2.com")


def build_nd_subdomain_swapped():
    return _nd_hops("x@test2.dkim2.com", "mail.test2.dkim2.com", "test3.dkim2.com")


def build_nd_next_hop_mismatch():
    return _nd_hops("x@mail.test2.dkim2.com", "test2.dkim2.com", "test4.dkim2.com")


def build_custody_mf_domain_literal():
    """C5: i=1 rt=<x@[192.0.2.1]>, i=2 mf=<y@[192.0.2.1]>: a domain literal
    never relaxed-matches anything."""
    return _chain(_one_state(), [
        dict(d=DOM, m=1, mf=MF, rt=["x@[192.0.2.1]"]),
        dict(d="test2.dkim2.com", m=1, mf="y@[192.0.2.1]", rt=["final@test5.dkim2.com"]),
    ])


def build_mf_d_mismatch():
    """C6: i=1 d=test1 with mf= in test2."""
    return _chain(_one_state(), [
        dict(d=DOM, m=1, mf="a@test2.dkim2.com", rt=RT),
    ])


def build_from_not_authentic():
    """A1: From brong@test1.dkim2.com, but i=1 is d=test2.dkim2.com."""
    return _chain(_one_state(), [
        dict(d="test2.dkim2.com", m=1, mf="x@test2.dkim2.com", rt=["user@test3.dkim2.com"]),
    ])


def build_positive_from_folded_2047():
    """A1 review focus: a From folded over two lines with an RFC 2047
    display name and an angle-addr is one mailbox, Authentic for test1."""
    h, b = load_base()
    h = [b"From: =?utf-8?q?Caf=C3=A9?=\r\n <brong@test1.dkim2.com>"
         if x.lower().startswith(b"from:") else x for x in h]
    return _chain([(h, b, None)], [dict(d=DOM, m=1, mf=MF, rt=RT)])


def _from_changed(new_from):
    """A2: i=1 test1; a list under test2 rewrites From in m=2 (Recipe has a
    "from" key) and signs i=2 d=test2.dkim2.com m=2."""
    h1, b1 = load_base()
    h2 = [b"From: " + new_from if x.lower().startswith(b"from:") else x for x in h1]
    return _chain([(h1, b1, None), (h2, b1, ds.build_recipes(h1, b1, h2, b1))], [
        dict(d=DOM, m=1, mf=MF, rt=["list@lists.test2.dkim2.com"]),
        dict(d="test2.dkim2.com", m=2, mf="list-bounces@lists.test2.dkim2.com",
             rt=["user@test5.dkim2.com"]),
    ])


def build_positive_from_changed():
    return _from_changed(b"\"Bron Gondwana via list\" <list@lists.test2.dkim2.com>")


def build_from_changed_not_authentic():
    return _from_changed(b"x@test5.dkim2.com")


def build_positive_ingress_from_rewritten():
    """Ruling 19 (contract C5 corrected): an unsigned ingress m=1 carrying
    the author's From (test5, a domain no signature here holds); the list
    under test2 rewrites From in m=2 and signs i=1 over m=2.  The author's
    From was replaced before any signature covered it, so it is never
    checked; the From at state m(i=1) = 2 is the list's.  MUST be accepted."""
    h1, b1 = load_base()
    h1 = [b"From: A <a@test5.dkim2.com>" if x.lower().startswith(b"from:") else x for x in h1]
    h2 = [b'From: "A via list" <list@lists.test2.dkim2.com>'
          if x.lower().startswith(b"from:") else x for x in h1]
    return _chain([(h1, b1, None), (h2, b1, ds.build_recipes(h1, b1, h2, b1))], [
        dict(d="test2.dkim2.com", m=2, mf="list-bounces@lists.test2.dkim2.com",
             rt=["user@test5.dkim2.com"]),
    ])


def build_from_not_authentic_at_signed_state():
    """Ruling 19: i=1 covers m=2, and the From at state 2 (unchanged from
    the author's, test1) is not Authentic for i=1's d=test2.  REJECT with
    "i=1 matching From is not authentic"."""
    h1, b1 = load_base()
    h2 = _subject_prefixed(h1, b"list")
    return _chain([(h1, b1, None), (h2, b1, ds.build_recipes(h1, b1, h2, b1))], [
        dict(d="test2.dkim2.com", m=2, mf="list-bounces@lists.test2.dkim2.com",
             rt=["user@test5.dkim2.com"]),
    ])


def build_recipe_u_nonzero_pad():
    """U3: "QR==" fails the zero-pad-bits pattern (it would decode to "A")."""
    headers, _ = load_base()
    return _two_hop(headers, b"A\r\n" + CUR_BODY, headers, CUR_BODY,
                    {"b": [{"u": ["QR=="]}, {"c": [1, 3]}]})


def build_recipe_b_step():
    """U4: the -06 "b" step key is now an unknown key."""
    headers, _ = load_base()
    return _two_hop(headers, b"x\r\n" + CUR_BODY, headers, CUR_BODY,
                    {"b": [{"b": ["eA=="]}, {"c": [1, 3]}]})


def build_recipe_two_step_keys():
    """U4: a step object with two keys."""
    headers, _ = load_base()
    return _two_hop(headers, b"alpha\r\nx\r\nbeta\r\ngamma\r\n", headers, CUR_BODY,
                    {"b": [{"c": [1, 1], "d": ["x"]}, {"c": [2, 3]}]})


def build_recipe_empty_step():
    """U4: an empty step object."""
    headers, _ = load_base()
    return _two_hop(headers, CUR_BODY, headers, CUR_BODY,
                    {"b": [{}, {"c": [1, 3]}]})


def _subject_hop():
    h1, b1 = load_base()
    h2 = _subject_prefixed(h1, b"list")
    return h1, b1, h2, ds.build_recipes(h1, b1, h2, b1)


def build_recipe_uppercase_keys():
    """K1: the same Recipe with every key in upper/mixed case ("H",
    "Subject", "D").  -07 (decision 2) accepted it; -08 (contract D10)
    requires lowercase keys: "contains invalid JSON"."""
    h1, b1, h2, r = _subject_hop()
    up = {"H": {name.title(): [{k.upper(): v for k, v in step.items()} for step in steps]
                for name, steps in r["h"].items()}}
    return _two_hop(h1, b1, h2, b1, up)


def build_recipe_case_duplicate_key():
    """K2: "Subject" and "subject" in one "h" object are a duplicate."""
    h1, b1, h2, r = _subject_hop()
    steps = next(iter(r["h"].values()))
    return _two_hop(h1, b1, h2, b1, {"h": {"Subject": steps, "subject": []}})


# Multi-fault vectors (contract C9, final review I1/I2): two faults at
# once, so the runner can pin which one is the PRIMARY error -- the first in
# -07 §14 section order -- and its state, exactly.  A single-fault vector
# cannot tell a verifier that checks From before the hashes from one that
# checks it after.

def _replace_header(msg, name, value):
    """`msg` with the first header field `name` (no colon) replaced by
    `name: value` (no other change), after signing."""
    head, sep, body = msg.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    for k, line in enumerate(lines):
        if line.lower().startswith(name.lower() + b":"):
            j = k + 1
            while j < len(lines) and lines[j][:1] in (b" ", b"\t"):
                j += 1
            lines[k:j] = [name + b": " + value]
            break
    else:
        raise ValueError(f"no {name!r} header field")
    return b"\r\n".join(lines) + sep + body


def _corrupt_signature(msg, i=1):
    """`msg` with DKIM2-Signature i=<i>'s first signature value changed in
    one base64 character mid-value: still valid base64, still the right
    length, but the signature no longer verifies (§14.6)."""
    head, sep, body = msg.partition(b"\r\n\r\n")
    want = f"DKIM2-Signature: i={i};".encode()
    start = head.index(want)
    end = head.find(b"\r\nDKIM2-Signature:", start + 1)
    end = len(head) if end < 0 else end
    field = head[start:end]
    at = field.index(b":rsa-sha256:") + len(b":rsa-sha256:") + 20
    c = b"B" if field[at:at + 1] == b"A" else b"A"
    field = field[:at] + c + field[at + 1:]
    return head[:start] + field + head[end:] + sep + body


def build_multi_from_tampered():
    """A validly signed message whose From was then changed to a domain no
    signature holds.  Both the m=1 header hash (§14.7) and From Authentic
    (§14.8) fail; the primary error is the hash FAIL."""
    return _replace_header(build_positive_control(), b"From", b"brong@evil.example")


def build_multi_header_and_body_tampered():
    """A validly signed message whose Subject AND body were then changed.
    Both m=1 hashes fail; within §14.7 every verifier checks the header
    hash first, so the primary error is the header hash FAIL."""
    msg = _replace_header(build_positive_control(), b"Subject", b"tampered")
    head, sep, _body = msg.partition(b"\r\n\r\n")
    return head + sep + b"tampered body\r\n"


def build_multi_expired_custody():
    """i=1 made 30 days ago (expired, §14.3) whose mf= is not under its d=
    (Chain of Custody, §14.4).  The primary error is "signature expired".
    Verified WITH the timestamp check (the runner's real-clock vectors)."""
    import time
    return _chain(_one_state(), [
        dict(d=DOM, m=1, mf="a@test2.dkim2.com", rt=RT),
    ], ts=int(time.time()) - 30 * 86400)


def build_multi_custody_bad_signature():
    """mf= not under d= (§14.4) and a signature that does not verify
    (§14.6).  The primary error is the custody PERMERROR."""
    return _corrupt_signature(build_mf_d_mismatch())


def build_multi_bad_signature_header_hash():
    """A signature that does not verify (§14.6) on a message whose Subject
    changed after signing (§14.7).  The primary error is the selector FAIL."""
    msg = _chain(_one_state(), [dict(d=DOM, m=1, mf=MF, rt=RT)])
    return _replace_header(_corrupt_signature(msg), b"Subject", b"tampered")


def build_multi_tamper_two_instances():
    """A two-instance chain (positive-control-from-changed) whose Subject
    changed after the top signature: m=2 and m=1 both mismatch.  §14.7 is
    walked top down (a lower instance is rebuilt from the one above it), so
    the primary error is the top instance's, m=2."""
    return _replace_header(build_positive_from_changed(), b"Subject", b"Tampered")


# Recipe errors and C9.  A Recipe that is malformed on its own (its JSON,
# the §5 schema, "c" ranges out of order) is a §14.2 error of the field and
# comes before everything else; one that only fails against the message (a
# copy past the end) is found by the §14.7 chain walk, and ranks there.

def build_multi_expired_recipe_json():
    """Malformed Recipe JSON at m=2 (§14.2) on expired signatures (§14.3,
    the fixed t= is weeks old): the Recipe error is primary."""
    return build_malformed_json()


def build_multi_expired_recipe_order():
    """Descending "c" ranges at m=2 (§14.2, no message needed) on expired
    signatures: the Recipe error is primary."""
    return build_recipe_descending()


def build_multi_expired_recipe_past_end():
    """m=2's body Recipe copies lines 1-10 of a 3-line body: it fits the
    schema and only fails against the message, so the walk (§14.7) finds
    it, after the expired signature (§14.3), which is primary."""
    headers, _ = load_base()
    return _two_hop(headers, b"a\r\nb\r\n", headers, CUR_BODY, {"b": [{"c": [1, 10]}]})


def build_multi_tamper_recipe_past_end():
    """A valid two-hop chain (m=2's Recipe copies lines 1-2 of the body)
    whose body was cut to one line after signing: the top body hash fails
    (§14.7) before the walk can apply m=2's Recipe, which no longer fits.
    The primary error is the hash FAIL."""
    headers, _ = load_base()
    msg = _two_hop(headers, b"alpha\r\nbeta\r\n", headers, CUR_BODY, {"b": [{"c": [1, 2]}]})
    head, sep, _ = msg.partition(b"\r\n\r\n")
    return head + sep + b"alpha\r\n"


# C9 check order (perl/t/check-order.t and the C9 block of perl/t/spec07.t):
# more two-fault vectors.  §14.2 STRUCTURE (what the fields' names and m=/i=
# numbers decide, steps a..h) comes before §14.2 CONTENT; instances by
# ascending m= before signatures; within §14.7 the header hashes in h= order
# before any body hash; and the Message-Instances (§14.7 included) before
# §14.3, §14.4 and §14.5.  Every field a signature covers is signed as it
# stands (malformed or not), so nothing but the two named faults is wrong.

def _order_states():
    """Two states: the base message (m=1) and a Subject-tag + footer hop
    (m=2, with its real Recipe)."""
    h1, b1 = load_base()
    h2, b2 = _subject_prefixed(h1, b"list"), b1 + b"footer\r\n"
    return (h1, b1), (h2, b2, ds.build_recipes(h1, b1, h2, b2))


def _order_sign(mis, below, i, m, d=DOM, mf=MF, rt=RT, sel="sel1", ts=TS):
    """DKIM2-Signature i=<i> m=<m> signed with d's sel1 key (named `sel` in
    the field) over exactly the instance fields `mis` and the signature
    fields `below`, as they stand."""
    priv, alg = ds.load_private_key(key("sel1", d))
    return ds.build_dkim2_signature(
        mis, below, None, d, sel, priv, alg,
        mailfrom=mf, rcptto=rt, seq=i, mi_version=m, timestamp=ts)


def _order_message(fields, headers, body):
    """`fields` (DKIM2 fields, top first, as str or bytes) over the message."""
    out = b"".join((f if isinstance(f, bytes) else f.encode()) + b"\r\n" for f in fields)
    out += b"".join(h + b"\r\n" for h in headers)
    return out + b"\r\n" + body


def _order_two_hop():
    """The fields of a valid two-hop chain, ([sig2, sig1], [mi2, mi1]),
    and the top state's headers and body."""
    (h1, b1), (h2, b2, r) = _order_states()
    mi1, mi2 = _mi_raw(h1, b1, 1), _mi_raw(h2, b2, 2, r)
    sig1 = _order_sign([mi1], [], 1, 1)
    sig2 = _order_sign([mi1, mi2], [sig1], 2, 2, d="test2.dkim2.com",
                       mf="relay@test2.dkim2.com", rt=["final@example.com"])
    return [sig2, sig1], [mi2, mi1], h2, b2


def _with_r(mi, r):
    """Message-Instance field `mi` (no r= yet) with r=<r> added as written."""
    return mi[:-1] + f"; r={r};"


def _dup_alg(mi):
    """Message-Instance field `mi` with its sha256 hash set given twice."""
    return re.sub(r"h=(sha256:[^;]*)", r"h=\1,\1", mi, count=1)


def build_multi_signature_gap_recipe_json():
    """i=1 missing (§14.2 structure, step h) + m=2's r= not base64 (§14.2
    content): the gap is primary.  i=2 is signed over the chain as sent."""
    (h1, b1), (h2, b2, _r) = _order_states()
    mi1, mi2 = _mi_raw(h1, b1, 1), _with_r(_mi_raw(h2, b2, 2), "!!!!")
    sig2 = _order_sign([mi1, mi2], [], 2, 2, d="test2.dkim2.com",
                       mf="relay@test2.dkim2.com", rt=["final@example.com"])
    return _order_message([sig2, mi2, mi1], h2, b2)


def build_multi_instance_gap_signature_gap():
    """m=1 and i=1 both missing (steps f and h): "m=1 missing" is primary."""
    _s1, (h2, b2, r) = _order_states()
    mi2 = _mi_raw(h2, b2, 2, r)
    sig2 = _order_sign([mi2], [], 2, 2, d="test2.dkim2.com",
                       mf="relay@test2.dkim2.com", rt=["final@example.com"])
    return _order_message([sig2, mi2], h2, b2)


def build_multi_instance_no_m_signature_twice():
    """A Message-Instance with no m= (step b) + DKIM2-Signature i=1 given
    twice (step e): the instance with no m= is primary."""
    headers, body = load_base()
    mi1 = _mi_raw(headers, body, 1)
    sig1 = _order_sign([mi1], [], 1, 1)
    return _order_message(["Message-Instance: h=sha256:AAAA:BBBB;", sig1, sig1, mi1],
                          headers, body)


def build_multi_instance_twice_signature_no_i():
    """Message-Instance m=1 given twice (step c) + a DKIM2-Signature with no
    i= (step d): the m= given twice is primary."""
    headers, body = load_base()
    mi1 = _mi_raw(headers, body, 1)
    sig1 = _order_sign([mi1], [], 1, 1)
    return _order_message(["DKIM2-Signature: m=1; d=test1.dkim2.com;", sig1, mi1, mi1],
                          headers, body)


def build_multi_instance_twice_lowest():
    """m=2 and m=1 both given twice, m=2's copy met first (step c): the
    LOWEST m= given twice, m=1, is primary."""
    sigs, (mi2, mi1), h, b = _order_two_hop()
    return _order_message([mi2] + sigs + [mi2, mi1, mi1], h, b)


def build_multi_signature_twice_lowest():
    """i=2 and i=1 both given twice, i=2's copy met first (step e): the
    LOWEST i= given twice, i=1, is primary."""
    (sig2, sig1), mis, h, b = _order_two_hop()
    return _order_message([sig2, sig2, sig1, sig1] + mis, h, b)


def build_multi_instance_twice_junk_signature():
    """A junk "DKIM2-Signature: i=1;" (i=1 given twice, step e) + m=1 given
    twice (step c): the m= given twice is primary."""
    headers, body = load_base()
    mi1 = _mi_raw(headers, body, 1)
    sig1 = _order_sign([mi1], [], 1, 1)
    return _order_message(["DKIM2-Signature: i=1;", sig1, mi1, mi1], headers, body)


def build_multi_instance_gap_unsigned():
    """Only a Message-Instance m=2 and no signature: m=1 missing (step f)
    and m=2 not signed (step g).  The gap is primary -- and a message with
    a DKIM2 field is never "none"."""
    _s1, (h2, b2, r) = _order_states()
    return _order_message([_mi_raw(h2, b2, 2, r)], h2, b2)


def build_multi_instance_syntax_dup_alg():
    """m=1 a tag-list syntax error (";;") + m=2 a duplicate hash algorithm,
    both signed as they stand: content by ascending m=, so m=1's syntax
    error is primary."""
    (h1, b1), (h2, b2, r) = _order_states()
    mi1 = _mi_raw(h1, b1, 1) + ";"
    mi2 = _dup_alg(_mi_raw(h2, b2, 2, r))
    sig1 = _order_sign([mi1], [], 1, 1)
    sig2 = _order_sign([mi1, mi2], [sig1], 2, 2, d="test2.dkim2.com",
                       mf="relay@test2.dkim2.com", rt=["final@example.com"])
    return _order_message([sig2, sig1, mi2, mi1], h2, b2)


def build_multi_instance_dup_alg_recipe():
    """m=2 with a duplicate hash algorithm AND an r= that is not base64:
    within one instance the duplicate algorithm comes before its Recipe."""
    (h1, b1), (h2, b2, _r) = _order_states()
    mi1 = _mi_raw(h1, b1, 1)
    mi2 = _with_r(_dup_alg(_mi_raw(h2, b2, 2)), "!!!!")
    sig1 = _order_sign([mi1], [], 1, 1)
    sig2 = _order_sign([mi1, mi2], [sig1], 2, 2, d="test2.dkim2.com",
                       mf="relay@test2.dkim2.com", rt=["final@example.com"])
    return _order_message([sig2, sig1, mi2, mi1], h2, b2)


def build_multi_instance_syntax_dup_selector():
    """m=1 a tag-list syntax error + i=1 a duplicate selector (both entries
    genuinely signed): instances before signatures, so m=1 is primary."""
    headers, body = load_base()
    mi1 = _mi_raw(headers, body, 1) + ";"
    sig1 = build_multi_sig([mi1], [], seq=1, mi_version=1, timestamp=TS, domain=DOM,
                           mailfrom=MF, rcptto=RT,
                           entries=[("sel1", key("sel1")), ("sel1", key("sel1"))])
    return _order_message([sig1, mi1], headers, body)


def build_multi_header_sha512_body_sha256():
    """One instance with h=sha256:..,sha512:.. whose sha256 BODY hash and
    sha512 HEADER hash are both wrong (the instance is signed as it stands).
    Every header hash comes before any body hash, so the sha512 header hash
    is primary, though sha256 is listed first."""
    headers, body = load_base()
    mi1 = ds.build_message_instance(headers, body, version=1, algs=["sha256", "sha512"])

    def flip(b64v):
        return ("B" if b64v[0] == "A" else "A") + b64v[1:]
    mi1 = re.sub(r"sha256:([^:]+):([^,;]+)", lambda x: f"sha256:{x[1]}:{flip(x[2])}", mi1)
    mi1 = re.sub(r"sha512:([^:]+):([^,;]+)", lambda x: f"sha512:{flip(x[1])}:{x[2]}", mi1)
    sig1 = _order_sign([mi1], [], 1, 1)
    return _order_message([sig1, mi1], headers, body)


def _expired_ts():
    import time
    return int(time.time()) - 30 * 86400


def build_multi_expired_nd():
    """i=1 made 30 days ago (§14.3) carrying an nd= on the top signature
    (§14.4: the next hop never signed): "signature expired" is primary."""
    return _chain(_one_state(), [
        dict(d=DOM, m=1, nd="test3.dkim2.com"),
    ], ts=_expired_ts())


def build_multi_expired_header_hash():
    """An expired i=1 (§14.3) on a message whose Subject changed after
    signing (§14.7): the hash FAIL is primary."""
    msg = _chain(_one_state(), [dict(d=DOM, m=1, mf=MF, rt=RT)], ts=_expired_ts())
    return _replace_header(msg, b"Subject", b"tampered")


def build_multi_custody_header_hash():
    """i=1's mf= not under its d= (§14.4) on a message whose Subject changed
    after signing (§14.7): the hash FAIL is primary."""
    return _replace_header(build_mf_d_mismatch(), b"Subject", b"tampered")


def _too_many_fields(n_mi, n_sig):
    """A valid one-hop message with its Message-Instance written n_mi times
    and its DKIM2-Signature n_sig times: more than 32 of either is §14.2
    step a, before the duplicate numbers (c, e) the copies also are."""
    headers, body = load_base()
    mi_hdr = ds.build_message_instance(headers, body, version=1, algs=["sha256"])
    sig_hdr = build_multi_sig(
        [mi_hdr], [], seq=1, mi_version=1, timestamp=TS, domain=DOM,
        mailfrom=MF, rcptto=RT, entries=[("sel1", key("sel1"))],
    )
    out = (sig_hdr.encode() + b"\r\n") * n_sig + (mi_hdr.encode() + b"\r\n") * n_mi
    for h in headers:
        out += h + b"\r\n"
    return out + b"\r\n" + body


def build_too_many_instance_fields():
    return _too_many_fields(33, 33)


def build_too_many_signature_fields():
    return _too_many_fields(1, 33)


def build_multi_body_hash_no_key():
    """i=1 names selector "nokey", which has no key record (§14.5; the
    signature itself is made with sel1's key), on a message whose body
    changed after signing (§14.7): the body hash FAIL is primary, and no
    key need be fetched."""
    headers, body = load_base()
    mi1 = _mi_raw(headers, body, 1)
    sig1 = _order_sign([mi1], [], 1, 1, sel="nokey")
    return _order_message([sig1, mi1], headers, b"changed\r\n")


def build_from_display_no_brackets():
    """T3: "From: Bron brong@test1.dkim2.com" -- display text with no angle
    brackets is not one mailbox (RFC 5322 name-addr needs the <>), so From
    is not Authentic even though the address is test1's and i=1 is d=test1."""
    h, b = load_base()
    h = [b"From: Bron brong@test1.dkim2.com" if x.lower().startswith(b"from:") else x for x in h]
    return _chain([(h, b, None)], [dict(d=DOM, m=1, mf=MF, rt=RT)])



# ---------------------------------------------------------------------------
# draft -08 (docs/superpowers/specs/2026-10-28-dkim2-spec-08-design.md)
# ---------------------------------------------------------------------------

_LAYOUT_ITEM = re.compile(r"([^\s:,|]+)(\s*:\s*)([^\s:,|]+)(\s*:)(SIGN:[\w-]+|[^,|;]*)")


def _layout_sig(mis, below, s_layout, seq=1, m=1, d=DOM, mf=MF, rt=RT, ts=TS,
                extra="", d_name="d"):
    """DKIM2-Signature i=<seq> m=<m> whose s= is `s_layout` as written:
    items "sel:alg:VALUE" joined by "," and "|" (any FWS kept).  VALUE
    "SIGN:<keysel>" is a real signature with <keysel>'s key for `d` over
    the signed form: every value blanked, everything else -- selectors,
    names, ":" "," "|" -- byte for byte (-08 §12.8).  `extra` is more tags,
    written before s=; `d_name` spells the d= tag's name."""
    mf_b64 = ds.b64(ds.to_rfc5321_path(mf).encode("utf-8"))
    rt_b64 = ",".join(ds.b64(ds.to_rfc5321_path(r).encode("utf-8")) for r in rt)
    pre = (f"DKIM2-Signature: i={seq}; m={m}; t={ts}; {d_name}={d}; mf={mf_b64}; "
           f"rt={rt_b64}; {extra}s=")
    incomplete = pre + _LAYOUT_ITEM.sub(
        lambda x: x.group(1) + x.group(2) + x.group(3) + x.group(4), s_layout) + ";"

    def signed(x):
        v = x.group(5)
        if v.startswith("SIGN:"):
            priv, alg = ds.load_private_key(key(v[5:], d))
            v = ds.b64(ds.compute_signature(mis, below, incomplete, priv, alg))
        return x.group(1) + x.group(2) + x.group(3) + x.group(4) + v
    return pre + _LAYOUT_ITEM.sub(signed, s_layout) + ";"


def _layout_message(s_layout, mi=None, headers=None, body=None, extra=""):
    """A one-hop message: Message-Instance `mi` (default: the right sha256
    hashes) and a signature whose s= is `s_layout` (_layout_sig)."""
    if headers is None:
        headers, body = load_base()
    mi = mi or _mi_raw(headers, body, 1)
    sig = _layout_sig([mi], [], s_layout, extra=extra)
    return _order_message([sig, mi], headers, body)


def _flip(b64v):
    return ("B" if b64v[0] == "A" else "A") + b64v[1:]


def _h_layout(h_layout, headers, body):
    """A Message-Instance m=1 whose h= is `h_layout`: "<alg>:H:B" gives the
    right hashes, "BAD" in either place a wrong (but base64) one; any other
    algorithm's values are written as given."""
    def one(x):
        alg, hh, bh = x.group(1), x.group(2), x.group(3)
        if alg in ("sha256", "sha512"):
            good_h = ds.b64(ds.compute_header_hash(headers, alg))
            good_b = ds.b64(ds.compute_body_hash(body, alg))
            hh = good_h if hh == "H" else _flip(good_h) if hh == "BAD" else hh
            bh = good_b if bh == "B" else _flip(good_b) if bh == "BAD" else bh
        return f"{alg}:{hh}:{bh}"
    return "Message-Instance: m=1; h=" + re.sub(
        r"([^\s:,|]+):([^\s:,|]*):([^\s:,|;]*)", one, h_layout) + ";"


def _hash_layout_message(h_layout):
    headers, body = load_base()
    return _layout_message("sel1:rsa-sha256:SIGN:sel1",
                           _h_layout(h_layout, headers, body), headers, body)


S1 = "sel1:rsa-sha256:SIGN:sel1"
S2 = "sel2:rsa-sha256:SIGN:sel2"
BAD2 = "sel2:rsa-sha256:SIGN:sel1"   # sel1's signature under sel2: FAIL
BAD3 = "sel3:rsa-sha256:SIGN:sel1"   # sel1's signature under sel3: FAIL


def build_positive_sig_group_pass():
    """D2/D3: s= "sel2(bad) | sel1": the first group fails, the second
    passes, so the signature passes (§14.6 step 7)."""
    return _layout_message(f"{BAD2} |\r\n {S1}")


def build_sig_group_fail():
    """D3: s= "sel2(bad) | sel3(bad)": no group passes, and with more than
    one group a FAIL is reported as "no group of signatures passed"."""
    return _layout_message(f"{BAD2}|{BAD3}")


def build_sig_group_bad_signature():
    """D3: one "," group "sel1, sel2(bad)": the first FAIL item is named."""
    return _layout_message(f"{S1},{BAD2}")


def build_sig_unknown_algorithm_and():
    """D3/D8: "sel1, x:mldsa44:..." -- ML-DSA-44 is not implemented, so its
    item is a PERMERROR and the "," group with it is PERMERROR."""
    return _layout_message(f"{S1},x:mldsa44:AAAA")


def build_positive_sig_unknown_algorithm_or():
    """D3/D8: the same joined by "|": sel1's group passes."""
    return _layout_message(f"{S1}|x:mldsa44:AAAA")


def build_sig_unknown_algorithm_only():
    """D3/D8: only the old composite algorithm: PERMERROR, no key fetched
    (there is no record for selector x)."""
    return _layout_message("x:mldsa44-ed25519-sha512:AAAA")


def build_sig_unknown_algorithm_not_base64():
    """D3: an unimplemented algorithm's value must still be a base64string:
    "sel1 | x:future:@@@@" is a syntax error."""
    return _layout_message(f"{S1}|x:future:@@@@")


def build_sig_empty_group():
    """D2: "sel1 || sel2": an empty member is a syntax error."""
    return _layout_message(f"{S1}||{S2}")


def build_sig_duplicate_selector_across_groups():
    """D2: the duplicate-selector rule spans the whole tag: "sel1 | sel1"."""
    return _layout_message(f"{S1}|{S1}")


def build_hash_group_fail():
    """D4: h= "sha256 (body wrong) | sha512 (header wrong)": no group
    passes, so "no group of hashes passed"."""
    return _hash_layout_message("sha256:H:BAD|sha512:BAD:B")


def build_positive_hash_group_pass():
    """D4: h= "sha256 (body wrong) | sha512": the second group passes."""
    return _hash_layout_message("sha256:H:BAD | sha512:H:B")


def build_hash_unknown_algorithm():
    """D4: h= with only an algorithm we have not implemented:
    "algorithm x-hash unknown" (PERMERROR)."""
    return _hash_layout_message("x-hash:AAAA:AAAA")


def build_hash_unknown_algorithm_and():
    """D4: "sha256, x-hash": the unknown set makes the "," group PERMERROR."""
    return _hash_layout_message("sha256:H:B,x-hash:AAAA:AAAA")


def build_positive_hash_unknown_algorithm_or():
    """D4: "sha256 | x-hash": the sha256 group passes."""
    return _hash_layout_message("sha256:H:B|x-hash:AAAA:AAAA")


def build_hash_set_order():
    """D4: one "," group "sha512 (header wrong), sha256 (body wrong)": the
    first FAIL set in h= order is named, header before body within it."""
    return _hash_layout_message("sha512:BAD:B,sha256:H:BAD")


def build_order_sig_syntax_before_duplicate():
    """D2/D3 within-field order: s= repeats sel1, and its second item's
    value is not base64.  The value's syntax comes first: "syntax error"."""
    return _layout_message(f"{S1}|sel1:rsa-sha256:@@@@")


def build_order_hash_syntax_before_duplicate():
    """D2 within-field order: h= repeats sha256, and the repeat's header
    hash is unpadded base64.  The syntax comes first: "syntax error"."""
    return _hash_layout_message("sha256:H:B,sha256:AAA:AAAA")


def build_order_duplicate_before_limit():
    """D3 within-field order: 9 items (over the limit of 8) with sel1 twice.
    The duplicate comes before the limit: "has a duplicate selector"."""
    return _layout_message(SIX + "|a:x-alg:AAAA,b:x-alg:AAAA,sel1:x-alg:AAAA")


def build_key_ed25519_spki():
    """D7: selector ed25519spki publishes test1's Ed25519 key as a DER
    SubjectPublicKeyInfo (44 octets), not the raw 32 octets -08 §3.3/§14.5
    require: "public key ed25519spki is malformed".  The signature is made
    with the matching private key, so only the key's form is wrong."""
    headers, body = load_base()
    mi = _mi_raw(headers, body, 1)
    sig = _layout_sig([mi], [], "ed25519spki:ed25519-sha256:SIGN:ed25519")
    return _order_message([sig, mi], headers, body)


def build_recipe_h_step():
    """D6: the second step of the Subject header Recipe is not a step:
    "Recipe h.subject[1] is invalid"."""
    h1, b1, h2, r = _subject_hop()
    steps = next(iter(r["h"].values()))
    return _two_hop(h1, b1, h2, b1, {"h": {"subject": steps + [{"x": [1]}]}})


def build_recipe_h_name_escaped():
    """D6: a header name with a space and a UTF-8 octet pair, its one step
    bad: "Recipe h.x\\x20caf\\xC3\\xA9[0] is invalid" (every octet outside
    0x21-0x7E escaped, uppercase hex).  "x café" sorts after "subject" in
    byte order, so the (valid) Subject Recipe is checked first."""
    h1, b1, h2, r = _subject_hop()
    text = json.dumps({"h": dict(r["h"], **{"x café": [{"z": 1}]})},
                      separators=(",", ":"), ensure_ascii=False)
    return _two_hop(h1, b1, h2, b1, text)


def build_recipe_b_before_h():
    """D6: a bad "b" step and a bad "h" step: "b" is reported first."""
    h1, b1, h2, r = _subject_hop()
    steps = next(iter(r["h"].values()))
    return _two_hop(h1, b1, h2, b1,
                    {"h": {"subject": [{"x": 1}] + steps}, "b": [{"c": [1, 1]}, {"y": 1}]})


def build_recipe_whole_before_step():
    """D6: a bad step AND a whole-document fault ("h" not an object): the
    whole-document fault is reported, "contains invalid JSON"."""
    headers, _ = load_base()
    return _two_hop(headers, CUR_BODY, headers, CUR_BODY, '{"b":[{"x":1}],"h":[]}')


def build_recipe_number_exponent():
    """D6: a JSON number with an exponent anywhere ("1e0", unused key) makes
    the whole Recipe invalid JSON, whatever a JSON library makes of it."""
    headers, _ = load_base()
    return _two_hop(headers, CUR_BODY, headers, CUR_BODY, '{"b":[{"c":[1,3]}],"n":1e0}')


def build_recipe_lone_surrogate():
    """D6: a "d" string written as the escape of a lone surrogate (\\udc80) is
    not a Unicode string, so the document is not JSON text: "contains
    invalid JSON", not one bad step."""
    headers, _ = load_base()
    return _two_hop(headers, b"x\r\n" + CUR_BODY, headers, CUR_BODY,
                    '{"b":[{"d":["\\udc80"]},{"c":[1,3]}]}')


def build_auto_submitted_modified():
    """D1: Auto-Submitted is hashed since -08.  A message signed with
    "Auto-Submitted: auto-generated", which a later hop changed to
    "auto-replied": the header hash fails (a -07 verifier ignored it)."""
    headers, body = load_base()
    headers = headers + [b"Auto-Submitted: auto-generated"]
    msg = _chain([(headers, body, None)], [dict(d=DOM, m=1, mf=MF, rt=RT)])
    return _replace_header(msg, b"Auto-Submitted", b"auto-replied")


def build_positive_auto_submitted():
    """D1: the same, unchanged: it verifies."""
    headers, body = load_base()
    headers = headers + [b"Auto-Submitted: auto-generated", b"VBR-Info: md=test1.dkim2.com; mc=all; mv=x.example"]
    return _chain([(headers, body, None)], [dict(d=DOM, m=1, mf=MF, rt=RT)])


def build_uppercase_tag():
    """D10: "D=test1.dkim2.com" (and no d=) in a signature signed as it
    stands: an uppercase tag is an unknown tag, so d= is missing."""
    headers, body = load_base()
    mi = _mi_raw(headers, body, 1)
    sig = _layout_sig([mi], [], S1, d_name="D")
    return _order_message([sig, mi], headers, body)


def build_positive_uppercase_twin_tag():
    """D10: "M=2" beside m=1 in a Message-Instance and "I=9" beside i=1 in
    the signature, both signed in: unknown tags, ignored, not duplicates."""
    headers, body = load_base()
    mi = _mi_raw(headers, body, 1)[:-1] + "; M=2;"
    sig = _layout_sig([mi], [], S1, extra="I=9; ")
    return _order_message([sig, mi], headers, body)


def build_multi_key_error_above_bad_signature():
    """Amended C9 (contract D3): i=1's signature does not verify (§14.6) and
    i=2 names a selector with no key record (§14.5).  Key and signature are
    one step per signature now, so i=1's FAIL is primary (-07 put every
    §14.5 key error before any §14.6 FAIL)."""
    (sig2, sig1), (mi2, mi1), h2, b2 = _order_two_hop()
    bad1 = _corrupt_signature(_order_message([sig1], [], b"")[:-4] + b"\r\n\r\n", 1)
    bad1 = bad1.split(b"\r\n")[0].decode()
    sig2 = _order_sign([mi1, mi2], [bad1], 2, 2, d="test2.dkim2.com",
                       mf="relay@test2.dkim2.com", rt=["final@example.com"],
                       sel="nokey")
    return _order_message([sig2, bad1, mi2, mi1], h2, b2)

FIXTURES = {
    "signature-gap.eml": build_signature_gap,
    "instance-gap.eml": build_instance_gap,
    "dup-hash-algorithm.eml": build_dup_hash,
    "dup-selector.eml": build_dup_selector,
    "too-many-signatures.eml": build_too_many,
    "order-sig-syntax-before-duplicate.eml": build_order_sig_syntax_before_duplicate,
    "order-hash-syntax-before-duplicate.eml": build_order_hash_syntax_before_duplicate,
    "order-duplicate-before-limit.eml": build_order_duplicate_before_limit,
    "positive-control-eight-signatures.eml": build_positive_eight_signatures,
    "positive-control-three-same-algorithm.eml": build_positive_three_same_algorithm,
    "malformed-json-r.eml": build_malformed_json,
    "unsigned-mi.eml": build_unsigned_mi,
    "nd-bridge-wrong-domain.eml": build_nd_bridge_wrong_domain,
    "duplicate-mi-version.eml": build_duplicate_mi_version,
    "positive-control-unreferenced-lower-mi.eml": build_positive_unreferenced_lower_mi,
    "positive-control-two-selectors.eml": build_positive_control,
    "positive-control-bottom-recipe.eml": build_positive_bottom_recipe,
    "recipe-descending-ranges.eml": build_recipe_descending,
    "recipe-overlapping-ranges.eml": build_recipe_overlapping,
    "positive-control-u-literal.eml": build_positive_u_literal,
    "positive-control-nd-bridge.eml": build_positive_nd_bridge,
    "positive-control-null-body.eml": build_positive_null_body,
    "positive-control-null-body-over-recipe.eml": build_positive_null_body_over_recipe,
    "null-body-forged-history.eml": build_null_body_forged_history,
    "positive-control-null-below.eml": build_positive_null_below,
    "positive-control-empty-body-chain.eml": build_positive_empty_body,
    "empty-body-forged-history.eml": build_empty_body_forged_history,
    "malformed-body-recipe-below-null.eml": build_malformed_body_recipe_below_null,
    "unkeyable-signature-no-i.eml": build_unkeyable_signature_no_i,
    "unkeyable-signature-i-abc.eml": build_unkeyable_signature_i_abc,
    "lone-junk-signature.eml": build_lone_junk_signature,
    "signature-i-33.eml": build_signature_i_33,
    "signature-i-101.eml": build_signature_i_101,
    "signature-i-huge.eml": build_signature_i_huge,
    "signature-m-huge.eml": build_signature_m_huge,
    "instance-m-huge.eml": build_instance_m_huge,
    "signature-m-malformed.eml": build_signature_m_malformed,
    "instance-m-malformed.eml": build_instance_m_malformed,
    "recipe-duplicate-b-null-last.eml": build_recipe_duplicate_b_null_last,
    "recipe-duplicate-b-null-first.eml": build_recipe_duplicate_b_null_first,
    "recipe-duplicate-h-key.eml": build_recipe_duplicate_h_key,
    "positive-control-custody-bounce.eml": build_positive_custody_bounce,
    "custody-bounce-d-mismatch.eml": build_custody_bounce_d_mismatch,
    "positive-control-nd-subdomain-rt.eml": build_positive_nd_subdomain_rt,
    "nd-subdomain-swapped.eml": build_nd_subdomain_swapped,
    "nd-next-hop-mismatch.eml": build_nd_next_hop_mismatch,
    "custody-mf-domain-literal.eml": build_custody_mf_domain_literal,
    "mf-d-mismatch.eml": build_mf_d_mismatch,
    "from-not-authentic.eml": build_from_not_authentic,
    "positive-control-from-folded-2047.eml": build_positive_from_folded_2047,
    "positive-control-from-changed.eml": build_positive_from_changed,
    "from-changed-not-authentic.eml": build_from_changed_not_authentic,
    "positive-control-ingress-from-rewritten.eml": build_positive_ingress_from_rewritten,
    "from-not-authentic-at-signed-state.eml": build_from_not_authentic_at_signed_state,
    "recipe-u-nonzero-pad.eml": build_recipe_u_nonzero_pad,
    "recipe-b-step.eml": build_recipe_b_step,
    "recipe-two-step-keys.eml": build_recipe_two_step_keys,
    "recipe-empty-step.eml": build_recipe_empty_step,
    "recipe-uppercase-keys.eml": build_recipe_uppercase_keys,
    "recipe-case-duplicate-key.eml": build_recipe_case_duplicate_key,
    "from-display-no-brackets.eml": build_from_display_no_brackets,
    "multi-from-tampered.eml": build_multi_from_tampered,
    "multi-header-and-body-tampered.eml": build_multi_header_and_body_tampered,
    "multi-expired-custody.eml": build_multi_expired_custody,
    "multi-custody-bad-signature.eml": build_multi_custody_bad_signature,
    "multi-bad-signature-header-hash.eml": build_multi_bad_signature_header_hash,
    "multi-tamper-two-instances.eml": build_multi_tamper_two_instances,
    "multi-expired-recipe-json.eml": build_multi_expired_recipe_json,
    "multi-expired-recipe-order.eml": build_multi_expired_recipe_order,
    "multi-expired-recipe-past-end.eml": build_multi_expired_recipe_past_end,
    "multi-tamper-recipe-past-end.eml": build_multi_tamper_recipe_past_end,
    "multi-signature-gap-recipe-json.eml": build_multi_signature_gap_recipe_json,
    "multi-instance-gap-signature-gap.eml": build_multi_instance_gap_signature_gap,
    "multi-instance-no-m-signature-twice.eml": build_multi_instance_no_m_signature_twice,
    "multi-instance-twice-signature-no-i.eml": build_multi_instance_twice_signature_no_i,
    "multi-instance-twice-lowest.eml": build_multi_instance_twice_lowest,
    "multi-signature-twice-lowest.eml": build_multi_signature_twice_lowest,
    "multi-instance-twice-junk-signature.eml": build_multi_instance_twice_junk_signature,
    "multi-instance-gap-unsigned.eml": build_multi_instance_gap_unsigned,
    "multi-instance-syntax-dup-alg.eml": build_multi_instance_syntax_dup_alg,
    "multi-instance-dup-alg-recipe.eml": build_multi_instance_dup_alg_recipe,
    "multi-instance-syntax-dup-selector.eml": build_multi_instance_syntax_dup_selector,
    "multi-header-sha512-body-sha256.eml": build_multi_header_sha512_body_sha256,
    "multi-expired-nd.eml": build_multi_expired_nd,
    "multi-expired-header-hash.eml": build_multi_expired_header_hash,
    "multi-custody-header-hash.eml": build_multi_custody_header_hash,
    "multi-body-hash-no-key.eml": build_multi_body_hash_no_key,
    "too-many-instance-fields.eml": build_too_many_instance_fields,
    "too-many-signature-fields.eml": build_too_many_signature_fields,
    # draft -08
    "positive-control-sig-group-pass.eml": build_positive_sig_group_pass,
    "sig-group-fail.eml": build_sig_group_fail,
    "sig-group-bad-signature.eml": build_sig_group_bad_signature,
    "sig-unknown-algorithm-and.eml": build_sig_unknown_algorithm_and,
    "positive-control-sig-unknown-algorithm-or.eml": build_positive_sig_unknown_algorithm_or,
    "sig-unknown-algorithm-only.eml": build_sig_unknown_algorithm_only,
    "sig-unknown-algorithm-not-base64.eml": build_sig_unknown_algorithm_not_base64,
    "sig-empty-group.eml": build_sig_empty_group,
    "sig-duplicate-selector-across-groups.eml": build_sig_duplicate_selector_across_groups,
    "hash-group-fail.eml": build_hash_group_fail,
    "positive-control-hash-group-pass.eml": build_positive_hash_group_pass,
    "hash-unknown-algorithm.eml": build_hash_unknown_algorithm,
    "hash-unknown-algorithm-and.eml": build_hash_unknown_algorithm_and,
    "positive-control-hash-unknown-algorithm-or.eml": build_positive_hash_unknown_algorithm_or,
    "hash-set-order.eml": build_hash_set_order,
    "key-ed25519-spki.eml": build_key_ed25519_spki,
    "recipe-h-step.eml": build_recipe_h_step,
    "recipe-h-name-escaped.eml": build_recipe_h_name_escaped,
    "recipe-b-before-h.eml": build_recipe_b_before_h,
    "recipe-whole-before-step.eml": build_recipe_whole_before_step,
    "recipe-number-exponent.eml": build_recipe_number_exponent,
    "recipe-lone-surrogate.eml": build_recipe_lone_surrogate,
    "auto-submitted-modified.eml": build_auto_submitted_modified,
    "positive-control-auto-submitted.eml": build_positive_auto_submitted,
    "uppercase-tag.eml": build_uppercase_tag,
    "positive-control-uppercase-twin-tag.eml": build_positive_uppercase_twin_tag,
    "multi-key-error-above-bad-signature.eml": build_multi_key_error_above_bad_signature,
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
