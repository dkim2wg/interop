"""Verifier strictness (docs/superpowers/specs/2026-10-09-verifier-strictness-review-fixes.md).

A. signature algorithms (-07 §3.5, §10.9)
B. key records (-07 §14.5, dkim2-dns-00 §3.2, §3.4.1, §3.4.2.2)
C. Message-Instance tag case and duplicates (-07 §8, §9)
D. t= syntax (-07 §10.4, §14.2)

Messages are signed here by hand (rather than through sign_message) so each
test controls the exact s= list, Message-Instance text and t= value. Key
records are fed through the dns_data dict; a TXT value given as a list is one
RR split into several character-strings.
"""
import gate_env  # noqa: F401
import copy
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))

import dkim2verify  # noqa: E402
from dkim2sign import (  # noqa: E402
    b64, compute_body_hash, compute_header_hash, compute_signature,
    load_private_key, parse_message,
)
from dkim2verify import verify_message  # noqa: E402

D = "test1.dkim2.com"
DNS = json.load(open(os.path.join(REPO, "dns.json")))
BASE = (b"From: a@test1.dkim2.com\r\nTo: b@example.com\r\nSubject: strict\r\n"
        b"\r\nHello\r\n")
MF = b64(b"<a@test1.dkim2.com>")
RT = b64(b"<b@example.com>")


def _key(sel):
    return load_private_key(os.path.join(REPO, "keys", f"{sel}._domainkey.{D}.pem"))


def _good_mi_value():
    headers, body = parse_message(BASE)
    return (f"m=1; h=sha256:{b64(compute_header_hash(headers, 'sha256'))}:"
            f"{b64(compute_body_hash(body, 'sha256'))};")


def make(items, mi_value=None, t="TS", extra="", sep=","):
    """items: list of (selector, algorithm, value), joined by `sep`. value
    "SIGN:<keysel>" is replaced by a real signature with that key over the
    incomplete header."""
    if t == "TS":
        t = str(int(time.time()))
    mi = "Message-Instance: " + (mi_value or _good_mi_value())
    pre = f"DKIM2-Signature: i=1; m=1; t={t}; d={D}; mf={MF}; rt={RT}; {extra}s="
    incomplete = pre + sep.join(f"{s}:{a}:" for s, a, _ in items) + ";"
    vals = []
    for s, a, v in items:
        if v.startswith("SIGN:"):
            key, kalg = _key(v[5:])
            v = b64(compute_signature([mi], [], incomplete, key, kalg))
        vals.append(f"{s}:{a}:{v}")
    sig = pre + sep.join(vals) + ";"
    return (mi + "\r\n" + sig + "\r\n").encode() + BASE


def verify(raw, dns=None, **kw):
    kw.setdefault("skip_timestamp_check", True)
    return verify_message(raw, DNS if dns is None else dns, **kw)


@pytest.fixture
def lookups(monkeypatch):
    calls = []
    real = dkim2verify.lookup_public_key

    def counting(domain, selector, dns_data):
        calls.append(selector)
        return real(domain, selector, dns_data)

    monkeypatch.setattr(dkim2verify, "lookup_public_key", counting)
    return calls


def test_baseline_rsa_and_ed25519_pass():
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")])).ok
    assert verify(make([("ed25519", "ed25519-sha256", "SIGN:ed25519")])).ok


# --- A. signature algorithms -------------------------------------------------

@pytest.mark.parametrize("alg", ["future-alg", "RSA-SHA256", "rsa-sha256x", "rsa"])
def test_unknown_algorithm_with_good_rsa_signature_does_not_pass(alg, lookups):
    r = verify(make([("sel1", alg, "SIGN:sel1")]))
    assert not r.ok
    # -08 §14.6 step 4 (contract D3): an algorithm we have not implemented is
    # a PERMERROR item naming its selector (-07 had "has no signature with a
    # supported algorithm").
    assert r.message == "PERMERROR: DKIM2-Signature i=1 selector sel1 algorithm unknown", r
    assert r.status == "permerror", r
    assert lookups == [], "no key is fetched for an unknown algorithm"


def test_unknown_item_in_another_group_good_item_passes_one_lookup(lookups):
    # -07 skipped an unknown item; -08 makes it a PERMERROR item, so it only
    # stays out of the way in another "|" group (contract D3).
    raw = make([("sel2", "future-alg", "AAAA"), ("sel1", "rsa-sha256", "SIGN:sel1")])
    r = verify(raw)
    assert r.message == "PERMERROR: DKIM2-Signature i=1 selector sel2 algorithm unknown", r
    r = verify(raw.replace(b"AAAA,sel1:", b"AAAA|sel1:"))
    assert not r.ok  # the separator is signed: changing it breaks i=1
    lookups.clear()
    r = verify(make([("sel2", "future-alg", "AAAA"), ("sel1", "rsa-sha256", "SIGN:sel1")],
                    sep="|"))
    assert r.ok, r
    assert lookups == ["sel1"]


def test_many_unknown_items_are_over_the_limit(lookups):
    # -07 let 4000 unknown items cost one lookup; -08 caps an s= tag at 8
    # items (contract D3, local limit), before any key is fetched.
    items = [(f"x{n}", f"alg{n}", "AAAA") for n in range(4000)]
    items.append(("sel1", "rsa-sha256", "SIGN:sel1"))
    r = verify(make(items))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 has more than 8 signatures", r
    assert lookups == []


@pytest.mark.parametrize("val", ["", "!!!!", "AAA", "####"])
def test_known_algorithm_bad_base64_is_syntax_error(val, lookups):
    r = verify(make([("sel1", "rsa-sha256", val)]))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 syntax error", r
    assert r.status == "permerror"


def test_signature_value_with_fws_still_verifies():
    raw = make([("sel1", "rsa-sha256", "SIGN:sel1")])
    # fold inside the base64 signature value: still valid (FWS removed)
    head, rest = raw.split(b"s=sel1:rsa-sha256:", 1)
    raw = head + b"s=sel1:rsa-sha256:" + rest[:20] + b"\r\n\t" + rest[20:]
    assert verify(raw).ok


def test_key_type_must_match_algorithm():
    # ed25519-sha256 item naming an RSA key
    r = verify(make([("sel1", "ed25519-sha256", "SIGN:ed25519")]))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel1 algorithm mismatch", r
    assert r.status == "permerror"
    # rsa-sha256 item naming an Ed25519 key
    r = verify(make([("ed25519", "rsa-sha256", "SIGN:sel1")]))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key ed25519 algorithm mismatch", r


# --- B. key records ----------------------------------------------------------

RSA_P = [v for t, v in DNS[D]["sel1._domainkey"] if t == "txt"][0].split("p=", 1)[1].strip()
ED_P = [v for t, v in DNS[D]["ed25519._domainkey"] if t == "txt"][0].split("p=", 1)[1].strip()


def _dns_with(records, sel="sel1"):
    d = copy.deepcopy(DNS)
    d[D][f"{sel}._domainkey"] = records
    return d


def _rsa_with(*records):
    return verify(make([("sel1", "rsa-sha256", "SIGN:sel1")]),
                  _dns_with([["txt", r] for r in records]))


SYNTAX = "PERMERROR: DKIM2-Signature i=1 public key sel1 has a syntax error"


@pytest.mark.parametrize("rec", [
    f"v=DKIM1; p=; p={RSA_P}",          # repeated tag
    f"v=DKIM1; p={RSA_P}; p={RSA_P}",   # repeated tag, same value
    f"v=garbage; p={RSA_P}",            # bad v=
    f"v=dkim1; p={RSA_P}",              # v= value is case sensitive
    f"k=rsa; v=DKIM1; p={RSA_P}",       # v= not first
    "v=DKIM1; k=rsa",                   # no p=
    "v=DKIM1; k=rsa; p=!!!!",           # p= not base64
    f"v=DKIM1; 1k=rsa; p={RSA_P}",      # bad tag name
    f"v=DKIM1; k rsa; p={RSA_P}",       # spec without '='
    f"v=DKIM1; P={RSA_P}",              # tag names case sensitive: no p=
])
def test_bad_key_record_is_syntax_error(rec):
    r = _rsa_with(rec)
    assert r.message == SYNTAX, (rec, r)
    assert r.status == "permerror"


# -08 §14.5 (contract D7): a p= that is base64 but not a key of its type is
# "is malformed" (both were "has a syntax error" under -07).
@pytest.mark.parametrize("rec", [
    "v=DKIM1; k=rsa; p=AAAA",           # p= not a key
    f"v=DKIM1; k=rsa; p={ED_P}",        # p= not an RSA key
])
def test_base64_p_that_is_not_a_key_is_malformed(rec):
    r = _rsa_with(rec)
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel1 is malformed", (rec, r)
    assert r.status == "permerror"


@pytest.mark.parametrize("rec", [
    f"v=DKIM1; k=rsa; p={RSA_P}",
    f"v=DKIM1; k=rsa; p={RSA_P};",            # trailing ;
    f"p={RSA_P}",                             # v= and k= optional
    f"v=DKIM1;k=rsa;p={RSA_P[:40]} {RSA_P[40:]}",  # FWS inside p=
    f"v=DKIM1; h=sha1; n=note; s=email; t=y; x_y=z; p={RSA_P}",  # retired/unknown ignored
])
def test_good_key_record_passes(rec):
    r = _rsa_with(rec)
    assert r.ok, (rec, r)


def test_unknown_key_type_is_algorithm_mismatch():
    r = _rsa_with(f"v=DKIM1; k=unknown; p={RSA_P}")
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel1 algorithm mismatch", r
    assert r.status == "permerror"


def test_k_ed25519_for_rsa_signature_is_algorithm_mismatch():
    r = _rsa_with(f"v=DKIM1; k=ed25519; p={ED_P}")
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel1 algorithm mismatch", r


def test_empty_p_is_revoked():
    r = _rsa_with("v=DKIM1; k=rsa; p=")
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel1 has been revoked", r
    assert r.status == "permerror"


def test_two_txt_records_is_multiple_records():
    rec = f"v=DKIM1; k=rsa; p={RSA_P}"
    for pair in ([rec, rec], [rec, "v=spf1 -all"]):
        r = _rsa_with(*pair)
        assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel1 has multiple records", r
        assert r.status == "permerror"


def test_one_rr_split_into_two_strings_is_fine():
    rec = f"v=DKIM1; k=rsa; p={RSA_P}"
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")]),
               _dns_with([["txt", [rec[:100], rec[100:]]]]))
    assert r.ok, r


def test_ed25519_record_split_and_good():
    r = verify(make([("ed25519", "ed25519-sha256", "SIGN:ed25519")]),
               _dns_with([["txt", ["v=DKIM1; k=ed25519; p=", ED_P]]], "ed25519"))
    assert r.ok, r


def test_ed25519_bad_length_is_malformed():
    # -08 §3.2, §14.5 (contract D7): not exactly 32 octets is "is
    # malformed" ("has a syntax error" under -07).
    bad = b64(b"\x00" * 40)
    r = verify(make([("ed25519", "ed25519-sha256", "SIGN:ed25519")]),
               _dns_with([["txt", f"v=DKIM1; k=ed25519; p={bad}"]], "ed25519"))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key ed25519 is malformed", r


# --- C. Message-Instance tag case and duplicates -----------------------------

# -07 decision 2 accepted tag names in any case; -08 (contract D10) makes
# them strictly lower case, so "H=" and "M=" are unknown tags, ignored.

def test_mi_uppercase_h_is_unknown_tag():
    mi = _good_mi_value().replace("h=", "H=")
    for fc in (False, True):
        r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=fc)
        assert r.message == "PERMERROR: Message-Instance m=1 tag=h missing", r


def test_mi_uppercase_m_is_unknown_tag():
    mi = _good_mi_value().replace("m=", "M=")
    for fc in (False, True):
        r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=fc)
        assert r.message == "PERMERROR: Message-Instance m= tag=m missing", r


@pytest.mark.parametrize("mk", [
    lambda good: "m=1; h=sha256:AAAA:AAAA; " + good[5:],      # h= ... h=<correct>
    lambda good: good[:-1] + "; h=sha256:AAAA:AAAA;",          # h=<correct> ... h=
    lambda good: good + " m=1;",                               # m=1 ... m=1
])
@pytest.mark.parametrize("full_chain", [False, True])
def test_mi_duplicate_tag_is_syntax_error(mk, full_chain):
    mi = mk(_good_mi_value())
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=full_chain)
    assert not r.ok, mi
    assert "PERMERROR: Message-Instance m=1 syntax error" in r.errors, (mi, r)
    assert r.status == "permerror"


# These were duplicates under -07 (any case); under -08 the uppercase twin is
# an unknown tag and is ignored (contract D10).
@pytest.mark.parametrize("mk", [
    lambda good: "m=1; H=sha256:AAAA:AAAA; " + good[5:],      # H= ... h=
    lambda good: good + " M=1;",                               # m=1 ... M=1
])
@pytest.mark.parametrize("full_chain", [False, True])
def test_mi_uppercase_twin_is_not_a_duplicate(mk, full_chain):
    mi = mk(_good_mi_value())
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=full_chain)
    assert r.ok, (mi, r)


# --- D. t= syntax --------------------------------------------------------------

@pytest.mark.parametrize("t", ["garbage", "-5", "1e9", "0x10", "12 34", "+5", "1.5",
                               "١٢"])
@pytest.mark.parametrize("skip", [True, False])
def test_bad_t_is_syntax_error(t, skip):
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t=t),
               skip_timestamp_check=skip)
    assert r.message == "PERMERROR: DKIM2-Signature i=1 syntax error", (t, r)
    assert r.status == "permerror"


def test_t_zero_is_expired():
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t="0"),
               skip_timestamp_check=False)
    assert not r.ok
    assert "expired" in r.message, r
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t="0")).ok


def test_t_large_values_do_not_overflow():
    for t in ("1000000000000", "99999999999999999999999"):
        r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t=t),
                   skip_timestamp_check=False)
        assert not r.ok and "future" in r.message, (t, r)
        assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t=t)).ok


def test_t_with_surrounding_wsp_is_fine():
    t = str(int(time.time()))
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t=f" {t} "),
                  skip_timestamp_check=False).ok



# --- E. outcome of a signature's items ----------------------------------------

def test_e_unusable_record_on_any_item_is_permerror_even_if_other_verifies():
    # sel2's record is revoked; sel1 verifies. In one "," group the whole
    # signature is PERMERROR (-08 §14.6 step 6: sig-all with no FAIL).
    for rec, why in (("v=DKIM1; k=rsa; p=", "has been revoked"),
                     ("v=DKIM1; k=rsa; p=AAAA", "is malformed"),
                     (f"v=DKIM1; k=ed25519; p={ED_P}", "algorithm mismatch")):
        for order in ((0, 1), (1, 0)):
            items = [("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel2")]
            items = [items[i] for i in order]
            r = verify(make(items), _dns_with([["txt", rec]], "sel2"))
            assert r.message == f"PERMERROR: DKIM2-Signature i=1 public key sel2 {why}", (rec, r)
            assert r.status == "permerror"
    rec = [v for t, v in DNS[D]["sel2._domainkey"] if t == "txt"][0]
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel2")]),
               _dns_with([["txt", rec], ["txt", rec]], "sel2"))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel2 has multiple records", r


def test_e_absent_key_item_is_an_item_permerror():
    # -07 skipped an item whose key did not exist; -08 makes every item's
    # key error its own PERMERROR (contract D3), so in a "," group it is the
    # result -- and in another "|" group it is not.
    items = [("nosuch", "rsa-sha256", "SIGN:sel2"), ("sel1", "rsa-sha256", "SIGN:sel1")]
    r = verify(make(items))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key nosuch does not exist", r
    assert verify(make(items, sep="|")).ok


def test_e_all_keys_absent_is_does_not_exist():
    # the first PERMERROR item, in s= order
    r = verify(make([("nosuch", "rsa-sha256", "SIGN:sel1"),
                     ("gone", "ed25519-sha256", "SIGN:ed25519"),
                     ("x", "future-alg", "AAAA")]))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key nosuch does not exist", r
    assert r.status == "permerror"


def test_e_any_crypto_failure_is_fail_naming_selector():
    # sel2 item carries sel1's signature: verifies with neither key it names
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel1")]))
    assert r.status == "fail", r
    # -08 removed "signature <s1> signature <s2> failed": one group reports
    # its first FAIL item (contract D3).
    assert r.message == "FAIL: DKIM2-Signature i=1 selector sel2 incorrect signature", r
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel2"), ("sel2", "rsa-sha256", "SIGN:sel1")]))
    assert r.message == "FAIL: DKIM2-Signature i=1 selector sel1 incorrect signature", r


def test_e_p_must_be_padded():
    unpadded = ED_P.rstrip("=")
    assert unpadded != ED_P
    r = verify(make([("ed25519", "ed25519-sha256", "SIGN:ed25519")]),
               _dns_with([["txt", f"v=DKIM1; k=ed25519; p={unpadded}"]], "ed25519"))
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key ed25519 has a syntax error", r


def test_e_signature_value_must_be_padded():
    raw = make([("ed25519", "ed25519-sha256", "SIGN:ed25519")])
    head, rest = raw.split(b"s=ed25519:ed25519-sha256:", 1)
    val, tail = rest.split(b";", 1)
    assert val.endswith(b"=")
    r = verify(head + b"s=ed25519:ed25519-sha256:" + val.rstrip(b"=") + b";" + tail)
    assert r.message == "PERMERROR: DKIM2-Signature i=1 syntax error", r



def _short_rsa_p():
    """A 512-bit RSA public key (modulus 2^511 + 0x1234567; never a real key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.RSAPublicNumbers(65537, (1 << 511) | 0x1234567).public_key()
    return b64(key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo))


SHORT_RSA_P = _short_rsa_p()


def test_e_short_rsa_key_is_permerror_even_if_other_verifies():
    dns = _dns_with([["txt", f"v=DKIM1; k=rsa; p={SHORT_RSA_P}"]], "sel2")
    for items in ([("sel2", "rsa-sha256", "SIGN:sel2")],
                  [("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel2")],
                  [("sel2", "rsa-sha256", "SIGN:sel2"), ("sel1", "rsa-sha256", "SIGN:sel1")]):
        r = verify(make(items), dns)
        # -08 §3.2, §14.5 (contract D7): "is malformed".
        assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel2 is malformed", (items, r)
        assert r.status == "permerror"

# --- F. whole-field syntax (follow-up review) --------------------------------

SIG_SYNTAX = "PERMERROR: DKIM2-Signature i=1 syntax error"
MI_SYNTAX = "PERMERROR: Message-Instance m=1 syntax error"
GOOD = [("sel1", "rsa-sha256", "SIGN:sel1")]


@pytest.mark.parametrize("extra", [
    "junk; ", "9bad=foo; ", "=v; ", "x=a\x00b; ", "x=a\x7fb; ", "x=café; ",
    "n=café; ", "x-y=1; ", ";; ",
])
def test_f1_bad_sig_tag_fragment_is_syntax_error(extra):
    r = verify(make(GOOD, extra=extra))
    assert r.message == SIG_SYNTAX, (extra, r)
    assert r.status == "permerror"


@pytest.mark.parametrize("extra", [
    "x_y=foo bar; ", "x=; ", " x =\r\n\t1 ; ", "x=a\r\n\tb; ",
])
def test_f1_wellformed_sig_fragments_pass(extra):
    r = verify(make(GOOD, extra=extra))
    assert r.ok, (extra, r)


@pytest.mark.parametrize("mk", [
    lambda g: g + " junk;",
    lambda g: g + " 9bad=foo;",
    lambda g: g + " =v;",
    lambda g: g + " x=a\x00b;",
    lambda g: g + " x=a\x7fb;",
    lambda g: g + " x=café;",
])
@pytest.mark.parametrize("full_chain", [False, True])
def test_f1_bad_mi_tag_fragment_is_syntax_error(mk, full_chain):
    r = verify(make(GOOD, mk(_good_mi_value())), full_chain=full_chain)
    assert r.message == MI_SYNTAX, r
    assert r.status == "permerror"


def test_f1_wellformed_mi_unknown_tag_and_empty_fragments_pass():
    mi = _good_mi_value() + " x_y=a b;"
    assert verify(make(GOOD, mi)).ok
    assert verify(make(GOOD, mi), full_chain=True).ok
    # -07 §8: an empty tag-spec (";;") is not a tag-list.
    assert verify(make(GOOD, mi + ";")).message == MI_SYNTAX


@pytest.mark.parametrize("items", [
    [("sel1", "rsa- sha256", "SIGN:sel1")],
    [("sel1", "rsa-\r\n\tsha256", "SIGN:sel1")],
    [("se l1", "rsa-sha256", "SIGN:sel1")],
    [("s@l1", "rsa-sha256", "SIGN:sel1")],
    [("sel1..x", "rsa-sha256", "SIGN:sel1")],
    [("x", "future alg", "AAAA"), ("sel1", "rsa-sha256", "SIGN:sel1")],
])
def test_f2_fws_inside_selector_or_algorithm_is_syntax_error(items):
    r = verify(make(items))
    assert r.message == SIG_SYNTAX, (items, r)


def test_f2_item_with_too_few_parts_is_syntax_error():
    raw = make(GOOD).replace(b"; s=sel1:", b"; s=sel2:ed25519-sha256,sel1:")
    r = verify(raw)
    assert r.message == SIG_SYNTAX, r


def test_f2_fws_around_colons_and_comma_passes():
    items = [("sel1 ", " rsa-sha256 ", "SIGN:sel1"),
             ("\r\n\ted25519\r\n\t", "\r\n\ted25519-sha256", "SIGN:ed25519")]
    r = verify(make(items))
    assert r.ok, r


def _mi_h(h):
    return f"m=1; h={h};"


def _hashes():
    headers, body = parse_message(BASE)
    return (b64(compute_header_hash(headers, "sha256")),
            b64(compute_body_hash(body, "sha256")))


@pytest.mark.parametrize("fmt", [
    "sha 256:{h}:{b}",
    "sha\r\n\t256:{h}:{b}",
    "sha256:{h}:{b},sha512:{h}",
    "sha256:{h}:{b},sha512:{h}:",
    "sha256:{h}:{b}:x",
    "sha256:{h}:{b},",
])
def test_f3_bad_hash_set_is_syntax_error(fmt):
    h, b = _hashes()
    r = verify(make(GOOD, _mi_h(fmt.format(h=h, b=b))))
    assert r.message == MI_SYNTAX, (fmt, r)


@pytest.mark.parametrize("fmt", [
    " sha256 : {h} : {b}",
    "\r\n\tsha256\r\n\t:{h1}\r\n\t{h2}:{b}",
    # -08: an unknown algorithm passes only in another "|" group (contract
    # D4); with "," it would be a PERMERROR hash-set.
    "sha256:{h}:{b}\r\n\t| x-future:AAAA:BBBB",
])
def test_f3_fws_around_hash_name_and_inside_digests_passes(fmt):
    h, b = _hashes()
    v = fmt.format(h=h, b=b, h1=h[:10], h2=h[10:])
    assert verify(make(GOOD, _mi_h(v))).ok, fmt
    assert verify(make(GOOD, _mi_h(v)), full_chain=True).ok, fmt


@pytest.mark.parametrize("rec", [
    f"v=DKIM1; x=a\x00b; p={RSA_P}",
    f"v=DKIM1; x=a\x7fb; p={RSA_P}",
    f"v=DKIM1; n=café; p={RSA_P}",
    f"v=DKIM1; k=rsa; p={RSA_P}\x00",
])
def test_f4_bad_byte_in_key_record_is_syntax_error(rec):
    r = _rsa_with(rec)
    assert r.message == SYNTAX, (rec, r)


def test_f4_wsp_between_valchars_in_key_record_passes():
    assert _rsa_with(f"v=DKIM1; n=a note; p={RSA_P}").ok


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
