"""Verifier strictness (docs/superpowers/specs/2026-10-09-verifier-strictness-review-fixes.md).

A. signature algorithms (spec-06 §3.4, §8.9)
B. key records (spec-06 §11.5, dkim2-dns-00 §3.2, §3.4.1, §3.4.2.2)
C. Message-Instance tag case and duplicates (spec-06 §7)
D. t= syntax (spec-06 §8.4, §11.2)

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


def make(items, mi_value=None, t="TS"):
    """items: list of (selector, algorithm, value). value "SIGN:<keysel>" is
    replaced by a real signature with that key over the incomplete header."""
    if t == "TS":
        t = str(int(time.time()))
    mi = "Message-Instance: " + (mi_value or _good_mi_value())
    pre = f"DKIM2-Signature: i=1; m=1; t={t}; d={D}; mf={MF}; rt={RT}; s="
    incomplete = pre + ",".join(f"{s}:{a}:" for s, a, _ in items) + ";"
    vals = []
    for s, a, v in items:
        if v.startswith("SIGN:"):
            key, kalg = _key(v[5:])
            v = b64(compute_signature([mi], [], incomplete, key, kalg))
        vals.append(f"{s}:{a}:{v}")
    sig = pre + ",".join(vals) + ";"
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
    # E.1: no implemented algorithm at all is FAIL
    assert r.message == "FAIL DKIM2-Signature i=1 has no signature with a supported algorithm", r
    assert r.status == "fail", r
    assert lookups == [], "unknown algorithm must be ignored before key lookup"


def test_unknown_item_skipped_good_item_passes_one_lookup(lookups):
    r = verify(make([("sel2", "future-alg", "AAAA"), ("sel1", "rsa-sha256", "SIGN:sel1")]))
    assert r.ok, r
    assert lookups == ["sel1"]


def test_many_unknown_items_are_linear(lookups):
    items = [(f"x{n}", f"alg{n}", "AAAA") for n in range(4000)]
    items.append(("sel1", "rsa-sha256", "SIGN:sel1"))
    raw = make(items)
    start = time.monotonic()
    r = verify(raw)
    assert r.ok, r.message
    assert time.monotonic() - start < 2.0
    assert lookups == ["sel1"]


@pytest.mark.parametrize("val", ["", "!!!!", "AAA", "####"])
def test_known_algorithm_bad_base64_is_syntax_error(val, lookups):
    r = verify(make([("sel1", "rsa-sha256", val)]))
    assert r.message == "PERMERROR DKIM2-Signature i=1 syntax error", r
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
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel1 algorithm mismatch", r
    assert r.status == "permerror"
    # rsa-sha256 item naming an Ed25519 key
    r = verify(make([("ed25519", "rsa-sha256", "SIGN:sel1")]))
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key ed25519 algorithm mismatch", r


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


SYNTAX = "PERMERROR DKIM2-Signature i=1 public key sel1 has a syntax error"


@pytest.mark.parametrize("rec", [
    f"v=DKIM1; p=; p={RSA_P}",          # repeated tag
    f"v=DKIM1; p={RSA_P}; p={RSA_P}",   # repeated tag, same value
    f"v=garbage; p={RSA_P}",            # bad v=
    f"v=dkim1; p={RSA_P}",              # v= value is case sensitive
    f"k=rsa; v=DKIM1; p={RSA_P}",       # v= not first
    "v=DKIM1; k=rsa",                   # no p=
    "v=DKIM1; k=rsa; p=!!!!",           # p= not base64
    "v=DKIM1; k=rsa; p=AAAA",           # p= not a key
    f"v=DKIM1; k=rsa; p={ED_P}",        # p= not an RSA key
    f"v=DKIM1; 1k=rsa; p={RSA_P}",      # bad tag name
    f"v=DKIM1; k rsa; p={RSA_P}",       # spec without '='
    f"v=DKIM1; P={RSA_P}",              # tag names case sensitive: no p=
])
def test_bad_key_record_is_syntax_error(rec):
    r = _rsa_with(rec)
    assert r.message == SYNTAX, (rec, r)
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
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel1 algorithm mismatch", r
    assert r.status == "permerror"


def test_k_ed25519_for_rsa_signature_is_algorithm_mismatch():
    r = _rsa_with(f"v=DKIM1; k=ed25519; p={ED_P}")
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel1 algorithm mismatch", r


def test_empty_p_is_revoked():
    r = _rsa_with("v=DKIM1; k=rsa; p=")
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel1 has been revoked", r
    assert r.status == "permerror"


def test_two_txt_records_is_multiple_records():
    rec = f"v=DKIM1; k=rsa; p={RSA_P}"
    for pair in ([rec, rec], [rec, "v=spf1 -all"]):
        r = _rsa_with(*pair)
        assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel1 has multiple records", r
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


def test_ed25519_bad_length_is_syntax_error():
    bad = b64(b"\x00" * 40)
    r = verify(make([("ed25519", "ed25519-sha256", "SIGN:ed25519")]),
               _dns_with([["txt", f"v=DKIM1; k=ed25519; p={bad}"]], "ed25519"))
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key ed25519 has a syntax error", r


# --- C. Message-Instance tag case and duplicates -----------------------------

def test_mi_uppercase_h_passes():
    mi = _good_mi_value().replace("h=", "H=")
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi)).ok
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=True).ok


def test_mi_uppercase_m_passes():
    mi = _good_mi_value().replace("m=", "M=")
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi)).ok
    assert verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=True).ok


@pytest.mark.parametrize("mk", [
    lambda good: "m=1; h=sha256:AAAA:AAAA; " + good[5:],      # h= ... h=<correct>
    lambda good: good[:-1] + "; h=sha256:AAAA:AAAA;",          # h=<correct> ... h=
    lambda good: "m=1; H=sha256:AAAA:AAAA; " + good[5:],      # H= ... h=
    lambda good: good + " M=1;",                               # m=1 ... M=1
    lambda good: good + " m=1;",                               # m=1 ... m=1
    lambda good: good + " r=e30=; R=e30=;",                    # r= ... R=
])
@pytest.mark.parametrize("full_chain", [False, True])
def test_mi_duplicate_tag_is_syntax_error(mk, full_chain):
    mi = mk(_good_mi_value())
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], mi), full_chain=full_chain)
    assert not r.ok, mi
    assert "PERMERROR Message-Instance m=1 syntax error" in r.errors, (mi, r)
    assert r.status == "permerror"


# --- D. t= syntax --------------------------------------------------------------

@pytest.mark.parametrize("t", ["garbage", "-5", "1e9", "0x10", "12 34", "+5", "1.5",
                               "١٢"])
@pytest.mark.parametrize("skip", [True, False])
def test_bad_t_is_syntax_error(t, skip):
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1")], t=t),
               skip_timestamp_check=skip)
    assert r.message == "PERMERROR DKIM2-Signature i=1 syntax error", (t, r)
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
    # sel2's record is revoked; sel1 verifies. Whole signature is PERMERROR.
    for rec, why in (("v=DKIM1; k=rsa; p=", "has been revoked"),
                     ("v=DKIM1; k=rsa; p=AAAA", "has a syntax error"),
                     (f"v=DKIM1; k=ed25519; p={ED_P}", "algorithm mismatch")):
        for order in ((0, 1), (1, 0)):
            items = [("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel2")]
            items = [items[i] for i in order]
            r = verify(make(items), _dns_with([["txt", rec]], "sel2"))
            assert r.message == f"PERMERROR DKIM2-Signature i=1 public key sel2 {why}", (rec, r)
            assert r.status == "permerror"
    rec = [v for t, v in DNS[D]["sel2._domainkey"] if t == "txt"][0]
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel2")]),
               _dns_with([["txt", rec], ["txt", rec]], "sel2"))
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel2 has multiple records", r


def test_e_absent_key_item_is_skipped():
    r = verify(make([("nosuch", "rsa-sha256", "SIGN:sel2"), ("sel1", "rsa-sha256", "SIGN:sel1")]))
    assert r.ok, r


def test_e_all_keys_absent_is_does_not_exist():
    r = verify(make([("nosuch", "rsa-sha256", "SIGN:sel1"),
                     ("gone", "ed25519-sha256", "SIGN:ed25519"),
                     ("x", "future-alg", "AAAA")]))
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key nosuch does not exist", r
    assert r.status == "permerror"


def test_e_any_crypto_failure_is_fail_naming_selector():
    # sel2 item carries sel1's signature: verifies with neither key it names
    r = verify(make([("sel1", "rsa-sha256", "SIGN:sel1"), ("sel2", "rsa-sha256", "SIGN:sel1")]))
    assert r.status == "fail", r
    assert r.message.startswith("FAIL DKIM2-Signature i=1 sel2 "), r


def test_e_p_must_be_padded():
    unpadded = ED_P.rstrip("=")
    assert unpadded != ED_P
    r = verify(make([("ed25519", "ed25519-sha256", "SIGN:ed25519")]),
               _dns_with([["txt", f"v=DKIM1; k=ed25519; p={unpadded}"]], "ed25519"))
    assert r.message == "PERMERROR DKIM2-Signature i=1 public key ed25519 has a syntax error", r


def test_e_signature_value_must_be_padded():
    raw = make([("ed25519", "ed25519-sha256", "SIGN:ed25519")])
    head, rest = raw.split(b"s=ed25519:ed25519-sha256:", 1)
    val, tail = rest.split(b";", 1)
    assert val.endswith(b"=")
    r = verify(head + b"s=ed25519:ed25519-sha256:" + val.rstrip(b"=") + b";" + tail)
    assert r.message == "PERMERROR DKIM2-Signature i=1 syntax error", r



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
        assert r.message == "PERMERROR DKIM2-Signature i=1 public key sel2 is shorter than 1024 bits", (items, r)
        assert r.status == "permerror"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
