"""draft -09 contract tests (docs/superpowers/specs/2026-11-03-dkim2-spec-09-design.md).

Each section names the contract item it pins (E1-E6).  Keys and DNS for
example.com, example.org, mail.example.org, ... come from spec07_env
(generated for the test suite only); Domain Policy Records are added to a
copy of that DNS per test.
"""
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spec07_env as E  # noqa: E402
from spec07_env import add_mi, message, replace_header, sign  # noqa: E402

import dkim2verify  # noqa: E402
from dkim2dns import DNSTempError, LiveDNS  # noqa: E402
from dkim2verify import (  # noqa: E402
    POLICY_MULTIPLE, POLICY_OPEN, POLICY_STRICT, policy_state,
)

WALKS = ("plan", "undo")


def _verify(msg, dns=None, **kw):
    kw.setdefault("skip_timestamp_check", True)
    out = []
    for walk in WALKS:
        r = dkim2verify.verify_message(msg, E.DNS if dns is None else dns,
                                       full_chain=True, walk=walk, **kw)
        out.append((r.ok, r.status, r.message, r.errors))
    assert out[0] == out[1], out
    return r


def _fails_with(msg, error, dns=None, **kw):
    r = _verify(msg, dns, **kw)
    assert not r.ok and r.message == error, r.errors
    assert r.status == error.split(":", 1)[0].lower(), (r.status, r.errors)
    return r


def _pass(msg, dns=None, **kw):
    r = _verify(msg, dns, **kw)
    assert r.ok and r.status == "pass", r.errors
    return r


def _hop1(frm="A <a@example.com>", d="example.com", raw=None, mailfrom=None,
          **kw):
    raw = raw or message(frm)
    kw.setdefault("skip_from_check", True)
    return sign(raw, d, mailfrom or f"a@{d}", ["list@lists.example.org"], **kw)


def _dns_policy(records, dom="example.org"):
    """spec07_env's DNS with these TXT records at _domainkey.<dom>."""
    d = copy.deepcopy(E.DNS)
    d.setdefault(dom, {})["_domainkey"] = [["TXT", r] for r in records]
    return d


# --- E1: NONE ------------------------------------------------------------------

def test_e1_no_dkim2_fields_is_none():
    r = dkim2verify.verify_message(message(), E.DNS, full_chain=True)
    assert r.status == "none" and not r.ok and r.errors == []
    assert r.message == "NONE: No DKIM2 header fields found"
    assert r.fully_verified is False


def test_e1_instances_only_is_not_none():
    msg = add_mi(_hop1(), replace_header(b"Subject", b"x"))
    # Drop the signature: instances with no signature are a PERMERROR.
    lines = [ln for ln in msg.split(b"\r\n") if not ln.startswith(b"DKIM2-Signature:")]
    r = _verify(b"\r\n".join(lines))
    assert r.status == "permerror"


# --- E2: a null Recipe is a PERMERROR -----------------------------------------

NULL_B = b'{"b":null}'


def _list_null(msg=None, m_extra=None):
    """A list hop over an unsigned instance whose Recipe is a null body."""
    msg = add_mi(msg or _hop1(), recipe_json=NULL_B)
    return sign(msg, "example.org", "list@lists.example.org", ["b@example.net"],
                skip_upstream_check=True)


def test_e2_signed_null_is_permerror():
    _fails_with(_list_null(), "PERMERROR: Message-Instance m=2 has a null recipe")


def test_e2_null_at_m1_with_nothing_below_is_permerror():
    # Nothing below m=1 could be checked anyway; still a PERMERROR.
    import dkim2sign
    headers, body = E.parse_message(message())
    mi = dkim2sign.build_message_instance(headers, body, version=1,
                                          recipe={"b": None})
    raw = mi.encode() + b"\r\n" + message()
    signed = sign(raw, "example.com", "a@example.com", ["b@example.net"],
                  skip_upstream_check=True)
    assert signed.count(b"Message-Instance:") == 1
    _fails_with(signed, "PERMERROR: Message-Instance m=1 has a null recipe")


def test_e2_lowest_null_is_named():
    two = _list_null(_list_null())
    _fails_with(two, "PERMERROR: Message-Instance m=2 has a null recipe")


def test_e2_lower_recipe_fault_beats_higher_null():
    bad = add_mi(_hop1(), recipe_json=b'{"b":[{"c":[2,2]},{"c":[1,1]}]}')
    bad = sign(bad, "example.org", "list@lists.example.org", ["b@example.net"],
               skip_upstream_check=True)
    _fails_with(_list_null(bad), "PERMERROR: Message-Instance m=2 recipe b[1] is invalid")


def test_e2_own_recipe_fault_beats_own_null():
    # A step check of the same instance comes first, then its null check;
    # a duplicate "b" is a whole-document fault.
    msg = add_mi(_hop1(), recipe_json=b'{"h":{"subject":[{"x":1}]},"b":null}')
    msg = sign(msg, "example.org", "list@lists.example.org", ["b@example.net"],
               skip_upstream_check=True)
    _fails_with(msg, "PERMERROR: Message-Instance m=2 recipe h.subject[0] is invalid")


def test_e2_structure_error_wins():
    msg = _list_null()
    # Remove the m=1 instance: a gap is a structure error.
    lines = msg.split(b"\r\n")
    lines = [ln for ln in lines if not ln.startswith(b"Message-Instance: m=1;")]
    r = _verify(b"\r\n".join(lines))
    assert r.message == "PERMERROR: Message-Instance m=1 missing", r.errors


def test_e2_outbound_skips_unsigned_null_only():
    unsigned = add_mi(_hop1(), recipe_json=NULL_B)
    r = _verify(unsigned, allow_unsigned_mi=True)
    assert r.ok and r.fully_verified, r.errors
    r = _verify(_list_null(), allow_unsigned_mi=True)
    assert r.message == "PERMERROR: Message-Instance m=2 has a null recipe"


def test_e2_signer_signs_over_its_own_null():
    out = sign(add_mi(_hop1(), recipe_json=NULL_B), "example.org",
               "list@lists.example.org", ["b@example.net"])
    assert out.startswith(b"DKIM2-Signature:")
    _fails_with(out, "PERMERROR: Message-Instance m=2 has a null recipe")


def test_e2_signer_refuses_a_signed_null():
    import dkim2sign
    with pytest.raises(dkim2sign.SigningRefused, match="has a null recipe"):
        sign(_list_null(), "example.net", "fwd@example.net", ["c@other.net"])


def test_e2_fully_verified_is_true_exactly_for_a_pass():
    assert _pass(_hop1()).fully_verified is True
    assert _verify(_list_null()).fully_verified is False


# --- E3.1: the From checks -------------------------------------------------------

SIG1 = "DKIM2-Signature i=1"


@pytest.mark.parametrize("frm,want", [
    ("a@example.com, b@example.com", "From has more than one address"),
    ("g: a@example.com, b@example.com;", "From has more than one address"),
    ('"Smith, J" <a@example.com>', None),               # comma quoted
    ("a@example.com (Smith, J)", None),                 # comma in a comment
    ('"x\\" , y" <a@example.com>', None),               # escaped quote
    ("g: a@example.com;", "matching From is not authentic"),
    ("undisclosed:;", "matching From is not authentic"),
    ("nobody", "matching From is not authentic"),
    ("A a@example.com", "matching From is not authentic"),
    ("a@[192.0.2.1]", "From uses a domain literal"),
    ("A <a@[192.0.2.1]>", "From uses a domain literal"),
    ("a@example.org", "matching From is not authentic"),
])
def test_e3_from_classification(frm, want):
    msg = _hop1(frm)
    if want is None:
        _pass(msg)
    else:
        _fails_with(msg, f"FAIL: {SIG1} {want}")


def test_e3_two_from_fields():
    raw = message(extra=b"From: a@example.com\r\n")
    _fails_with(_hop1(raw=raw), f"FAIL: {SIG1} From has more than one address")


def test_e3_no_from_field():
    raw = b"To: b@example.org\r\nSubject: s\r\n\r\nbody\r\n"
    _fails_with(_hop1(raw=raw), f"FAIL: {SIG1} matching From is not authentic")


# --- E3: up/down and the Domain Policy Record ------------------------------------

SUB = "mail.example.org"


def _sub_signed(frm="a@example.org"):
    return _hop1(frm, d=SUB)


def test_e3_upward_match_with_no_policy_passes():
    _pass(_sub_signed())


@pytest.mark.parametrize("records,state", [
    ([], POLICY_OPEN),
    (["v=DKIM1"], POLICY_OPEN),
    (["v=DKIM1;"], POLICY_OPEN),
    (["v=DKIM1; f="], POLICY_OPEN),
    (["v=DKIM1; f=foo"], POLICY_OPEN),
    (["v=DKIM1; f=Strict"], POLICY_OPEN),               # case-sensitive flag
    (["v=DKIM1; f=strict"], POLICY_STRICT),
    (["v=DKIM1; f=foo:strict"], POLICY_STRICT),
    (["v=DKIM1; f=foo : strict"], POLICY_STRICT),
    (["v=DKIM1; f=a-b:strict"], POLICY_STRICT),
    ([" v = DKIM1 ; f=strict"], POLICY_STRICT),         # WSP around the first tag
    (["v=DKIM1; f=strict:"], POLICY_STRICT),            # empty member: malformed
    (["v=DKIM1; f=a::b"], POLICY_STRICT),
    (["v=DKIM1; f=a-"], POLICY_STRICT),                 # not a hyphenated-word
    (["v=DKIM1; f=1a"], POLICY_STRICT),
    (["v=DKIM1; f=foo bar"], POLICY_STRICT),
    (["v=DKIM1; f=strict; f=foo"], POLICY_STRICT),      # duplicate tag
    (["v=DKIM1; junk"], POLICY_STRICT),                 # unparseable
    (["v=DKIM1; x=\x00"], POLICY_STRICT),
    (["v=DKIM1; X=1; f=foo"], POLICY_OPEN),             # unknown tags ignored
    (["v=dkim1; f=strict"], POLICY_OPEN),               # not v=DKIM1: ignored
    (["v=DKIM1x; f=strict"], POLICY_OPEN),
    (["f=strict"], POLICY_OPEN),
    (["v=spf1 -all"], POLICY_OPEN),
    (["v=spf1 -all", "v=DKIM1; f=strict"], POLICY_STRICT),
    (["v=DKIM1", "v=DKIM1; f=strict"], POLICY_MULTIPLE),
    (["v=DKIM1; junk", "v=DKIM1"], POLICY_MULTIPLE),    # counted before parsing
])
def test_e3_policy_state(records, state):
    assert policy_state(records) == state


def test_e3_policy_state_long_record():
    # The record is attacker-served: a long WSP run is handled (linearly)
    # and still parsed exactly.
    pad = " " * 65000
    assert policy_state([f"v=DKIM1;{pad}f=strict{pad}"]) == POLICY_STRICT
    assert policy_state([f"v=DKIM1; f=foo{pad}x"]) == POLICY_STRICT
    assert policy_state([f"{pad}v{pad}={pad}DKIM1{pad}"]) == POLICY_OPEN


@pytest.mark.parametrize("records,want", [
    (["v=DKIM1; f=strict"], f"FAIL: {SIG1} From example.org forbids subdomain signing"),
    (["v=DKIM1; f=strict; f=x"], f"FAIL: {SIG1} From example.org forbids subdomain signing"),
    (["v=DKIM1", "v=DKIM1"], f"PERMERROR: {SIG1} multiple records for example.org policy"),
    (["v=DKIM1; f=foo"], None),
    (["v=spf1 -all", "f=strict"], None),
])
def test_e3_policy_outcomes(records, want):
    dns = _dns_policy(records)
    if want is None:
        _pass(_sub_signed(), dns)
    else:
        _fails_with(_sub_signed(), want, dns)


def test_e3_policy_domain_is_lowercased_alabel():
    dns = _dns_policy(["v=DKIM1; f=strict"])
    _fails_with(_sub_signed("A <a@Example.ORG>"),
                f"FAIL: {SIG1} From example.org forbids subdomain signing", dns)


def test_e3_no_inheritance():
    # A strict record at the parent's parent, or at d=, is not consulted.
    dns = _dns_policy(["v=DKIM1; f=strict"], "org")
    dns[SUB]["_domainkey"] = [["TXT", "v=DKIM1; f=strict"]]
    _pass(_sub_signed(), dns)


def test_e3_sibling_is_not_authentic():
    # mail.example.org and lists.example.org: neither is below the other.
    _fails_with(_hop1("a@mail.example.org", d="lists.example.org"),
                f"FAIL: {SIG1} matching From is not authentic")


class _Policies:
    """A policy_source: answers from a dict, counts calls, TEMPERRORs."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, dom):
        self.calls.append(dom)
        a = self.answers.get(dom)
        if a == "TEMP":
            raise DNSTempError("SERVFAIL")
        return a


def test_e3_policy_source_hook():
    src = _Policies({"example.org": ["v=DKIM1; f=strict"]})
    r = dkim2verify.verify_message(_sub_signed(), E.DNS, full_chain=True,
                                   skip_timestamp_check=True, policy_source=src)
    assert r.message == f"FAIL: {SIG1} From example.org forbids subdomain signing"
    assert src.calls == ["example.org"]


def test_e3_policy_temperror():
    src = _Policies({"example.org": "TEMP"})
    r = dkim2verify.verify_message(_sub_signed(), E.DNS, full_chain=True,
                                   skip_timestamp_check=True, policy_source=src)
    assert r.status == "temperror"
    assert r.message == f"TEMPERROR: {SIG1} policy for example.org unavailable"


def test_e3_no_lookup_for_downward_match():
    src = _Policies({})
    r = dkim2verify.verify_message(_hop1(), E.DNS, full_chain=True,
                                   skip_timestamp_check=True, policy_source=src)
    assert r.ok and src.calls == []


def test_e3_no_lookup_when_message_already_has_an_error():
    # A bad signature (§14.6) is the first error: no policy lookup.
    msg = _sub_signed().replace(b"Subject: hello", b"Subject: hellp")
    src = _Policies({"example.org": "TEMP"})
    r = dkim2verify.verify_message(msg, E.DNS, full_chain=True,
                                   skip_timestamp_check=True, policy_source=src)
    assert not r.ok and src.calls == [] and r.status != "temperror", r.errors


def test_e3_one_lookup_per_domain():
    # i=1 (mail.example.org) and i=2 (lists.example.org, which changed From
    # to another address at example.org) both match upward to example.org.
    msg = add_mi(_sub_signed(), replace_header(b"From", b"b@example.org"))
    msg = sign(msg, "lists.example.org", "list@lists.example.org",
               ["b@example.net"], skip_upstream_check=True, skip_from_check=True)
    src = _Policies({"example.org": ["v=DKIM1"]})
    r = dkim2verify.verify_message(msg, E.DNS, full_chain=True,
                                   skip_timestamp_check=True, policy_source=src)
    assert r.ok, r.errors
    assert src.calls == ["example.org"]


def test_e3_policy_errors_rank_as_section_14_8():
    # A policy TEMPERROR is a §14.8 error, not a §14.5 key TEMPERROR, even
    # though "TEMPERROR:" starts it (contract C9 ranking).
    assert dkim2verify._c9_key(
        f"TEMPERROR: {SIG1} policy for example.org unavailable")[0] == 8
    assert dkim2verify._c9_key(
        f"PERMERROR: {SIG1} multiple records for example.org policy")[0] == 8


class _Resolver:
    """A dnspython stand-in for LiveDNS: answers from a dns.json dict."""

    def __init__(self, dns, servfail=()):
        self.dns, self.servfail = dns, set(servfail)
        self.calls = []

    def query_txt(self, name):
        self.calls.append(name)
        if name in self.servfail:
            return "SERVFAIL", []
        label, _, dom = name.partition("._domainkey.")
        if not dom:
            label, dom = "_domainkey", name[len("_domainkey."):]
        else:
            label += "._domainkey"
        recs = (self.dns.get(dom) or {}).get(label)
        if recs is None:
            return "NXDOMAIN", []
        return "NOERROR", [[v.encode()] for t, v in recs if t.upper() == "TXT"]


@pytest.mark.parametrize("prefetch", [False, True])
def test_e3_live_dns_policy(prefetch):
    res = _Resolver(_dns_policy(["v=DKIM1; f=strict"]))
    r = dkim2verify.verify_message(_sub_signed(), LiveDNS(res, prefetch=prefetch),
                                   full_chain=True, skip_timestamp_check=True)
    assert r.message == f"FAIL: {SIG1} From example.org forbids subdomain signing"
    assert res.calls.count("_domainkey.example.org") == 1


def test_e3_live_dns_policy_never_prefetched():
    res = _Resolver(E.DNS)
    keys = LiveDNS(res).for_message()
    names = []
    real = keys.prefetch
    keys.prefetch = lambda n: (names.extend(n), real(n))
    dkim2verify.verify_message(_sub_signed(), type("S", (), {
        "for_message": lambda self: keys})(), full_chain=True,
        skip_timestamp_check=True)
    assert names and not any(n.startswith("_domainkey.") for n in names), names


def test_e3_live_dns_policy_nxdomain_and_servfail():
    res = _Resolver(E.DNS)
    _pass(_sub_signed(), LiveDNS(res, prefetch=False))
    res = _Resolver(E.DNS, servfail={"_domainkey.example.org"})
    r = dkim2verify.verify_message(_sub_signed(), LiveDNS(res, prefetch=False),
                                   full_chain=True, skip_timestamp_check=True)
    assert r.message == f"TEMPERROR: {SIG1} policy for example.org unavailable"


# --- E4: key records next to a foreign TXT record --------------------------------

def _with_key_records(extra, before=False):
    d = copy.deepcopy(E.DNS)
    recs = d["example.com"]["sel._domainkey"]
    extra = [["TXT", x] for x in extra]
    d["example.com"]["sel._domainkey"] = extra + recs if before else recs + extra
    return d


@pytest.mark.parametrize("before", [False, True])
def test_e4_foreign_v_record_is_ignored(before):
    _pass(_hop1(), _with_key_records(["v=spf1 -all"], before))


def test_e4_record_without_v_is_counted():
    _fails_with(_hop1(), "PERMERROR: DKIM2-Signature i=1 public key sel has multiple records",
                _with_key_records(["k=rsa; p=AAAA"]))


def test_e4_unparseable_record_is_counted():
    _fails_with(_hop1(), "PERMERROR: DKIM2-Signature i=1 public key sel has multiple records",
                _with_key_records(["garbage"]))


def test_e4_only_foreign_records_is_no_key():
    d = copy.deepcopy(E.DNS)
    d["example.com"]["sel._domainkey"] = [["TXT", "v=spf1 -all"]]
    _fails_with(_hop1(), "PERMERROR: DKIM2-Signature i=1 public key sel does not exist", d)


# --- E5: RSA too short -----------------------------------------------------------

def test_e5_rsa_under_1024_bits_is_too_short():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.RSAPublicNumbers(65537, (1 << 1022) | 0x1234567).public_key()
    p = E.b64(key.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo))
    d = copy.deepcopy(E.DNS)
    d["example.com"]["sel._domainkey"] = [["TXT", f"v=DKIM1; k=rsa; p={p}"]]
    # The signature is Ed25519, but the key's own fault is reported first.
    r = _verify(_hop1(), d)
    assert r.message == "PERMERROR: DKIM2-Signature i=1 public key sel too short", r.errors


# --- E6: strings and the exploded flag at i=1 ------------------------------------

def test_e6_exploded_at_i1():
    msg = _hop1()
    # The signer never writes it at i=1; add it (before any key fetch, so
    # the broken signature does not matter).
    msg = msg.replace(b"DKIM2-Signature: i=1;", b"DKIM2-Signature: i=1; f=feedback, exploded;", 1)
    assert b"f=feedback, exploded;" in msg
    _fails_with(msg, "PERMERROR: DKIM2-Signature i=1 has an exploded flag")


def test_e6_exploded_above_i1_is_fine():
    msg = add_mi(_hop1(), replace_header(b"Subject", b"x"))
    out = sign(msg, "example.org", "list@lists.example.org",
               ["b@example.net", "c@example.net"])
    assert b"exploded" in out
    _pass(out)


def test_e6_exploded_check_before_duplicate_selector():
    msg = _hop1()
    head, sep, rest = msg.partition(b"; s=")
    item = rest.split(b";", 1)[0]
    dup = head + b"; f=exploded; s=" + item + b"," + item + b";" + rest.split(b";", 1)[1]
    _fails_with(dup, "PERMERROR: DKIM2-Signature i=1 has an exploded flag")


def test_e6_duplicates_and_mf():
    msg = _hop1()
    sig = msg.split(b"\r\n", 1)[0]
    _fails_with(sig + b"\r\n" + msg, "PERMERROR: DKIM2-Signature i=1 is duplicated")
    _fails_with(_hop1(mailfrom="a@example.net"),
                "FAIL: DKIM2-Signature i=1 mf= and d= do not match")
