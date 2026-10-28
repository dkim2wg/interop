"""draft -07 shared behaviour tests (U1..D1 in the -07 upgrade plan).

Keys and DNS for example.com, example.org, ... come from spec07_env, which
generates them for this suite only.
"""
import base64
import email
import os
import sys
import time
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spec07_env as E  # noqa: E402
from spec07_env import add_mi, message, replace_header, sign, verify  # noqa: E402

import dkim2dsn  # noqa: E402
import dkim2sign  # noqa: E402
from dkim2sign import SigningRefused, parse_message  # noqa: E402

WALKS = ("plan", "undo")
INVALID_JSON_2 = "PERMERROR: Message-Instance m=2 contains invalid JSON"


def _hop1(frm="A <a@example.com>", rt=("list@lists.example.org",), **kw):
    raw = kw.pop("raw", None) or message(frm)
    return sign(raw, kw.pop("d", "example.com"),
                kw.pop("mailfrom", "a@example.com"), list(rt), **kw)


def _pass(msg, **kw):
    for walk in WALKS:
        r = verify(msg, walk=walk, **kw)
        assert r.ok and r.status == "pass", (walk, r.errors)


def _fails_with(msg, error, status=None, first=True, **kw):
    # The state is the error's own (-08 moved timestamps, custody and From
    # Authentic from PERMERROR to FAIL, contract D5).
    if status is None:
        status = error.split(":", 1)[0].lower()
    for walk in WALKS:
        r = verify(msg, walk=walk, **kw)
        assert not r.ok, (walk, r.message)
        assert r.status == status, (walk, r.status, r.errors)
        if first:
            assert r.errors[0] == error, (walk, r.errors)
        else:
            assert error in r.errors, (walk, r.errors)


def _to_list(msg, **kw):
    """i=2 by the list example.org, which received the message at
    lists.example.org."""
    return sign(msg, "example.org", kw.pop("mailfrom", "list@lists.example.org"),
                kw.pop("rcptto", ["b@example.net"]), **kw)


# --- U: the "u" Recipe step -------------------------------------------------

def test_u1_utf8_header_literal_is_d():
    hop1 = _hop1(raw=message(subject="café"))
    msg = add_mi(hop1, replace_header(b"Subject", b"x"))
    assert E.mi_recipe(msg, 2) == {"h": {"subject": [{"d": [" café"]}]}}
    _pass(_to_list(msg))


def test_u2_non_utf8_body_line_is_u():
    hop1 = _hop1(raw=message(body=b"line one\r\ncaf\xe9\r\n"))
    msg = add_mi(hop1, lambda h, b: (h, b"line one\r\ncafe\r\n"))
    assert E.mi_recipe(msg, 2) == {"b": [{"c": [1, 1]}, {"u": ["Y2Fm6Q=="]}]}
    _pass(_to_list(msg))


def test_u2_utf8_body_line_stays_d_and_undoes_exactly():
    hop1 = _hop1(raw=message(body="naïve\r\n".encode()))
    msg = add_mi(hop1, lambda h, b: (h, b"naive\r\n"))
    assert E.mi_recipe(msg, 2) == {"b": [{"d": ["naïve"]}]}
    _pass(_to_list(msg))


def _bad_recipe(recipe_json: bytes) -> bytes:
    msg = add_mi(_hop1(), recipe_json=recipe_json)
    return _to_list(msg, skip_upstream_check=True)


def _invalid_json(recipe_json: bytes):
    _fails_with(_bad_recipe(recipe_json), INVALID_JSON_2)


def _invalid_step(recipe_json: bytes, path="b[0]"):
    """-07 called every one of these "contains invalid JSON"; -08 (contract
    D6) names the one bad step instead."""
    _fails_with(_bad_recipe(recipe_json),
                f"PERMERROR: Message-Instance m=2 Recipe {path} is invalid")


def test_u3_u_with_nonzero_pad_bits():
    _invalid_step(b'{"b":[{"u":["QR=="]}]}')


def test_u3_u_not_canonical_base64():
    for item in (b'"QQ"', b'"Q Q=="', b'"QQ=\\n="', b'"QQ==="', b'"****"'):
        _invalid_step(b'{"b":[{"u":[' + item + b']}]}')


def test_u4_bad_step_shapes():
    for steps in (b'{"b":["eA=="]}', b'{"c":[1,1],"d":["x"]}', b'{}'):
        _invalid_step(b'{"b":[' + steps + b']}')


def test_u5_u_decoding_to_cr():
    _invalid_step(b'{"b":[{"u":["YQ1i"]}]}')


def test_u5_empty_h_and_neither_h_nor_b():
    _invalid_json(b'{"h":{}}')
    _invalid_json(b'{"x":1}')


def test_d_with_lone_surrogate():
    # -08: a lone surrogate makes the whole document invalid JSON (it is
    # not a Unicode string, so the text does not parse), not one bad step.
    _invalid_json(b'{"b":[{"d":["\\udc80"]}]}')


def test_d_with_cr():
    _invalid_step(b'{"b":[{"d":["a\\rb"]}]}')


# --- K: JSON keys -------------------------------------------------------------
# -07 decision 2 matched keys case-insensitively; -08 (contract D10, Bron and
# Richard 2026-10-26) reverses it: a key that is not lower case is invalid
# JSON.  So K1's uppercase keys now fail, and K2's case-twins fail too (the
# uppercase one is invalid on its own).

def test_k1_uppercase_keys_are_invalid_json():
    _pass(_to_list(add_mi(_hop1(), recipe_json=b'{"h":{"subject":[{"c":[1,1]}]}}')))
    _invalid_json(b'{"H":{"Subject":[{"C":[1,1]}]}}')


def test_k1_uppercase_literal_step_is_invalid_json():
    msg = add_mi(_hop1(), replace_header(b"Subject", b"Hi"),
                 recipe_json=b'{"h":{"subject":[{"D":[" hello"]}]}}')
    _fails_with(_to_list(msg, skip_upstream_check=True), INVALID_JSON_2)


def test_k2_duplicate_keys_ignoring_case():
    _invalid_json(b'{"h":{"Subject":[],"subject":[]}}')
    _invalid_json(b'{"h":{"subject":[{"c":[1,1],"C":[1,1]}]}}')
    _invalid_json(b'{"b":[{"c":[1,1]}],"B":[{"c":[1,1]}]}')


# --- tag-list syntax (-07 §8) ------------------------------------------------

def test_empty_tag_fragments_are_syntax_errors():
    signed = _hop1()
    bad_mi = signed.replace(b"Message-Instance: m=1; h=",
                            b"Message-Instance: m=1;; h=")
    _fails_with(bad_mi, "PERMERROR: Message-Instance m=1 syntax error")
    bad_sig = signed.replace(b"DKIM2-Signature: i=1;",
                             b"DKIM2-Signature: ; i=1;")
    _fails_with(bad_sig, "PERMERROR: DKIM2-Signature i=1 syntax error")


# --- F: flags -----------------------------------------------------------------

def test_f1_donotmodify_is_not_enforced():
    hop1 = _hop1(flags=["donotmodify"])
    assert E.sig_tag(hop1, 1, "f") == "donotmodify"
    msg = add_mi(hop1, lambda h, b: (h, b + b"footer\r\n"))
    _pass(_to_list(msg))


def test_f2_exploded():
    hop1 = _hop1(exploded=True)
    assert E.sig_tag(hop1, 1, "f") is None
    assert "exploded" not in str(E.sig_tag(_hop1(flags=["exploded"]), 1, "f"))
    hop2 = _to_list(hop1, exploded=True)
    assert E.sig_tag(hop2, 2, "f") == "exploded"
    hop2 = _to_list(hop1, rcptto=["b@example.net", "c@example.net"])
    assert E.sig_tag(hop2, 2, "f") == "exploded"
    hop2 = _to_list(hop1)
    assert E.sig_tag(hop2, 2, "f") is None
    _pass(_to_list(hop1, exploded=True))


def test_f2_cli_exploded():
    import subprocess
    import tempfile
    hop1 = _hop1()
    with tempfile.NamedTemporaryFile(suffix=".eml") as fh:
        fh.write(hop1)
        fh.flush()
        env = dict(os.environ)
        import json
        dnsfile = os.path.join(os.path.dirname(E.keyfile("example.org")),
                               "dns.json")
        with open(dnsfile, "w") as dfh:
            json.dump(E.DNS, dfh)
        out = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(dkim2sign.__file__),
                                          "dkim2sign.py"),
             fh.name, "-s", "sel", "-d", "example.org",
             "-k", E.keyfile("example.org"),
             "--mailfrom", "list@lists.example.org",
             "--rcptto", "b@example.net", "--exploded",
             "--dns-json", dnsfile, "--ignore-timestamps"],
            capture_output=True, env=env, check=True).stdout
    assert E.sig_tag(out, 2, "f") == "exploded"


# --- C: Chain of Custody ------------------------------------------------------

def test_c1_null_mf_at_i2():
    hop2 = _to_list(_hop1(), mailfrom="<>", rcptto=["a@example.com"])
    _pass(hop2)


def test_c1_postfix_style_rt():
    hop1 = _hop1(rt=("<list@Lists.Example.ORG.>",))
    _pass(_to_list(hop1, mailfrom="<>", rcptto=["a@example.com"]))
    _pass(_to_list(hop1))


def test_c2_null_mf_wrong_domain():
    hop2 = sign(_hop1(), "other.net", "<>", ["a@example.com"])
    _fails_with(hop2, "FAIL: DKIM2-Signature i=2 d= does not match "
                      "the rt= of i=1")


def _nd_chain(rt1, d2, d3, **kw3):
    hop1 = _hop1(rt=(rt1,))
    hop2 = sign(hop1, d2, "", next_domain="fwd.example.net")
    return sign(hop2, d3, f"b@{d3}", ["r@example.net"], **kw3)


def test_c3_nd_direction():
    _pass(_nd_chain("x@mail.example.org", "example.org", "fwd.example.net"))
    _fails_with(_nd_chain("x@example.org", "mail.example.org",
                          "fwd.example.net", skip_upstream_check=True),
                "FAIL: DKIM2-Signature i=2 d= does not match the rt= of i=1")


def test_c4_nd_mismatch():
    _fails_with(_nd_chain("x@mail.example.org", "example.org", "other.example",
                          skip_upstream_check=True),
                "FAIL: DKIM2-Signature i=2 nd= does not match")


def test_c5_domain_literals_never_match():
    hop1 = _hop1(rt=("x@[192.0.2.1]",))
    hop2 = sign(hop1, "example.org", "y@[192.0.2.1]", ["r@example.net"])
    _fails_with(hop2, "FAIL: DKIM2-Signature i=2 mf= does not match "
                      "the rt= of i=1", first=False)
    _fails_with(hop2, "FAIL: DKIM2-Signature i=2 MAIL FROM and d= do "
                      "not match", first=False)


def test_c6_mf_vs_d():
    hop1 = _hop1(mailfrom="a@example.net")
    _fails_with(hop1, "FAIL: DKIM2-Signature i=1 MAIL FROM and d= do "
                      "not match")


def test_top_nd_inbound_and_gate():
    hop1 = _hop1(next_domain="fwd.example.net")
    _fails_with(hop1, "FAIL: DKIM2-Signature i=1 unexpected nd= tag")
    # The gate (outbound) lets the domain nd= names sign over it.
    hop2 = sign(hop1, "fwd.example.net", "b@fwd.example.net", ["r@example.net"])
    _pass(hop2)


# --- A: From must be Authentic -------------------------------------------------

def test_a1_from_authentic():
    for frm in ("A <a@example.com>", "a@sub.example.com",
                "=?utf-8?q?Caf=C3=A9?=\r\n <a@example.com>"):
        _pass(_hop1(frm))
    not_auth = "FAIL: DKIM2-Signature i=1 matching From is not authentic"
    _fails_with(_hop1(d="example.net", mailfrom="a@example.net",
                      skip_from_check=True), not_auth)
    for frm in ("a@example.com, b@example.com", "a@[192.0.2.1]",
                "group: a@example.com;", "undisclosed:;"):
        _fails_with(_hop1(frm, skip_from_check=True), not_auth)
    two_froms = message(extra=b"From: a@example.com\r\n")
    _fails_with(_hop1(raw=two_froms, skip_from_check=True), not_auth)
    # Display text with no angle brackets is not one mailbox (final review
    # T3): all five implementations agree.
    _fails_with(_hop1("A a@example.com", skip_from_check=True), not_auth)


def _list_rewrites_from(new_from: bytes):
    return add_mi(_hop1(), replace_header(b"From", new_from))


def test_a2_from_changed_by_list():
    msg = _list_rewrites_from(b"list@lists.example.org")
    assert "from" in E.mi_recipe(msg, 2)["h"]
    _pass(_to_list(msg))
    bad = _to_list(_list_rewrites_from(b"x@elsewhere.net"),
                   skip_from_check=True)
    _fails_with(bad, "FAIL: DKIM2-Signature i=2 matching From is not "
                     "authentic")


def test_a2_gate_refuses_unauthentic_rewritten_from():
    msg = _list_rewrites_from(b"x@elsewhere.net")
    try:
        _to_list(msg)
    except SigningRefused as e:
        assert str(e) == "From header field is not Authentic for d=example.org", e
    else:
        raise AssertionError("signed a rewritten From that is not Authentic")


def _ingress(raw: bytes) -> bytes:
    """An unsigned m=1 over `raw` as it arrived (a list's ingress stamp)."""
    headers, body = parse_message(raw)
    mi = dkim2sign.build_message_instance(headers, body, version=1)
    return mi.encode() + b"\r\n" + raw


def test_a5_from_replaced_before_first_signature_is_not_checked():
    # Ruling 19: i=1 is checked against the From at state m(i=1).  The
    # author's From in an unsigned ingress m=1, rewritten by the list in m=2
    # before it signed i=1 (m=2), was never covered by a signature.
    msg = add_mi(_ingress(message("A <a@elsewhere.net>")),
                 replace_header(b"From", b"list@lists.example.org"))
    assert "from" in E.mi_recipe(msg, 2)["h"]
    _pass(sign(msg, "example.org", "list@lists.example.org"))


def test_a5_from_at_state_m_of_i1_is_checked():
    # i=1 covers m=2; the From at state 2 is not Authentic for d=example.org.
    msg = add_mi(_ingress(message("A <a@example.com>")),
                 replace_header(b"Subject", b"[list] hello"))
    _fails_with(sign(msg, "example.org", "list@lists.example.org",
                     skip_from_check=True),
                "FAIL: DKIM2-Signature i=1 matching From is not authentic")


def test_a3_signer_refuses_unauthentic_from():
    try:
        sign(message("a@example.net"), "example.com", "a@example.com")
    except SigningRefused as e:
        assert str(e) == "From header field is not Authentic for d=example.com", e
    else:
        raise AssertionError("signed a From that is not Authentic")


def test_a4_idn_from():
    hop1 = sign(message("u@bücher.example"), "xn--bcher-kva.example",
                "u@bücher.example", ["r@example.net"])
    mf = base64.b64decode(E.sig_tag(hop1, 1, "mf")).decode()
    assert mf == "<u@xn--bcher-kva.example>", mf
    _pass(hop1)


# --- T: timestamps ---------------------------------------------------------------

def test_t1_future_limit():
    now = int(time.time())
    _pass(_hop1(timestamp=now + 7200), skip_timestamp_check=False)
    _fails_with(_hop1(timestamp=now + 172800),
                "FAIL: DKIM2-Signature i=1 signature is from the future",
                skip_timestamp_check=False)
    _fails_with(_hop1(timestamp=now - 15 * 86400),
                "FAIL: DKIM2-Signature i=1 signature expired",
                skip_timestamp_check=False)


# --- C6 strings this suite can reach directly --------------------------------------

def test_no_dkim2_fields_is_none_without_error():
    r = verify(message())
    assert r.status == "none" and r.errors == [], (r.status, r.errors)


def test_hash_and_signature_failures():
    signed = _hop1()
    _fails_with(signed + b"tampered\r\n",
                "FAIL: Message-Instance m=1 body hash sha256 mismatch",
                status="fail")
    _fails_with(signed.replace(b"Subject: hello", b"Subject: hullo"),
                "FAIL: Message-Instance m=1 header hash sha256 mismatch",
                status="fail")


def test_unsigned_mi():
    msg = add_mi(_hop1(), lambda h, b: (h, b + b"footer\r\n"))
    _fails_with(msg, "PERMERROR: Message-Instance m=2 is not signed")


# --- C9: the primary error is the first in -07 §14 section order --------------------

def _corrupt_sig(msg: bytes, i: int = 1) -> bytes:
    """DKIM2-Signature i=<i>'s first signature value with one base64
    character changed mid-value: still well-formed, no longer valid."""
    head, sep, body = msg.partition(b"\r\n\r\n")
    start = head.index(b"DKIM2-Signature: i=%d;" % i)
    at = head.index(b"-sha256:", start) + len(b"-sha256:") + 10
    c = b"B" if head[at:at + 1] == b"A" else b"A"
    return head[:at] + c + head[at + 1:] + sep + body


def test_c9_tampered_from_is_the_hash_fail():
    # §14.7 before §14.8: a From changed after signing is a hash FAIL.
    msg = _hop1().replace(b"From: A <a@example.com>", b"From: a@evil.example")
    _fails_with(msg, "FAIL: Message-Instance m=1 header hash sha256 mismatch",
                status="fail")


def test_c9_expired_before_custody():
    msg = _hop1(mailfrom="a@example.net", timestamp=int(time.time()) - 15 * 86400)
    _fails_with(msg, "FAIL: DKIM2-Signature i=1 signature expired",
                skip_timestamp_check=False)


def test_c9_expired_before_unexpected_nd():
    msg = _hop1(next_domain="fwd.example.net",
                timestamp=int(time.time()) - 15 * 86400)
    _fails_with(msg, "FAIL: DKIM2-Signature i=1 signature expired",
                skip_timestamp_check=False)


def test_c9_custody_before_signature():
    msg = _corrupt_sig(_hop1(mailfrom="a@example.net"))
    _fails_with(msg, "FAIL: DKIM2-Signature i=1 MAIL FROM and d= do not match")


def test_c9_hash_before_signature():
    # The chain walk (§14.7) before any signature (§14.6): a failing walk is
    # the primary error, whatever is wrong with the signatures.
    msg = _corrupt_sig(_hop1()).replace(b"Subject: hello", b"Subject: hullo")
    _fails_with(msg, "FAIL: Message-Instance m=1 header hash sha256 mismatch",
                status="fail")


def test_c9_lowest_i_first_within_a_section():
    # Both signatures fail §14.6: i=1's is the primary error, though the
    # chain walk reaches i=2 first.
    msg = _corrupt_sig(_corrupt_sig(_to_list(_hop1()), 2), 1)
    _fails_with(msg, "FAIL: DKIM2-Signature i=1 selector sel incorrect signature",
                status="fail")


# --- D: DSNs -----------------------------------------------------------------------

def _wrap_dsn(embedded: bytes) -> bytes:
    report = MIMEMultipart("report", report_type="delivery-status")
    report["From"] = "postmaster@example.net"
    report["To"] = "list@lists.example.org"
    report["Subject"] = "Delivery failure"
    report.attach(MIMEText("delivery failed\n"))
    ds = Message()
    ds.set_type("message/delivery-status")
    per_msg = Message()
    per_msg["Reporting-MTA"] = "dns; example.net"
    per_rcpt = Message()
    per_rcpt["Final-Recipient"] = "rfc822; b@example.net"
    per_rcpt["Action"] = "failed"
    per_rcpt["Status"] = "5.1.1"
    ds.set_payload([per_msg, per_rcpt])
    report.attach(ds)
    rfc822 = Message()
    rfc822.set_type("message/rfc822")
    rfc822.set_payload([email.message_from_bytes(embedded)])
    report.attach(rfc822)
    return report.as_bytes()


def _no_dsn(embedded):
    dsn = _wrap_dsn(embedded)
    try:
        dkim2dsn.propagate(dsn, forwarder_domain="example.org",
                           keyfile=E.keyfile("example.org"), selector="sel",
                           domain="example.org", skip_authentication=True)
    except ValueError as e:
        assert "<>" in str(e), e
    else:
        raise AssertionError("propagated a DSN for a null MAIL FROM")


def test_d1_no_dsn_for_null_mail_from():
    # Upstream (i=1) sent with MAIL FROM <>.
    _no_dsn(_to_list(_hop1(mailfrom="<>")))
    # The forwarder's own hop (the top signature) used MAIL FROM <>.
    _no_dsn(_to_list(_hop1(), mailfrom="<>", rcptto=["b@example.net"]))


def test_propagated_dsn_from_is_the_forwarders():
    # The propagated DSN is a new message signed by the Forwarder (i=1), so
    # the reporting system's From is replaced with one Authentic for it.
    dsn = _wrap_dsn(_to_list(_hop1()))
    out = dkim2dsn.propagate(dsn, forwarder_domain="example.org",
                             keyfile=E.keyfile("example.org"), selector="sel",
                             domain="example.org", skip_authentication=True)
    headers, _ = parse_message(out["raw"])
    froms = [h for h in headers if h.lower().startswith(b"from:")]
    assert froms == [b"From: Mail Delivery System <MAILER-DAEMON@example.org>"], froms
    assert out["upstream_mailfrom"] == "<a@example.com>"
    _pass(out["raw"])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("spec-07 shared tests OK")
