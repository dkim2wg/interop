import email
import os
import sys
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2sign  # noqa: E402
import dkim2dsn  # noqa: E402
import dkim2verify  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS = os.path.join(os.path.dirname(__file__), "..", "..", "keys")
DNS_DATA = dkim2verify.load_dns_json(os.path.join(REPO_ROOT, "dns.json"))


def _key(sel, dom):
    return os.path.join(KEYS, f"{sel}._domainkey.{dom}.pem")


def _two_hop_embedded():
    raw = (b"From: sender@origin.example\r\n"
           b"To: user@test1.dkim2.com\r\n"
           b"Subject: hello\r\n\r\nbody line\r\n")
    hop1 = dkim2sign.sign_message(
        raw, "rsa1024", "test1.dkim2.com", _key("rsa1024", "test1.dkim2.com"),
        mailfrom="sender@origin.example", rcptto=["user@test2.dkim2.com"],
        timestamp=1740000000)
    # forwarder modifies the body, then signs i=2 / m=2
    hop1_mod = hop1.replace(b"body line\r\n", b"body line\r\nforwarder footer\r\n")
    hop2 = dkim2sign.sign_message(
        hop1_mod, "rsa1024", "test2.dkim2.com", _key("rsa1024", "test2.dkim2.com"),
        mailfrom="user@test2.dkim2.com", rcptto=["dest@test3.dkim2.com"],
        timestamp=1740000000)
    return hop2


def _wrap_dsn(embedded: bytes) -> bytes:
    report = MIMEMultipart("report", report_type="delivery-status")
    report["From"] = "postmaster@test3.dkim2.com"
    report["To"] = "user@test2.dkim2.com"
    report["Subject"] = "Delivery failure"
    report.attach(MIMEText("delivery failed\n"))
    ds = Message()
    ds.set_type("message/delivery-status")
    per_msg = Message()
    per_msg["Reporting-MTA"] = "dns; test3.dkim2.com"
    per_rcpt = Message()
    per_rcpt["Final-Recipient"] = "rfc822; dest@test3.dkim2.com"
    per_rcpt["Action"] = "failed"
    per_rcpt["Status"] = "5.1.1"
    ds.set_payload([per_msg, per_rcpt])
    report.attach(ds)
    rfc822 = Message()
    rfc822.set_type("message/rfc822")
    rfc822.set_payload([email.message_from_bytes(embedded)])
    report.attach(rfc822)
    return report.as_bytes()


def _wrap_dsn_no_delivery_status(embedded: bytes) -> bytes:
    """A multipart/report with >=3 parts but no message/delivery-status part
    (violates the RFC 6522 3-part structure)."""
    report = MIMEMultipart("report", report_type="delivery-status")
    report["From"] = "postmaster@test3.dkim2.com"
    report["To"] = "user@test2.dkim2.com"
    report["Subject"] = "Delivery failure"
    report.attach(MIMEText("delivery failed\n"))
    # Second part is plain text instead of message/delivery-status.
    report.attach(MIMEText("not a delivery-status part\n"))
    rfc822 = Message()
    rfc822.set_type("message/rfc822")
    rfc822.set_payload([email.message_from_bytes(embedded)])
    report.attach(rfc822)
    return report.as_bytes()


# propagate() authenticates the DSN first (§12.1.2) unless told it has been
# done already. The fixtures below deliberately do NOT verify (hop 1 signs
# d=test1.dkim2.com over a sender@origin.example envelope, which the d=/mf=
# rule rejects), because they exist to exercise the rebuild machinery -- so
# they pass skip_authentication and the authentication is tested separately.
def test_propagate_rejects_missing_delivery_status():
    dsn = _wrap_dsn_no_delivery_status(_two_hop_embedded())
    try:
        dkim2dsn.propagate(
            dsn, forwarder_domain="test2.dkim2.com",
            keyfile=_key("ed25519", "test3.dkim2.com"),
            selector="ed25519", domain="test3.dkim2.com", timestamp=1740000000,
            skip_authentication=True)
        assert False, "propagate should reject a DSN with no message/delivery-status part"
    except ValueError as e:
        assert "delivery-status" in str(e), str(e)


def test_propagate_accepts_wellformed_three_part_dsn():
    dsn = _wrap_dsn(_two_hop_embedded())
    msg = email.message_from_bytes(dsn)
    parts = msg.get_payload()
    assert len(parts) == 3
    assert parts[0].get_content_type() == "text/plain"
    assert parts[1].get_content_type() == "message/delivery-status"
    assert parts[2].get_content_type() == "message/rfc822"

    out = dkim2dsn.propagate(
        dsn, forwarder_domain="test2.dkim2.com",
        keyfile=_key("ed25519", "test3.dkim2.com"),
        selector="ed25519", domain="test3.dkim2.com", timestamp=1740000000,
        skip_authentication=True)
    assert out["upstream_mailfrom"] == "<sender@origin.example>", out["upstream_mailfrom"]


def test_propagate_basic():
    dsn = _wrap_dsn(_two_hop_embedded())
    out = dkim2dsn.propagate(
        dsn, forwarder_domain="test2.dkim2.com",
        keyfile=_key("ed25519", "test3.dkim2.com"),
        selector="ed25519", domain="test3.dkim2.com", timestamp=1740000000,
        skip_authentication=True)

    # After undoing the forwarder hop (i=2/m=2), the now-top signature is i=1
    # with mf=<sender@origin.example> (spec 7.5: mf= is a bracketed RFC5321 path).
    assert out["upstream_mailfrom"] == "<sender@origin.example>", out["upstream_mailfrom"]

    msg = email.message_from_bytes(out["raw"])
    assert msg.get_content_type() == "multipart/report"
    headers, _ = dkim2sign.parse_message(out["raw"])
    mis = [h for h in headers if dkim2sign._header_name(h) == b"message-instance"]
    sigs = [h for h in headers if dkim2sign._header_name(h) == b"dkim2-signature"]
    assert len(mis) == 1, f"{len(mis)} MIs (want 1, new message)"
    assert len(sigs) == 1, f"{len(sigs)} sigs (want 1, new message)"


# --- authenticate: §12.1.2, the returned original's chain must verify -------

# The fixture above never verifies (hop 1 signs d=test1.dkim2.com over a
# sender@origin.example envelope, which the d=/mf= rule rejects), which the
# propagate tests never needed. authenticate does, so build a chain that
# holds: test1 originates to a user at test2, who forwards to test3.
def _verifiable_twohop() -> bytes:
    raw = (b"From: Sender <sender@test1.dkim2.com>\r\n"
           b"To: user@test2.dkim2.com\r\n"
           b"Subject: hello\r\n\r\nbody line\r\n")
    hop1 = dkim2sign.sign_message(
        raw, "rsa1024", "test1.dkim2.com", _key("rsa1024", "test1.dkim2.com"),
        mailfrom="sender@test1.dkim2.com", rcptto=["user@test2.dkim2.com"],
        timestamp=1740000000)
    return dkim2sign.sign_message(
        hop1, "rsa1024", "test2.dkim2.com", _key("rsa1024", "test2.dkim2.com"),
        mailfrom="user@test2.dkim2.com", rcptto=["dest@test3.dkim2.com"],
        timestamp=1740000000)


def _wrap_dsn_headers_only(embedded: bytes) -> bytes:
    """A DSN whose returned original is text/rfc822-headers (no body)."""
    headers, _ = dkim2sign.parse_message(embedded)
    hdr_text = b"".join(h + b"\r\n" for h in headers)

    report = MIMEMultipart("report", report_type="delivery-status")
    report["From"] = "postmaster@test3.dkim2.com"
    report["To"] = "user@test2.dkim2.com"
    report["Subject"] = "Delivery failure"
    report.attach(MIMEText("delivery failed\n"))
    ds = Message()
    ds.set_type("message/delivery-status")
    per_msg = Message()
    per_msg["Reporting-MTA"] = "dns; test3.dkim2.com"
    per_rcpt = Message()
    per_rcpt["Final-Recipient"] = "rfc822; dest@test3.dkim2.com"
    per_rcpt["Action"] = "failed"
    per_rcpt["Status"] = "5.1.1"
    ds.set_payload([per_msg, per_rcpt])
    report.attach(ds)
    hdrs = Message()
    hdrs.set_type("text/rfc822-headers")
    hdrs.set_payload(hdr_text.decode("utf-8", "surrogateescape"))
    report.attach(hdrs)
    return report.as_bytes()


def test_authenticate_intact_two_hop():
    auth = dkim2dsn.authenticate(_wrap_dsn(_verifiable_twohop()), DNS_DATA,
                                 skip_timestamp_check=True)
    assert auth["ok"], auth["message"]
    assert auth["headers_only"] is False
    # The forwarder recognises i=2 as its own by d= (§12.1.2 point 2).
    assert auth["top"]["i"] == 2, auth["top"]
    assert auth["top"]["d"] == "test2.dkim2.com", auth["top"]
    assert auth["top"]["mf"] == "<user@test2.dkim2.com>", auth["top"]


def test_authenticate_headers_only():
    auth = dkim2dsn.authenticate(
        _wrap_dsn_headers_only(_verifiable_twohop()), DNS_DATA,
        skip_timestamp_check=True)
    assert auth["ok"], auth["message"]
    assert auth["headers_only"] is True
    assert auth["top"]["i"] == 2, auth["top"]


def test_authenticate_rejects_tampered_headers():
    tampered = _verifiable_twohop().replace(b"Subject: hello",
                                            b"Subject: hullo")
    for wrap in (_wrap_dsn, _wrap_dsn_headers_only):
        auth = dkim2dsn.authenticate(wrap(tampered), DNS_DATA,
                                     skip_timestamp_check=True)
        assert not auth["ok"], f"{wrap.__name__} should not authenticate"
        assert any("header hash mismatch" in e for e in auth["errors"]), auth["errors"]


def test_authenticate_unsigned_original_reports_none():
    plain = b"From: a@b.example\r\nTo: c@d.example\r\nSubject: plain\r\n\r\nhi\r\n"
    auth = dkim2dsn.authenticate(_wrap_dsn(plain), DNS_DATA)
    assert not auth["ok"]
    # 'none', so a caller can fall back to legacy DSN handling.
    assert auth["status"] == "none", auth["status"]
    assert auth["top"] is None


# --- propagate: a Forwarder's §9.3 bridge goes with its hop ----------------

def _bridged_twohop() -> bytes:
    """test1 -> user@test2; test2 bridges with nd= and sends from test3."""
    raw = (b"From: Sender <sender@test1.dkim2.com>\r\n"
           b"To: user@test2.dkim2.com\r\n"
           b"Subject: bridged\r\n\r\nbody line\r\n")
    msg = dkim2sign.sign_message(
        raw, "sel1", "test1.dkim2.com", _key("sel1", "test1.dkim2.com"),
        mailfrom="sender@test1.dkim2.com", rcptto=["user@test2.dkim2.com"],
        timestamp=1740000000)
    msg = dkim2sign.sign_message(
        msg, "sel1", "test2.dkim2.com", _key("sel1", "test2.dkim2.com"),
        next_domain="test3.dkim2.com", timestamp=1740000000)
    return dkim2sign.sign_message(
        msg, "sel1", "test3.dkim2.com", _key("sel1", "test3.dkim2.com"),
        mailfrom="srs0=x@bounce.test3.dkim2.com", rcptto=["dest@test5.dkim2.com"],
        timestamp=1740000000)


def test_authenticate_bridged_chain():
    auth = dkim2dsn.authenticate(_wrap_dsn(_bridged_twohop()), DNS_DATA,
                                 skip_timestamp_check=True)
    assert auth["ok"], auth["message"]
    assert auth["top"]["i"] == 3, auth["top"]


def test_propagate_strips_the_bridge_with_its_hop():
    # This chain verifies, so propagate can do its own §12.1.2 authentication
    # rather than being told to skip it.
    out = dkim2dsn.propagate(
        _wrap_dsn(_bridged_twohop()), forwarder_domain="test3.dkim2.com",
        keyfile=_key("sel1", "test2.dkim2.com"),
        selector="sel1", domain="test2.dkim2.com", timestamp=1740000000,
        dns_data=DNS_DATA, skip_timestamp_check=True)
    # The report goes to the hop before both: the bridge is not a hop of its
    # own, and an nd= signature is never valid as the top of a chain.
    assert out["upstream_mailfrom"] == "<sender@test1.dkim2.com>", out["upstream_mailfrom"]

    msg = email.message_from_bytes(out["raw"])
    orig = [p for p in msg.get_payload()
            if p.get_content_type() == "message/rfc822"][0]
    inner = dkim2dsn._embedded_bytes(orig)
    headers, _ = dkim2sign.parse_message(inner)
    sigs = [h.decode() for h in headers
            if dkim2sign._header_name(h) == b"dkim2-signature"]
    assert len(sigs) == 1, sigs
    assert not dkim2sign._extract_tag(dkim2dsn._hval(sigs[0]), "nd"), sigs[0]


def test_authenticate_rejects_non_dsn():
    try:
        dkim2dsn.authenticate(b"From: a@b.example\r\n\r\nnot a DSN\r\n", DNS_DATA)
        assert False, "authenticate should reject a message that is not a DSN"
    except ValueError as e:
        assert "multipart/report" in str(e), str(e)


# --- §12.1.2 point 1: the DSN's own signing domain must be aligned with the
# rt= of the returned message's top signature -- i.e. the bounce came from the
# system we handed the message to. Checked only on a d= we have verified: an
# unverified d= is whatever the forger typed. --------------------------------

def _signed_dsn_around(embedded: bytes, domain: str,
                       headers_only: bool = False) -> bytes:
    """Wrap `embedded` in a DSN and sign the DSN as a new message (as §12.1.1
    makes it: MAIL FROM <>, one Message-Instance, one DKIM2-Signature)."""
    wrap = _wrap_dsn_headers_only if headers_only else _wrap_dsn
    return dkim2sign.sign_message(
        wrap(embedded), "sel1", domain, _key("sel1", domain),
        mailfrom="<>", rcptto=["user@test2.dkim2.com"], timestamp=1740000000)


def test_authenticate_aligned_dsn():
    # _verifiable_twohop's top signature is i=2 rt=<dest@test3.dkim2.com>, so a
    # DSN for it must be signed by test3.dkim2.com.
    auth = dkim2dsn.authenticate(
        _signed_dsn_around(_verifiable_twohop(), "test3.dkim2.com"),
        DNS_DATA, skip_timestamp_check=True)
    assert auth["ok"], (auth["message"], auth["dsn_message"], auth["alignment_detail"])
    assert auth["dsn_status"] == "pass", auth["dsn_message"]
    assert auth["dsn_sig"]["d"] == "test3.dkim2.com", auth["dsn_sig"]
    assert auth["alignment"] == "pass", auth["alignment_detail"]
    assert "dest@test3.dkim2.com" in auth["alignment_detail"], auth["alignment_detail"]


def test_authenticate_misaligned_dsn():
    # Every signature verifies and the returned message is intact, so nothing
    # but point 1 can tell this is not a bounce from where we sent the mail.
    auth = dkim2dsn.authenticate(
        _signed_dsn_around(_verifiable_twohop(), "test4.dkim2.com"),
        DNS_DATA, skip_timestamp_check=True)
    assert auth["status"] == "pass", auth["message"]
    assert auth["dsn_status"] == "pass", auth["dsn_message"]
    assert auth["alignment"] == "fail", auth["alignment_detail"]
    assert not auth["ok"]
    assert "d=test4.dkim2.com is not aligned" in auth["alignment_detail"]


def test_check_alignment_domain_relationships():
    # Which domain relationships count as "aligned" is a decision about
    # relaxed matching on its own, and the shared test DNS has keys for
    # test1..test5.dkim2.com only -- no subdomain and no parent -- so there is
    # no way to build a real signed DSN for either shape. The accept and
    # reject behaviour through the real entry point is covered above; this
    # pins the direction question, which is what would otherwise be guessed.
    rt_test3 = {"rt": ["<dest@test3.dkim2.com>"]}
    for d in ("bounce.test3.dkim2.com", "dkim2.com", "test3.dkim2.com"):
        state, detail = dkim2dsn._check_alignment({"d": d}, rt_test3)
        assert state == "pass", (d, detail)
    for d in ("test4.dkim2.com", "test3.dkim2.com.evil.example", "evil.example"):
        state, _ = dkim2dsn._check_alignment({"d": d}, rt_test3)
        assert state == "fail", d
    # An nd= top signature on the returned message has no rt= to align with.
    state, detail = dkim2dsn._check_alignment({"d": "test3.dkim2.com"}, {"rt": []})
    assert state == "none" and "no rt=" in detail, detail


def test_authenticate_broken_dsn_signature():
    # A DSN whose own signature is broken claims DKIM2 and lies, so it must not
    # be propagated, and point 1 cannot be applied to a d= we cannot trust.
    tampered = _signed_dsn_around(_verifiable_twohop(), "test3.dkim2.com") \
        .replace(b"Subject: Delivery failure", b"Subject: Delivery FAILURE")
    auth = dkim2dsn.authenticate(tampered, DNS_DATA, skip_timestamp_check=True)
    assert auth["dsn_status"] != "pass", auth["dsn_message"]
    assert auth["alignment"] == "none", auth["alignment_detail"]
    assert not auth["ok"]


def test_authenticate_unsigned_dsn_is_reported_not_failed():
    # An unsigned DSN is not what §12.1.2 is about ("when a system receives a
    # DKIM2 signed DSN"), so it is reported, not failed.
    auth = dkim2dsn.authenticate(_wrap_dsn(_verifiable_twohop()), DNS_DATA,
                                 skip_timestamp_check=True)
    assert auth["dsn_status"] == "none", auth["dsn_message"]
    assert auth["alignment"] == "none"
    assert auth["dsn_sig"] is None
    assert auth["ok"]


# --- §12.1.2: "If the verification fails then the DSN MUST NOT be propagated
# any further" -- propagate enforces that itself. ---------------------------

def test_propagate_needs_the_means_to_authenticate():
    try:
        dkim2dsn.propagate(
            _wrap_dsn(_verifiable_twohop()), forwarder_domain="test2.dkim2.com",
            keyfile=_key("sel1", "test2.dkim2.com"),
            selector="sel1", domain="test2.dkim2.com", timestamp=1740000000)
        assert False, "propagate should refuse without dns_data"
    except ValueError as e:
        assert "need dns_data to authenticate" in str(e), str(e)


def test_propagate_refuses_an_unverifiable_returned_message():
    try:
        dkim2dsn.propagate(
            _wrap_dsn(_two_hop_embedded()), forwarder_domain="test2.dkim2.com",
            keyfile=_key("sel1", "test2.dkim2.com"),
            selector="sel1", domain="test2.dkim2.com", timestamp=1740000000,
            dns_data=DNS_DATA, skip_timestamp_check=True)
        assert False, "propagate should refuse a DSN that does not authenticate"
    except ValueError as e:
        assert "did not authenticate" in str(e), str(e)


def test_propagate_refuses_a_misaligned_dsn():
    # Everything verifies, but the DSN came from a domain the message was
    # never sent to -- the forged-bounce case point 1 exists for.
    try:
        dkim2dsn.propagate(
            _signed_dsn_around(_verifiable_twohop(), "test4.dkim2.com"),
            forwarder_domain="test2.dkim2.com",
            keyfile=_key("sel1", "test2.dkim2.com"),
            selector="sel1", domain="test2.dkim2.com", timestamp=1740000000,
            dns_data=DNS_DATA, skip_timestamp_check=True)
        assert False, "propagate should refuse a misaligned DSN"
    except ValueError as e:
        assert "not aligned" in str(e), str(e)


def test_propagate_a_fully_authenticated_dsn():
    out = dkim2dsn.propagate(
        _signed_dsn_around(_verifiable_twohop(), "test3.dkim2.com"),
        forwarder_domain="test2.dkim2.com",
        keyfile=_key("sel1", "test2.dkim2.com"),
        selector="sel1", domain="test2.dkim2.com", timestamp=1740000000,
        dns_data=DNS_DATA, skip_timestamp_check=True)
    assert out["upstream_mailfrom"] == "<sender@test1.dkim2.com>", out["upstream_mailfrom"]

    # The inbound DSN was itself signed -- the only kind §12.1.2 is about --
    # so its own instance and signature must not survive into ours.
    headers, _ = dkim2sign.parse_message(out["raw"])
    mis = [h for h in headers if dkim2sign._header_name(h) == b"message-instance"]
    sigs = [h.decode("utf-8", "surrogateescape") for h in headers
            if dkim2sign._header_name(h) == b"dkim2-signature"]
    assert len(mis) == 1, f"{len(mis)} MIs (want 1, new message)"
    assert len(sigs) == 1, f"{len(sigs)} sigs (want 1, new message)"
    val = dkim2dsn._hval(sigs[0])
    assert dkim2sign._extract_tag(val, "d") == "test2.dkim2.com", val
    assert dkim2sign._extract_tag(val, "m") == "1", val


if __name__ == "__main__":
    test_propagate_rejects_missing_delivery_status()
    test_propagate_accepts_wellformed_three_part_dsn()
    test_propagate_basic()
    test_authenticate_intact_two_hop()
    test_authenticate_headers_only()
    test_authenticate_rejects_tampered_headers()
    test_authenticate_unsigned_original_reports_none()
    test_authenticate_bridged_chain()
    test_propagate_strips_the_bridge_with_its_hop()
    test_authenticate_rejects_non_dsn()
    test_authenticate_aligned_dsn()
    test_authenticate_misaligned_dsn()
    test_check_alignment_domain_relationships()
    test_authenticate_broken_dsn_signature()
    test_authenticate_unsigned_dsn_is_reported_not_failed()
    test_propagate_needs_the_means_to_authenticate()
    test_propagate_refuses_an_unverifiable_returned_message()
    test_propagate_refuses_a_misaligned_dsn()
    test_propagate_a_fully_authenticated_dsn()
    print("python dsn tests OK")
