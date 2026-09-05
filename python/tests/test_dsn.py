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


def test_propagate_rejects_missing_delivery_status():
    dsn = _wrap_dsn_no_delivery_status(_two_hop_embedded())
    try:
        dkim2dsn.propagate(
            dsn, forwarder_domain="test2.dkim2.com",
            keyfile=_key("ed25519", "test3.dkim2.com"),
            selector="ed25519", domain="test3.dkim2.com", timestamp=1740000000)
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
        selector="ed25519", domain="test3.dkim2.com", timestamp=1740000000)
    assert out["upstream_mailfrom"] == "<sender@origin.example>", out["upstream_mailfrom"]


def test_propagate_basic():
    dsn = _wrap_dsn(_two_hop_embedded())
    out = dkim2dsn.propagate(
        dsn, forwarder_domain="test2.dkim2.com",
        keyfile=_key("ed25519", "test3.dkim2.com"),
        selector="ed25519", domain="test3.dkim2.com", timestamp=1740000000)

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


def test_authenticate_rejects_non_dsn():
    try:
        dkim2dsn.authenticate(b"From: a@b.example\r\n\r\nnot a DSN\r\n", DNS_DATA)
        assert False, "authenticate should reject a message that is not a DSN"
    except ValueError as e:
        assert "multipart/report" in str(e), str(e)


if __name__ == "__main__":
    test_propagate_rejects_missing_delivery_status()
    test_propagate_accepts_wellformed_three_part_dsn()
    test_propagate_basic()
    test_authenticate_intact_two_hop()
    test_authenticate_headers_only()
    test_authenticate_rejects_tampered_headers()
    test_authenticate_unsigned_original_reports_none()
    test_authenticate_rejects_non_dsn()
    print("python dsn tests OK")
