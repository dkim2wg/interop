import email
import os
import sys
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2sign  # noqa: E402
import dkim2dsn  # noqa: E402

KEYS = os.path.join(os.path.dirname(__file__), "..", "..", "keys")


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
    (violates the RFC 3462 3-part structure)."""
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


if __name__ == "__main__":
    test_propagate_rejects_missing_delivery_status()
    test_propagate_accepts_wellformed_three_part_dsn()
    test_propagate_basic()
    print("python dsn tests OK")
