"""Task 4.1: envelope MAIL FROM/RCPT TO checks, relaxed d<->mf, and null-h reject.

Mirrors Perl Mail::DKIM2::Verifier semantics (Verifier.pm:326-333 for the
relaxed d<->mf per-signature check). Envelope-level MAIL FROM/RCPT TO
comparison is new: exact match against the top signature's decoded mf=/rt=,
domains lowercased, local-part case-sensitive; extra rt= entries are allowed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS = os.path.join(REPO_ROOT, "keys")
DNS_JSON_PATH = os.path.join(REPO_ROOT, "dns.json")
DNS_DATA = __import__("json").loads(open(DNS_JSON_PATH).read())

SAMPLE_EML = (b"From: sender@test1.dkim2.com\r\n"
              b"To: rcpt@test2.dkim2.com\r\n"
              b"Subject: hello\r\n\r\nbody line\r\n")

KEYFILE = os.path.join(KEYS, "rsa1024._domainkey.test1.dkim2.com.pem")


def _reassemble(sig_hdrs, mi_hdrs, content_hdrs, body):
    out = b""
    for h in sig_hdrs:
        out += h.encode("utf-8") + b"\r\n"
    for h in mi_hdrs:
        out += h.encode("utf-8") + b"\r\n"
    for h in content_hdrs:
        out += h + b"\r\n"
    out += b"\r\n" + body
    return out


def test_relaxed_mf_domain_mismatch_with_own_d():
    # Signed by test1.dkim2.com but the envelope mf= domain is test3, which
    # is not test1 or a subdomain of it -> relaxed d<->mf check must fail.
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test3.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)
    res = dkim2verify.verify_message(signed, DNS_DATA, skip_timestamp_check=True)
    assert not res.ok
    assert any("MAIL FROM and d= do not match" in e for e in res.errors), res.errors


def test_mail_from_param_mismatch():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)
    res = dkim2verify.verify_message(
        signed, DNS_DATA, skip_timestamp_check=True,
        mail_from="wrong@test1.dkim2.com")
    assert not res.ok
    assert any(
        "DKIM2-Signature i=1 MAIL FROM wrong@test1.dkim2.com did not match" == e
        for e in res.errors
    ), res.errors


def test_rcpt_to_param_mismatch():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)
    res = dkim2verify.verify_message(
        signed, DNS_DATA, skip_timestamp_check=True,
        rcpt_to=["other@test2.dkim2.com"])
    assert not res.ok
    assert any(
        "DKIM2-Signature i=1 RCPT TO other@test2.dkim2.com did not match" == e
        for e in res.errors
    ), res.errors


def test_mail_from_and_rcpt_to_match_still_passes():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)
    res = dkim2verify.verify_message(
        signed, DNS_DATA, skip_timestamp_check=True,
        mail_from="sender@test1.dkim2.com",
        rcpt_to=["rcpt@test2.dkim2.com"])
    assert res.ok, res.errors
    assert res.status == "pass"


def test_extra_rt_entries_allowed():
    # rt= carries extra recipients beyond what was actually delivered; the
    # spec allows this, only the delivered RCPT TO values must be present.
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com",
        rcptto=["rcpt@test2.dkim2.com", "extra@test2.dkim2.com"],
        timestamp=1740000000)
    res = dkim2verify.verify_message(
        signed, DNS_DATA, skip_timestamp_check=True,
        rcpt_to=["rcpt@test2.dkim2.com"])
    assert res.ok, res.errors


def test_null_h_recipe_rejected_full_chain():
    headers, body = dkim2sign.parse_message(SAMPLE_EML)

    mi1 = dkim2sign.build_message_instance(headers, body, version=1)
    mi2 = dkim2sign.build_message_instance(
        headers, body, version=2, recipe={"h": None})

    key, alg = dkim2sign.load_private_key(KEYFILE)
    sig1 = dkim2sign.build_dkim2_signature(
        [mi1], [], mi2, "test1.dkim2.com", "rsa1024", key, alg,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        seq=1, mi_version=2, timestamp=1740000000)

    raw = _reassemble([sig1], [mi1, mi2], headers, body)

    res = dkim2verify.verify_message(raw, DNS_DATA, full_chain=True,
                                     skip_timestamp_check=True)
    assert not res.ok
    assert any("header recipe is null" in e for e in res.errors), res.errors


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python envelope/null-h tests OK")
