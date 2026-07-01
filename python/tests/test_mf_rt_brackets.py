import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS = os.path.join(REPO_ROOT, "keys")
DNS_JSON_PATH = os.path.join(REPO_ROOT, "dns.json")

SAMPLE_EML = (b"From: sender@test1.dkim2.com\r\n"
              b"To: rcpt@test2.dkim2.com\r\n"
              b"Subject: hello\r\n\r\nbody line\r\n")

KEYFILE = os.path.join(KEYS, "rsa1024._domainkey.test1.dkim2.com.pem")
DNS_DATA = json.loads(open(DNS_JSON_PATH).read())


def _sig_header(msg: bytes) -> str:
    for line in msg.decode("utf-8", "surrogateescape").split("\r\n"):
        if line.startswith("DKIM2-Signature:"):
            return line


def _extract_tag(msg: bytes, tag: str) -> str:
    hdr = _sig_header(msg)
    value = dkim2verify._get_header_value(hdr)
    return dkim2sign._extract_tag(value, tag)


def test_encode_wraps_bare_address():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)
    mf_b64 = _extract_tag(signed, "mf")
    assert base64.b64decode(mf_b64).decode() == "<sender@test1.dkim2.com>"


def test_null_sender_stays_bracketed():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="<>", rcptto=["<rcpt@test2.dkim2.com>"],
        timestamp=1740000000)
    assert base64.b64decode(_extract_tag(signed, "mf")).decode() == "<>"


def test_bare_mf_fails_verification():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)
    bad = signed.replace(dkim2sign.b64(b"<sender@test1.dkim2.com>").encode("ascii"),
                         dkim2sign.b64(b"sender@test1.dkim2.com").encode("ascii"))
    assert bad != signed
    res = dkim2verify.verify_message(bad, DNS_DATA, skip_timestamp_check=True)
    assert not res.ok
    assert any("7.5" in e or "bracket" in e for e in res.errors)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python mf=/rt= bracket tests OK")
