import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS = os.path.join(REPO_ROOT, "keys")
DNS_JSON_PATH = os.path.join(REPO_ROOT, "dns.json")
DNS_DATA = json.loads(open(DNS_JSON_PATH).read())

SAMPLE_EML = (b"From: sender@test1.dkim2.com\r\n"
              b"To: rcpt@test2.dkim2.com\r\n"
              b"Subject: hello\r\n\r\nbody line\r\n")


def key_path(name):
    return os.path.join(KEYS, name)


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


def _build_nd_chain(top_has_nd: bool) -> bytes:
    """Build a real, crypto-verifiable two-domain nd= chain.

    Hop 1 (test1.dkim2.com) signs i=1 with nd=test2.dkim2.com, claiming the
    message is being forwarded on to test2.dkim2.com. Hop 2 (test2.dkim2.com)
    then signs i=2 with real mf=/rt= tags, matching the nd= domain.

    If top_has_nd is True, hop 2 is omitted entirely, leaving the *highest*
    (only) DKIM2-Signature carrying nd= -- the illegal state this task
    rejects.
    """
    headers, body = dkim2sign.parse_message(SAMPLE_EML)

    mi1 = dkim2sign.build_message_instance(headers, body, version=1)
    key1, alg1 = dkim2sign.load_private_key(
        key_path("ed25519._domainkey.test1.dkim2.com.pem"))

    sig1 = dkim2sign.build_dkim2_signature(
        [], [], mi1, "test1.dkim2.com", "ed25519", key1, alg1,
        seq=1, mi_version=1, timestamp=1740000000,
        next_domain="test2.dkim2.com")

    if top_has_nd:
        return _reassemble([sig1], [mi1], headers, body)

    # hop 2: content unmodified, new MI version, real mf=/rt= sig on top
    mi2 = dkim2sign.build_message_instance(headers, body, version=2)
    key2, alg2 = dkim2sign.load_private_key(
        key_path("ed25519._domainkey.test2.dkim2.com.pem"))
    sig2 = dkim2sign.build_dkim2_signature(
        [mi1], [sig1], mi2, "test2.dkim2.com", "ed25519", key2, alg2,
        mailfrom="relay@test2.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        seq=2, mi_version=2, timestamp=1740001000)

    return _reassemble([sig1, sig2], [mi1, mi2], headers, body)


def test_top_nd_rejected_full_chain():
    raw = _build_nd_chain(top_has_nd=True)
    result = dkim2verify.verify_message(raw, DNS_DATA, full_chain=True,
                                        skip_timestamp_check=True)
    assert result.status == 'permerror', result
    assert 'unexpected nd= tag' in result.message, result.message


def test_top_nd_rejected_simple_mode():
    raw = _build_nd_chain(top_has_nd=True)
    result = dkim2verify.verify_message(raw, DNS_DATA, full_chain=False,
                                        skip_timestamp_check=True)
    assert result.status == 'permerror', result
    assert 'unexpected nd= tag' in result.message, result.message


def test_legit_nd_chain_still_passes():
    raw = _build_nd_chain(top_has_nd=False)
    result = dkim2verify.verify_message(raw, DNS_DATA, full_chain=True,
                                        skip_timestamp_check=True)
    assert result.status == 'pass', result.message


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python nd= chain tests OK")
