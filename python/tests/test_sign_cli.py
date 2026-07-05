"""Task 4.2: expose --next-domain and --flag on the Python DKIM2 sign CLI.

Verifies that sign_message() (and therefore the CLI, which is a thin
wrapper around it) threads next_domain/flags through to
build_dkim2_signature: an nd= hop emits nd= and omits mf=/rt=, and
--flag values are emitted as a comma-joined f= tag.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2sign  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS = os.path.join(REPO_ROOT, "keys")

SAMPLE_EML = (b"From: sender@test1.dkim2.com\r\n"
              b"To: rcpt@test2.dkim2.com\r\n"
              b"Subject: hello\r\n\r\nbody line\r\n")

KEYFILE = os.path.join(KEYS, "rsa1024._domainkey.test1.dkim2.com.pem")


def test_next_domain_emits_nd_and_omits_mf_rt():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        timestamp=1740000000, next_domain="example.org")
    sig_line = signed.decode("utf-8").split("\r\n", 1)[0]
    assert sig_line.startswith("DKIM2-Signature:")
    assert "nd=example.org" in sig_line
    assert "mf=" not in sig_line
    assert "rt=" not in sig_line


def test_flag_emits_f_tag():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000, flags=["feedhere"])
    sig_line = signed.decode("utf-8").split("\r\n", 1)[0]
    assert "f=feedhere" in sig_line


def test_multiple_flags_comma_joined():
    signed = dkim2sign.sign_message(
        SAMPLE_EML, "rsa1024", "test1.dkim2.com", KEYFILE,
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000, flags=["feedhere", "feedback"])
    sig_line = signed.decode("utf-8").split("\r\n", 1)[0]
    assert "f=feedhere,feedback" in sig_line


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("python sign CLI (--next-domain/--flag) tests OK")
