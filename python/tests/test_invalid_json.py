import base64
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dkim2verify  # noqa: E402
from dkim2verify import verify_message_instance  # noqa: E402
from dkim2sign import (  # noqa: E402
    parse_message, sign_message, build_message_instance,
    build_dkim2_signature, load_private_key, _header_name,
)


def _mi_with_r(raw_json: bytes) -> str:
    r = base64.b64encode(raw_json).decode()
    return f"Message-Instance: m=2; h=sha256:AAA:BBB; r={r};"


def test_malformed_recipe_json_is_reported_specifically():
    # spec-05 §11.2: JSON errors are called out specifically, not as a
    # generic syntax error
    errs = verify_message_instance(_mi_with_r(b'{"h": '), [b"From: a@b\r\n"], b"x\r\n")
    assert any("contains invalid JSON" in e for e in errs)
    assert any("m=2" in e for e in errs)


# ---------------------------------------------------------------------------
# End-to-end: feed a complete, multi-hop message with a corrupted r= payload
# through the real verifier entry point (dkim2verify.verify_message), not
# just the recipe-parsing helper.
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS_DIR = os.path.join(REPO_ROOT, "keys")
EMAILS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emails")
DNS_JSON_PATH = os.path.join(REPO_ROOT, "dns.json")


def _key_path(name):
    return os.path.join(KEYS_DIR, name)


def _split_headers(headers):
    sigs, mis, content = [], [], []
    for hdr in headers:
        name = _header_name(hdr)
        if name == b"dkim2-signature":
            sigs.append(hdr)
        elif name == b"message-instance":
            mis.append(hdr)
        else:
            content.append(hdr)
    return sigs, mis, content


def _build_two_hop_message() -> bytes:
    """A real, validly-signed two-hop DKIM2 message (mirrors
    generate_multihop.py's header-add scenario), built in memory so no
    on-disk fixture is touched or changed."""
    raw = open(os.path.join(EMAILS_DIR, "simple.eml"), "rb").read()
    signed1 = sign_message(
        raw, "ed25519", "test1.dkim2.com",
        _key_path("ed25519._domainkey.test1.dkim2.com.pem"),
        mailfrom="sender@test1.dkim2.com", rcptto=["list@test2.dkim2.com"],
        timestamp=1740000000)

    headers, body = parse_message(signed1)
    sig_hdrs, mi_hdrs, content_hdrs = _split_headers(headers)

    new_hdrs = [
        b"Received: from test1.dkim2.com by relay.example.com; Sat, 01 Mar 2026 12:01:00 +0000",
        b"List-Unsubscribe: <mailto:unsub@relay.example.com>",
    ] + content_hdrs

    recipes = {"h": {"list-unsubscribe": []}}
    mi2 = build_message_instance(new_hdrs, body, version=2, recipe=recipes)

    mi_strs = [h.decode("utf-8") for h in mi_hdrs]
    sig_strs = [h.decode("utf-8") for h in sig_hdrs]

    private_key, algorithm = load_private_key(
        _key_path("ed25519._domainkey.test2.dkim2.com.pem"))
    sig2 = build_dkim2_signature(
        mi_strs, sig_strs, mi2,
        "test2.dkim2.com", "ed25519", private_key, algorithm,
        mailfrom="relay@test2.dkim2.com", rcptto=["recipient@example.com"],
        seq=2, mi_version=2, timestamp=1740001000,
    )

    output = sig2.encode() + b"\r\n"
    for hdr in sig_hdrs:
        output += hdr + b"\r\n"
    output += mi2.encode() + b"\r\n"
    for hdr in mi_hdrs:
        output += hdr + b"\r\n"
    for hdr in new_hdrs:
        output += hdr + b"\r\n"
    output += b"\r\n" + body
    return output


def _corrupt_r_tag(msg: bytes) -> bytes:
    """Replace the base64 r= payload on the m=2 Message-Instance header with
    one that decodes to malformed JSON, leaving everything else (including
    the signature bytes) untouched -- so the signature over that header will
    now legitimately fail too, alongside the invalid-JSON PERMERROR."""
    bad_r = base64.b64encode(b'{"h": ').decode()
    pattern = re.compile(rb"(Message-Instance: m=2;[^\r\n]*?r=)([^;\r\n]+)(;)")
    new_msg, count = pattern.subn(
        lambda m: m.group(1) + bad_r.encode() + m.group(3), msg, count=1)
    assert count == 1, "expected to find exactly one m=2 r= tag to corrupt"
    return new_msg


def test_end_to_end_malformed_recipe_json_rejected_by_verify_message():
    # This drives the real production entry point (dkim2verify.verify_message,
    # the same one the CLI and API callers use) on a complete signed message,
    # not just the recipe-parsing helper -- guards against the error being
    # raised deep in a parse path but silently dropped before it reaches the
    # caller (cf. the C duplicate-h= lesson in commit 66bd3e6).
    dns_data = dkim2verify.load_dns_json(DNS_JSON_PATH)
    msg = _build_two_hop_message()
    corrupted = _corrupt_r_tag(msg)
    assert corrupted != msg

    res = dkim2verify.verify_message(corrupted, dns_data, skip_timestamp_check=True)
    assert not res.ok
    assert any("contains invalid JSON" in e for e in res.errors), res.errors
    assert any("m=2" in e for e in res.errors), res.errors

    # Also exercise the --full-chain code path, which separately decodes the
    # r= payload to undo recipes; it must not crash on the same bad input.
    res_full = dkim2verify.verify_message(
        corrupted, dns_data, full_chain=True, skip_timestamp_check=True)
    assert not res_full.ok
    assert any("contains invalid JSON" in e for e in res_full.errors), res_full.errors
