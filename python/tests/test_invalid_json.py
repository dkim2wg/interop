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
    # spec-06 §11.2: JSON errors are called out specifically, not as a
    # generic syntax error. Exact match (not just Contains): proves the
    # emitted text really is the verbatim §11.2 string.
    errs = verify_message_instance(_mi_with_r(b'{"h": '), [b"From: a@b\r\n"], b"x\r\n")
    assert "PERMERROR Message-Instance m=2 contains invalid JSON" in errs, errs


def test_bad_base64_recipe_is_syntax_error_not_invalid_json():
    # spec-06 §11.2 ruling: base64 decode failure and JSON parse failure are
    # DIFFERENT errors and must stay distinct. "!!!!" is not valid base64
    # (never even reaches JSON parsing), so this must be the "syntax error"
    # PERMERROR, never mislabelled as "contains invalid JSON".
    mi_hdr = "Message-Instance: m=2; h=sha256:AAA:BBB; r=!!!!;"
    errs = verify_message_instance(mi_hdr, [b"From: a@b\r\n"], b"x\r\n")
    assert "PERMERROR Message-Instance m=2 syntax error" in errs, errs
    assert not any("invalid JSON" in e for e in errs), errs


# ---------------------------------------------------------------------------
# End-to-end: feed a complete, multi-hop message with a corrupted r= payload
# through the real verifier entry point (dkim2verify.verify_message), not
# just the Recipe-parsing helper.
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
    # not just the Recipe-parsing helper -- guards against the error being
    # raised deep in a parse path but silently dropped before it reaches the
    # caller (cf. the C duplicate-h= lesson in commit 66bd3e6).
    dns_data = dkim2verify.load_dns_json(DNS_JSON_PATH)
    msg = _build_two_hop_message()
    corrupted = _corrupt_r_tag(msg)
    assert corrupted != msg

    res = dkim2verify.verify_message(corrupted, dns_data, skip_timestamp_check=True)
    assert not res.ok
    want = "PERMERROR Message-Instance m=2 contains invalid JSON"
    # Exact membership (not just Contains): simple mode never adds any
    # prefix, so this was already exact.
    assert want in res.errors, res.errors

    # Also exercise the --full-chain code path (the CLI's actual default),
    # which separately decodes the r= payload to undo Recipes; it must not
    # crash on the same bad input. This path used to prefix every MI error
    # with "v=<version>: ", which would have doubled up the m= already
    # embedded in a self-describing PERMERROR and stopped it from being the
    # verbatim §11.2 string -- assert the exact, unprefixed text here too.
    res_full = dkim2verify.verify_message(
        corrupted, dns_data, full_chain=True, skip_timestamp_check=True)
    assert not res_full.ok
    assert want in res_full.errors, res_full.errors


def _build_single_hop_message() -> bytes:
    """A real, validly-signed single-instance (m=1 only) DKIM2 message, so
    m=1 is both the topmost AND the bottom instance."""
    raw = open(os.path.join(EMAILS_DIR, "simple.eml"), "rb").read()
    return sign_message(
        raw, "ed25519", "test1.dkim2.com",
        _key_path("ed25519._domainkey.test1.dkim2.com.pem"),
        mailfrom="sender@test1.dkim2.com", rcptto=["rcpt@test2.dkim2.com"],
        timestamp=1740000000)


def test_end_to_end_malformed_recipe_json_on_bottom_mi_rejected():
    # spec-06 §9.1: the BOTTOM (m=1) instance MAY carry Recipes too ("if it
    # is wished to record any changes made to a message as it enters the
    # DKIM2 ecosystem") -- confirm it is checked like any other instance,
    # not just non-bottom ones that participate in the undo walk.
    dns_data = dkim2verify.load_dns_json(DNS_JSON_PATH)
    msg = _build_single_hop_message()
    bad_r = base64.b64encode(b'{"h": ').decode()
    pattern = re.compile(rb"(Message-Instance: m=1;[^\r\n]*?h=[^;\r\n]+;)")
    corrupted, count = pattern.subn(
        lambda m: m.group(1) + b" r=" + bad_r.encode() + b";", msg, count=1)
    assert count == 1, "expected to find the m=1 Message-Instance header"
    assert corrupted != msg

    res = dkim2verify.verify_message(corrupted, dns_data, skip_timestamp_check=True)
    assert not res.ok
    assert "PERMERROR Message-Instance m=1 contains invalid JSON" in res.errors, res.errors
