"""Build a real, validly-signed two-hop DKIM2 message in memory.

Hop 1 signs the original as test1.dkim2.com/sel1 (m=1).  An intermediary
then changes the message; hop 2 signs the result as test2.dkim2.com/sel1
(m=2) and carries the Recipe that gets the original back.  Shared by the
Recipe tests so each can exercise dkim2verify.verify_message -- the entry
point the CLI and API callers use -- rather than a parsing helper.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkim2sign import (  # noqa: E402
    b64, build_dkim2_signature, build_message_instance, load_private_key,
    parse_message, sign_message, _header_name,
)
from dkim2verify import verify_message  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
KEYS = os.path.join(ROOT, "keys")
DNS = os.path.join(ROOT, "dns.json")

HOP1_KEY = os.path.join(KEYS, "sel1._domainkey.test1.dkim2.com.pem")
HOP2_KEY = os.path.join(KEYS, "sel1._domainkey.test2.dkim2.com.pem")


def split_headers(headers):
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


def hop1(original: bytes) -> bytes:
    return sign_message(original, "sel1", "test1.dkim2.com", HOP1_KEY,
                        mailfrom="sender@test1.dkim2.com",
                        rcptto=["list@test2.dkim2.com"],
                        timestamp=1740000000)


def two_hop(original: bytes, modify, recipe: dict | None = None,
            recipe_json: bytes | None = None) -> bytes:
    """Sign `original` twice, with `modify(content_headers, body)` -> (headers,
    body) applied between the hops.  m=2 carries `recipe` (a dict, encoded
    the way the signer does) or `recipe_json` (exact bytes, for payloads a
    conforming producer would never write).  Returns the hop-2 message."""
    headers, body = parse_message(hop1(original))
    sig_hdrs, mi_hdrs, content_hdrs = split_headers(headers)
    new_hdrs, new_body = modify(list(content_hdrs), body)

    if recipe_json is not None:
        assert recipe is None
        mi2 = build_message_instance(new_hdrs, new_body, version=2)
        mi2 = mi2[:-1] + f"; r={b64(recipe_json)};"
    else:
        mi2 = build_message_instance(new_hdrs, new_body, version=2, recipe=recipe)

    key, alg = load_private_key(HOP2_KEY)
    sig2 = build_dkim2_signature(
        [h.decode("utf-8", "surrogateescape") for h in mi_hdrs],
        [h.decode("utf-8", "surrogateescape") for h in sig_hdrs],
        mi2, "test2.dkim2.com", "sel1", key, alg,
        mailfrom="relay@test2.dkim2.com", rcptto=["recipient@example.com"],
        seq=2, mi_version=2, timestamp=1740001000)

    out = sig2.encode() + b"\r\n"
    for hdr in sig_hdrs:
        out += hdr + b"\r\n"
    out += mi2.encode() + b"\r\n"
    for hdr in mi_hdrs:
        out += hdr + b"\r\n"
    for hdr in new_hdrs:
        out += hdr + b"\r\n"
    return out + b"\r\n" + new_body


def verify(msg: bytes, full_chain: bool = True):
    with open(DNS) as fh:
        dns = json.load(fh)
    return verify_message(msg, dns, full_chain=full_chain,
                          skip_timestamp_check=True)
