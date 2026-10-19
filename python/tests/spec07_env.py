"""Fake DNS and signing helpers for the draft -07 shared behaviour tests.

The shared test table (U1..D1) names example.com, example.org and friends.
Each of those gets an Ed25519 key generated when this module is imported:
the private key is written to a temporary PEM (sign_message() takes a key
file) and the public key goes into DNS, a dns.json-shaped dict that only
these tests use.  Nothing is added to the repo-root dns.json.
"""

import atexit
import base64
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import gate_env  # noqa: E402,F401  (fixed timestamps are fine for the gate)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

import dkim2sign  # noqa: E402
import dkim2verify  # noqa: E402
from dkim2sign import (  # noqa: E402
    _header_name, _get_version_from_mi, b64, build_message_instance,
    build_recipes, parse_message,
)

SELECTOR = "sel"
DOMAINS = (
    "example.com", "example.org", "example.net", "other.net",
    "fwd.example.net", "other.example", "elsewhere.net",
    "lists.example.org", "mail.example.org", "xn--bcher-kva.example",
)
NOW = int(time.time())

_KEYDIR = tempfile.mkdtemp(prefix="dkim2-spec07-")
atexit.register(shutil.rmtree, _KEYDIR, True)

DNS: dict = {}
_KEYFILES: dict = {}
for _d in DOMAINS:
    _priv = ed25519.Ed25519PrivateKey.generate()
    _path = os.path.join(_KEYDIR, f"{SELECTOR}._domainkey.{_d}.pem")
    with open(_path, "wb") as _fh:
        _fh.write(_priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    _pub = _priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _KEYFILES[_d] = _path
    DNS[_d] = {f"{SELECTOR}._domainkey": [
        ["TXT", "v=DKIM1; k=ed25519; p=" + base64.b64encode(_pub).decode()]]}


def keyfile(domain: str) -> str:
    return _KEYFILES[domain]


def message(frm: str = "A <a@example.com>", subject: str = "hello",
            body: bytes = b"body line\r\n", extra: bytes = b"") -> bytes:
    """A small message.  `frm` may be non-ASCII (written as UTF-8)."""
    return (f"From: {frm}\r\nTo: list@lists.example.org\r\n"
            f"Subject: {subject}\r\n").encode("utf-8") + extra + b"\r\n" + body


def sign(raw: bytes, domain: str, mailfrom: str, rcptto=None, **kw) -> bytes:
    """sign_message() with the fake DNS for the gate and a current timestamp."""
    kw.setdefault("timestamp", NOW)
    kw.setdefault("skip_timestamp_check", True)
    return dkim2sign.sign_message(
        raw, SELECTOR, domain, keyfile(domain), mailfrom=mailfrom,
        rcptto=rcptto if rcptto is not None else ["r@example.net"],
        dns_data=DNS, **kw)


def verify(msg: bytes, **kw):
    kw.setdefault("skip_timestamp_check", True)
    kw.setdefault("full_chain", True)
    return dkim2verify.verify_message(msg, DNS, **kw)


def split(headers):
    sigs, mis, content = [], [], []
    for h in headers:
        name = _header_name(h)
        if name == b"dkim2-signature":
            sigs.append(h)
        elif name == b"message-instance":
            mis.append(h)
        else:
            content.append(h)
    return sigs, mis, content


def add_mi(raw: bytes, modify=None, recipe_json: bytes | None = None) -> bytes:
    """Add an unsigned Message-Instance above the chain on `raw`.

    `modify(content_headers, body)` -> (headers, body) changes the message;
    the new instance records the Recipe the signer's own build_recipes()
    makes, or `recipe_json` (exact bytes) when given."""
    headers, body = parse_message(raw)
    sigs, mis, content = split(headers)
    new_content, new_body = (modify(list(content), body) if modify
                             else (list(content), body))
    version = max(_get_version_from_mi(h.decode("utf-8", "surrogateescape"))
                  for h in mis) + 1
    if recipe_json is None:
        recipe = build_recipes(content, body, new_content, new_body)
        mi = build_message_instance(new_content, new_body, version=version,
                                    recipe=recipe)
    else:
        mi = build_message_instance(new_content, new_body, version=version)
        mi = mi[:-1] + f"; r={b64(recipe_json)};"
    out = b"".join(h + b"\r\n" for h in sigs)
    out += mi.encode("utf-8") + b"\r\n"
    out += b"".join(h + b"\r\n" for h in mis + new_content)
    return out + b"\r\n" + new_body


def replace_header(name: bytes, value: bytes):
    """A modify() for add_mi that sets every `name` field to `value`."""
    def modify(content, body):
        return ([name + b": " + value if _header_name(h) == name.lower() else h
                 for h in content], body)
    return modify


def mi_recipe(msg: bytes, m: int):
    """The decoded r= of Message-Instance m=`m`."""
    headers, _ = parse_message(msg)
    for h in headers:
        if _header_name(h) == b"message-instance":
            s = h.decode("utf-8", "surrogateescape")
            if _get_version_from_mi(s) == m:
                return dkim2verify.decode_recipes(s)
    raise KeyError(m)


def sig_tag(msg: bytes, i: int, tag: str):
    headers, _ = parse_message(msg)
    for h in headers:
        if _header_name(h) == b"dkim2-signature":
            s = h.decode("utf-8", "surrogateescape")
            if dkim2sign._get_seq_from_sig(s) == i:
                return dkim2sign._extract_tag(s[s.find(":") + 1:], tag)
    raise KeyError(i)
