#!/usr/bin/env python3
"""
DKIM2 signer - draft-ietf-dkim-dkim2-spec-06

Takes a raw email, selector, domain, and keyfile and produces a signed
message with Message-Instance and DKIM2-Signature headers on stdout.
"""

import argparse
import base64
import difflib
import hashlib
import io
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import IO, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils


# Source can be raw bytes, a file path (str/Path), or any binary-mode file-like object.
Source = Union[bytes, str, "Path", "IO[bytes]"]


def _to_bytes(source: "Source") -> bytes:
    """Normalize any message source to bytes."""
    if isinstance(source, bytes):
        return source
    if isinstance(source, (str, Path)):
        return Path(source).read_bytes()
    return source.read()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    """Base64-encode bytes, return str with no newlines."""
    return base64.b64encode(data).decode("ascii")


def b64json(obj) -> str:
    """JSON-encode an object, then base64-encode the result."""
    return b64(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def to_rfc5321_path(addr: str) -> str:
    """Wrap an address as an RFC5321 path for mf=/rt= (spec 7.5/7.6): angle
    brackets MUST be present. Empty -> '<>'; already-bracketed unchanged."""
    if not addr:
        return "<>"
    if addr.startswith("<") and addr.endswith(">"):
        return addr
    return f"<{addr}>"


# ---------------------------------------------------------------------------
# Parse raw message into (header_lines, body)
# ---------------------------------------------------------------------------

def parse_message(source: "Source") -> tuple[list[bytes], bytes]:
    """Split a raw RFC 5322 message into header lines and body.

    Returns (headers, body) where headers is a list of complete header
    fields (including continuation lines) as raw bytes, and body is the
    raw body bytes (everything after the blank line separator).
    """
    raw = _to_bytes(source)
    # Normalise line endings to CRLF
    raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

    # Split at first blank line
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        header_block = raw
        body = b""
    else:
        header_block = raw[:idx]
        body = raw[idx + len(sep):]

    # Split header block into individual header fields (handling continuations)
    header_lines: list[bytes] = []
    for line in header_block.split(b"\r\n"):
        if line and line[0:1] in (b" ", b"\t") and header_lines:
            # Continuation line – append to previous header
            header_lines[-1] += b"\r\n" + line
        else:
            if line:
                header_lines.append(line)

    return header_lines, body


# ---------------------------------------------------------------------------
# Canonicalization for header hash (Section 5.2)
# ---------------------------------------------------------------------------

# Headers to exclude from the header hash (spec-06 §4, §4.1)
_EXCLUDED_PREFIXES = (b"x-", b"received-")
_EXCLUDED_NAMES = {
    b"apparently-to", b"arc-authentication-results",
    b"arc-message-signature", b"arc-seal", b"authentication-results",
    b"auto-submitted", b"delivered-to", b"dkim-signature",
    b"dkim2-signature", b"dl-expansion-history", b"message-instance",
    b"original-recipient", b"received", b"return-path",
    b"sio-label-history", b"vbr-info", b"x400-received", b"x400-trace",
}


def _header_name(hdr: bytes) -> bytes:
    """Extract the field name from a raw header line (before the colon)."""
    colon = hdr.find(b":")
    if colon == -1:
        return hdr.strip().lower()
    return hdr[:colon].strip().lower()


def _should_exclude_header(name: bytes) -> bool:
    """Return True if this header should be excluded from the header hash."""
    if name in _EXCLUDED_NAMES:
        return True
    for prefix in _EXCLUDED_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def canonicalize_header_field(raw_hdr: bytes) -> bytes:
    """Canonicalize a single header field per Section 5.2 steps 2-6.

    Input is a raw header field (may include continuation lines).
    Returns the canonicalized form (name:value without trailing CRLF).
    """
    # Decode to str for easier manipulation
    hdr = raw_hdr.decode("utf-8", errors="surrogateescape")

    # Step 3: Unfold continuation lines (remove CRLF before WSP)
    hdr = re.sub(r"\r\n([ \t])", r"\1", hdr)

    # Split into name and value at first colon
    colon = hdr.find(":")
    if colon == -1:
        name = hdr
        value = ""
    else:
        name = hdr[:colon]
        value = hdr[colon + 1:]

    # Step 2: Lowercase the field name
    name = name.lower()

    # Step 4: Convert all WSP sequences to single SP
    name = re.sub(r"[ \t]+", " ", name).strip()
    value = re.sub(r"[ \t]+", " ", value)

    # Step 5: Delete WSP at end of value
    value = value.rstrip(" \t")

    # Step 6: Delete WSP before and after colon (i.e. trim name and value)
    name = name.strip()
    value = value.lstrip(" \t")

    return (name + ":" + value).encode("utf-8", errors="surrogateescape")


# spec-06 §3.1: two hashing algorithms are defined. Verifiers MUST implement
# both; Signers MAY implement either or both (we default to sha256).
HASH_ALGS = {
    "sha256": lambda data: hashlib.sha256(data).digest(),
    "sha512": lambda data: hashlib.sha512(data).digest(),
}


def _digest(data: bytes, alg: str = "sha256") -> bytes:
    try:
        return HASH_ALGS[alg](data)
    except KeyError:
        raise ValueError(f"unsupported hash algorithm: {alg}")


def compute_header_hash(headers: list[bytes], alg: str = "sha256") -> bytes:
    """Compute the hash of canonicalized, sorted headers (Section 5.2).

    Excludes headers listed in the spec. Returns raw digest bytes.
    """
    canon_headers: list[tuple[bytes, bytes]] = []

    for hdr in headers:
        name = _header_name(hdr)
        if _should_exclude_header(name):
            continue
        canon = canonicalize_header_field(hdr)
        canon_headers.append((name, canon))

    # Step 7-8: Sort alphabetically by name; duplicate names are ordered
    # bottom-up (last occurrence first), matching Recipe numbering.
    # Reverse before sorting so Python's stable sort preserves bottom-up order.
    canon_headers.reverse()
    canon_headers.sort(key=lambda x: x[0])

    # Concatenate with CRLF separators and a trailing CRLF
    data = b"\r\n".join(ch for _, ch in canon_headers)
    if data:
        data += b"\r\n"

    return _digest(data, alg)


# ---------------------------------------------------------------------------
# Canonicalization for body hash (Section 5.1)
# ---------------------------------------------------------------------------

def compute_body_hash(body: bytes, alg: str = "sha256") -> bytes:
    """Compute the hash of the canonicalized body (Section 5.1).

    Simple canonicalization:
    - Strip all trailing empty lines
    - Ensure body ends with exactly one CRLF
    """
    # Normalise line endings
    body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

    # Remove all trailing CRLF sequences (empty lines at end)
    while body.endswith(b"\r\n"):
        body = body[:-2]

    # Add exactly one trailing CRLF (even if body was empty)
    body += b"\r\n"

    return _digest(body, alg)


# ---------------------------------------------------------------------------
# Build Message-Instance header
# ---------------------------------------------------------------------------

def build_message_instance(headers: list[bytes], body: bytes,
                           version: int = 1, recipe: dict | None = None,
                           algs: list[str] | None = None) -> str:
    """Build a Message-Instance header field value.

    Returns the complete header as a string (including field name).
    Trailing semicolon is included per spec ABNF (tag-list grammar).
    """
    if algs is None:
        algs = ["sha256"]
    # spec-06 §7.3: one hash-set per algorithm, comma separated. An algorithm
    # MUST NOT appear more than once, so `algs` must be de-duplicated by the
    # caller (the CLI does this).
    sets = ",".join(
        f"{alg}:{b64(compute_header_hash(headers, alg))}:{b64(compute_body_hash(body, alg))}"
        for alg in algs
    )
    value = f"m={version}; h={sets}"
    if recipe is not None:
        value += f"; r={b64json(_lowercase_recipe_keys(recipe))}"
    value += ";"
    return f"Message-Instance: {value}"


def _lowercase_recipe_keys(recipe: dict) -> dict:
    """Force the header-recipe (h) keys to lowercase on output.

    Header field names are case-insensitive; emitting recipe keys in a
    canonical lowercase form keeps them stable and unambiguous.  spec-06
    §5.1: header field names in the JSON Recipes MUST be lower case
    (matching against the message stays case-insensitive).
    """
    h = recipe.get("h")
    if not isinstance(h, dict):
        return recipe
    out = dict(recipe)
    out["h"] = {k.lower(): v for k, v in h.items()}
    return out


# ---------------------------------------------------------------------------
# Recipe generation (Section 5)
# ---------------------------------------------------------------------------
#
# An intermediary that changes a message records how to get the previous
# version back.  The rules here are spec-06 §5.1/§5.2 plus the extension
# proposed to the WG: a literal whose octets are not all ASCII goes out as a
# "b" item (base64 of the raw octets), never as a "d" string -- JSON text
# cannot carry Latin-1 or EUC-KR bytes, and escaping them as \udcXX
# surrogates is Python-private.  Pure-ASCII literals stay "d".

def recipe_literal_steps(values: list[bytes]) -> list[dict]:
    """Turn literal lines/values into "d"/"b" steps.

    Consecutive literals of the same kind coalesce into one step; a mixed
    run alternates "d" and "b" steps in order.  A literal may not contain
    CR or LF (§5.1/§5.2) -- a folded header value must be unfolded first.
    """
    steps: list[dict] = []
    for v in values:
        if b"\r" in v or b"\n" in v:
            raise ValueError("Recipe literal contains CR or LF")
        if v.isascii():
            kind, item = "d", v.decode("ascii")
        else:
            kind, item = "b", b64(v)
        if steps and kind in steps[-1]:
            steps[-1][kind].append(item)
        else:
            steps.append({kind: [item]})
    return steps


def _recipe_steps(current: list, previous: list, keys, literal) -> list[dict]:
    """Steps that rebuild `previous` from `current`, both in Recipe order.

    `keys(x)` gives the comparison form of an item (equal keys mean a copy
    is hash-equivalent); `literal(x)` gives the octets to emit when an item
    must be written out.  Matched runs become "c" ranges; since the matcher
    walks both lists in order, every "c" start is greater than the previous
    "c" end (§5.1/§5.2).  An item of `previous` that does not match anything
    after the last copied item -- a reordered duplicate, say -- is emitted
    literally rather than as an out-of-order range.
    """
    cur_keys = [keys(x) for x in current]
    prev_keys = [keys(x) for x in previous]
    sm = difflib.SequenceMatcher(None, cur_keys, prev_keys, autojunk=False)
    steps: list[dict] = []
    pending: list[bytes] = []

    def flush():
        if pending:
            steps.extend(recipe_literal_steps(pending))
            pending.clear()

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            flush()
            steps.append({"c": [i1 + 1, i2]})
        elif tag in ("insert", "replace"):
            pending.extend(literal(x) for x in previous[j1:j2])
        # "delete": items only in the current message are simply not emitted
    flush()
    return steps


def _header_field_value(hdr: bytes) -> bytes:
    """The value after the colon, unfolded, without the trailing CRLF."""
    hdr = re.sub(rb"\r\n([ \t])", rb"\1", hdr.rstrip(b"\r\n"))
    colon = hdr.find(b":")
    return hdr[colon + 1:] if colon != -1 else b""


def build_header_recipe(previous: list[bytes], current: list[bytes]) -> list[dict]:
    """Recipe steps for one header field name (§5.1).

    Both lists hold the raw instances of that name in top-to-bottom message
    order.  Instances are numbered bottom-up and steps are emitted bottom-up,
    so both are reversed before alignment.  Two instances match when their
    §6.2 canonical forms are equal.
    """
    return _recipe_steps(list(reversed(current)), list(reversed(previous)),
                         canonicalize_header_field, _header_field_value)


def _body_lines(body: bytes) -> list[bytes]:
    body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = body.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def build_body_recipe(previous: bytes, current: bytes) -> list[dict]:
    """Recipe steps that rebuild the previous body from the current one (§5.2)."""
    return _recipe_steps(_body_lines(current), _body_lines(previous),
                         lambda line: line, lambda line: line)


def build_recipes(previous_headers: list[bytes], previous_body: bytes,
                  current_headers: list[bytes], current_body: bytes) -> dict | None:
    """The r= object for a hop that turned (previous_*) into (current_*).

    Only header field names whose instances changed get an "h" entry (an
    empty list where the name is new); "b" is present only if the body
    changed.  Header fields excluded from the hash (§4) are never described.
    Returns None when nothing relevant changed, so the caller omits r=.
    """
    def by_name(headers):
        out: dict[bytes, list[bytes]] = {}
        for hdr in headers:
            out.setdefault(_header_name(hdr), []).append(hdr)
        return out

    prev_by, cur_by = by_name(previous_headers), by_name(current_headers)
    h: dict[str, list] = {}
    for name in sorted(set(prev_by) | set(cur_by)):
        if _should_exclude_header(name):
            continue
        prev, cur = prev_by.get(name, []), cur_by.get(name, [])
        if ([canonicalize_header_field(x) for x in prev]
                == [canonicalize_header_field(x) for x in cur]):
            continue
        h[name.decode("ascii")] = build_header_recipe(prev, cur)

    recipes: dict = {}
    if h:
        recipes["h"] = h
    if compute_body_hash(previous_body) != compute_body_hash(current_body):
        recipes["b"] = build_body_recipe(previous_body, current_body)
    return recipes or None


# ---------------------------------------------------------------------------
# Signature computation (Section 11.5)
# ---------------------------------------------------------------------------

def canonicalize_sig_header(raw_hdr: str) -> bytes:
    """Canonicalize a Message-Instance or DKIM2-Signature header for signing.

    Per Section 9.5: same as header hash except ALL WSP is deleted
    (not collapsed to single SP).
    """
    hdr = raw_hdr if isinstance(raw_hdr, str) else raw_hdr.decode("utf-8", errors="surrogateescape")
    # Step 3: Unfold continuation lines
    hdr = re.sub(r"\r\n([ \t])", r"\1", hdr)
    # Split into name and value at first colon
    colon = hdr.find(":")
    if colon == -1:
        name = hdr
        value = ""
    else:
        name = hdr[:colon]
        value = hdr[colon + 1:]
    # Step 2: Lowercase the field name
    name = name.lower().strip()
    # Step 3 (sig-specific): Delete ALL WSP characters
    value = re.sub(r"[ \t]+", "", value)
    # Strip trailing CRLF/LF
    value = value.rstrip("\r\n")
    return (name + ":" + value + "\r\n").encode("utf-8", errors="surrogateescape")


def _extract_tag(header_value: str, tag: str) -> str | None:
    """Extract a tag value from a DKIM2-style tag-list header value.

    Per spec-06 §8, tag identifiers are case-insensitive, may appear in any
    order, and FWS is permitted around the '=' and ';' separators.
    """
    tl = tag.lower()
    for part in header_value.split(";"):
        if "=" not in part:
            continue
        name, val = part.split("=", 1)
        if name.strip().lower() == tl:
            return val.strip()
    return None


def _tag_names(header_value: str) -> list[str]:
    """Lowercased tag names in a tag-list value, in order (for duplicate
    detection per spec-06 §8: 'there MUST be only one of each kind')."""
    names = []
    for part in header_value.split(";"):
        if "=" in part:
            names.append(part.split("=", 1)[0].strip().lower())
    return names


def _get_version_from_mi(hdr: str) -> int:
    """Extract m= value from a Message-Instance header string."""
    # hdr is "Message-Instance: m=N; ..."
    colon = hdr.find(":")
    value = hdr[colon + 1:] if colon != -1 else hdr
    m = _extract_tag(value, "m")
    return int(m) if m else 0


def _mi_hashes(hdr: str) -> str | None:
    """Extract the h= hash set of a Message-Instance header, FWS removed.

    Folding whitespace may appear inside the base64 hashes (spec-06 §2.12), so
    strip it before comparing two instances' hashes.
    """
    colon = hdr.find(":")
    value = hdr[colon + 1:] if colon != -1 else hdr
    h = _extract_tag(value, "h")
    if h is None:
        return None
    return "".join(h.split())


def _get_seq_from_sig(hdr: str) -> int:
    """Extract i= value from a DKIM2-Signature header string.

    0 when i= is missing or not a positive integer (ASCII digits): such a
    signature cannot be keyed, and verify_message() reports it as a
    PERMERROR (see _sig_has_valid_i)."""
    colon = hdr.find(":")
    value = hdr[colon + 1:] if colon != -1 else hdr
    v = _extract_tag(value, "i")
    if v is None or not v.isascii() or not v.isdigit():
        return 0
    return int(v)


# Every i= and m= names one hop, and a chain has at most this many.
MAX_CHAIN_LENGTH = 32


def chain_number_in_range(v: str) -> bool:
    """False for an ASCII-digit i=/m= value above MAX_CHAIN_LENGTH, or one
    longer than two digits (so it is never turned into a huge number).
    Values that are not digits are left to the other syntax checks."""
    v = v.strip()
    if not v.isascii() or not v.isdigit():
        return True
    return len(v) <= 2 and int(v) <= MAX_CHAIN_LENGTH


def _tag_of(hdr: str, tag: str) -> str | None:
    colon = hdr.find(":")
    return _extract_tag(hdr[colon + 1:] if colon != -1 else hdr, tag)


def chain_range_error(mi_headers: list[str], sig_headers: list[str]) -> str | None:
    """The PERMERROR for the first i= or m= above MAX_CHAIN_LENGTH, or None.
    Checked before anything walks 1..max for gaps."""
    for field, tag, hdrs in (("DKIM2-Signature", "i", sig_headers),
                             ("DKIM2-Signature", "m", sig_headers),
                             ("Message-Instance", "m", mi_headers)):
        for h in hdrs:
            v = _tag_of(h, tag)
            if v is not None and not chain_number_in_range(v):
                return (f"PERMERROR {field} {tag}= exceeds the maximum chain "
                        f"length of {MAX_CHAIN_LENGTH}")
    return None


def _sig_has_valid_i(hdr: str) -> bool:
    """True iff the DKIM2-Signature has an i= that is a positive integer."""
    return _get_seq_from_sig(hdr) > 0


def _get_mi_from_sig(hdr: str) -> int | None:
    """Extract m= (the Message-Instance it covers) from a DKIM2-Signature."""
    colon = hdr.find(":")
    value = hdr[colon + 1:] if colon != -1 else hdr
    v = _extract_tag(value, "m")
    try:
        return int(v) if v else None
    except ValueError:
        return None


def compute_signature(mi_headers: list[str], sig_headers: list[str],
                      incomplete_sig: str, private_key, algorithm: str) -> bytes:
    """Compute the DKIM2 signature over MI and DKIM2-Sig headers.

    Args:
        mi_headers: Existing Message-Instance headers (as full header strings)
        sig_headers: Existing DKIM2-Signature headers (as full header strings)
        incomplete_sig: The DKIM2-Signature being created, with s= tag empty
        private_key: Private key object (RSA or Ed25519)
        algorithm: "rsa" or "ed25519"

    Returns:
        Raw signature bytes.
    """
    # Per draft-ietf-dkim-dkim2-spec-06 Section 9.5:
    # 1. All MI headers in ascending v= order
    # 2. All prior DKIM2-Signature headers in ascending i= order
    # 3. The incomplete DKIM2-Signature being created
    ordered: list[str] = []
    ordered.extend(sorted(mi_headers, key=_get_version_from_mi))
    ordered.extend(sorted(sig_headers, key=_get_seq_from_sig))
    ordered.append(incomplete_sig)

    # Canonicalize each header; each already ends in CRLF per spec Section 8.5
    canon = [canonicalize_sig_header(h) for h in ordered]
    data = b"".join(canon)

    # Hash with SHA-256
    digest = hashlib.sha256(data).digest()

    # Sign
    if algorithm.startswith("ed25519"):
        # Ed25519 signs the raw data (PureEdDSA), but the spec says
        # "signs the hash" - so we sign the SHA-256 digest
        return private_key.sign(digest)
    elif algorithm.startswith("rsa"):
        return private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


# ---------------------------------------------------------------------------
# Build DKIM2-Signature header
# ---------------------------------------------------------------------------

def build_dkim2_signature(mi_headers: list[str], sig_headers: list[str],
                          new_mi: str | None, domain: str, selector: str,
                          private_key, algorithm: str,
                          mailfrom: str = "<>",
                          rcptto: list[str] | None = None,
                          seq: int = 1, mi_version: int = 1,
                          timestamp: int | None = None,
                          next_domain: str | None = None,
                          flags: list[str] | None = None) -> str:
    """Build a complete DKIM2-Signature header.

    If next_domain is given, the signature carries an nd= tag for an imaginary
    forwarding hop (draft-06 §9.3) and omits mf=/rt=. Otherwise it carries
    mf=/rt= as usual. Any flags are emitted as an f= tag (draft-06 §8.10).

    Returns the full header string including field name.
    """
    if timestamp is None:
        timestamp = int(time.time())

    # draft-06 §9.3: an nd= hop carries nd= instead of mf=/rt=.
    if next_domain:
        chain = f"nd={next_domain}"
    else:
        mf_b64 = b64(to_rfc5321_path(mailfrom).encode("utf-8"))
        rt_list = rcptto or ["unknown@example.com"]
        rt_b64 = ",".join(b64(to_rfc5321_path(r).encode("utf-8")) for r in rt_list)
        chain = f"mf={mf_b64}; rt={rt_b64}"

    f_tag = f" f={','.join(flags)};" if flags else ""

    # Build the incomplete signature header with sel:alg: (null/empty string per spec §9.6).
    # Trailing semicolon included per spec ABNF (tag-list grammar).
    incomplete = (
        f"DKIM2-Signature: i={seq}; m={mi_version}; t={timestamp}; "
        f"d={domain}; {chain}; s={selector}:{algorithm}:;{f_tag}"
    )

    # Collect all MI headers, including the new one if this hop created one
    # (new_mi is None when the hop changed nothing and reuses the existing top
    # instance — see sign_message).
    all_mi = mi_headers + ([new_mi] if new_mi is not None else [])

    # Compute signature
    sig_bytes = compute_signature(all_mi, sig_headers, incomplete,
                                 private_key, algorithm)

    # Build s= tag: sel:alg:sig
    s_complete = f"{selector}:{algorithm}:{b64(sig_bytes)}"

    # Build the final header with the actual signature value
    return (
        f"DKIM2-Signature: i={seq}; m={mi_version}; t={timestamp}; "
        f"d={domain}; {chain}; s={s_complete};{f_tag}"
    )


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_private_key(keyfile: str) -> tuple:
    """Load a private key from a PEM file.

    Returns (key_object, algorithm_string).
    """
    key_data = Path(keyfile).read_bytes()

    key = serialization.load_pem_private_key(key_data, password=None)

    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key, "ed25519-sha256"
    elif isinstance(key, rsa.RSAPrivateKey):
        return key, "rsa-sha256"
    else:
        raise ValueError(f"Unsupported key type: {type(key)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

class SigningRefused(Exception):
    """The signer gate refused to extend an existing DKIM2 chain."""


def _gate_upstream(raw: bytes, headers, existing_mi, existing_sig,
                   dns_data: dict | None, skip_timestamp_check: bool,
                   allow_null_body_recipe: bool,
                   signing_domain: str | None = None) -> None:
    """Refuse (SigningRefused) unless the chain already on the message checks
    out.  Runs the verifier in outbound mode: an unsigned top Message-Instance
    is the one we are about to cover.  An UNSIGNED top instance (no
    DKIM2-Signature has its m=) with a null body Recipe needs
    allow_null_body_recipe as well; a signed one does not."""
    import os
    # dkim2verify imports this module, so import it lazily.
    import dkim2verify

    if dns_data is None and not existing_sig:
        dns_data = {}   # nothing to verify a signature with; MI chain only
    if dns_data is None:
        path = os.environ.get("DKIM2_DNS_JSON")
        if not path:
            raise SigningRefused(
                "not signing: cannot verify the upstream DKIM2 chain: no DNS "
                "data: pass --dns-json or set DKIM2_DNS_JSON (this verifier "
                "has no live DNS)")
        try:
            dns_data = dkim2verify.load_dns_json(path)
        except (OSError, ValueError) as e:
            raise SigningRefused(f"not signing: cannot read keys from "
                                 f"{path}: {e}")

    # A top signature with nd= may only be extended by the domain it names.
    if existing_sig:
        top_sig = max(existing_sig, key=_get_seq_from_sig)
        top_nd = _extract_tag(top_sig[top_sig.find(":") + 1:], "nd")
        if top_nd and (signing_domain is None
                       or top_nd.strip().lower() != signing_domain.lower()):
            raise SigningRefused(
                f"not signing: top signature nd={top_nd.strip()} names "
                f"another domain")

    result = dkim2verify.verify_message(
        raw, dns_data, full_chain=True,
        skip_timestamp_check=skip_timestamp_check, allow_unsigned_mi=True)
    if not result.ok:
        detail = "; ".join(result.errors) or result.message
        if any("v=" in e or "Recipe" in e or "Message-Instance" in e
               for e in result.errors) and result.status != "fail":
            raise SigningRefused(
                f"not signing: Message-Instance chain does not undo cleanly: "
                f"{detail}")
        raise SigningRefused(
            f"not signing: upstream DKIM2 chain result={result.status} "
            f"{detail}")

    # A null body Recipe on the top instance is refused only when no upstream
    # signature covers it (no DKIM2-Signature with m= equal to the top m=):
    # then it is a null THIS hop introduced, which needs the option.  A null
    # some upstream domain already declared and signed is extended normally
    # (e.g. a forwarder relaying a list post unchanged).
    top = max(existing_mi, key=_get_version_from_mi)
    top_m = _get_version_from_mi(top)
    # Only a signature with a valid i= can cover anything: one the verifier
    # cannot key is a PERMERROR above, and never counts as coverage here.
    top_signed = any(_get_mi_from_sig(s) == top_m
                     for s in existing_sig if _sig_has_valid_i(s))
    mi_json = _extract_mi_recipe(top)
    if mi_json is not None and "b" in mi_json and mi_json["b"] is None \
            and not top_signed and not allow_null_body_recipe:
        raise SigningRefused(
            f"not signing: unsigned top Message-Instance m={top_m} has a null "
            f"body Recipe (--allow-null-body-recipe not set)")


def _extract_mi_recipe(mi_hdr: str):
    """Decoded r= object of a Message-Instance header, or None if absent."""
    import dkim2verify
    try:
        return dkim2verify.decode_recipes(mi_hdr)
    except (ValueError, TypeError):
        return None


def sign_message(source: "Source", selector: str, domain: str, keyfile: str,
                 mailfrom: str = "<>", rcptto: list[str] | None = None,
                 timestamp: int | None = None,
                 next_domain: str | None = None,
                 flags: list[str] | None = None,
                 algs: list[str] | None = None,
                 dns_data: dict | None = None,
                 skip_timestamp_check: bool = False,
                 allow_null_body_recipe: bool = False,
                 skip_upstream_check: bool = False) -> bytes:
    """Sign a raw email message with DKIM2.

    A message that already carries a DKIM2 chain is verified first (outbound
    mode: an unsigned top Message-Instance is allowed); if the chain does not
    check out, or its top Message-Instance has a null body Recipe that no
    upstream DKIM2-Signature covers (none has that m=) and
    allow_null_body_recipe is not set, SigningRefused is raised.  Keys come
    from dns_data, else the dns.json named by $DKIM2_DNS_JSON.

    skip_upstream_check=True bypasses the gate entirely.  It exists for test
    and fixture builders that must sign over broken chains on purpose; there
    is deliberately no CLI flag for it.

    Returns the complete message with Message-Instance and DKIM2-Signature
    headers prepended.
    """
    raw = _to_bytes(source)
    private_key, algorithm = load_private_key(keyfile)

    headers, body = parse_message(raw)

    # Find any existing Message-Instance and DKIM2-Signature headers
    existing_mi: list[str] = []
    existing_sig: list[str] = []
    for hdr in headers:
        name = _header_name(hdr)
        if name == b"message-instance":
            existing_mi.append(hdr.decode("utf-8", errors="surrogateescape"))
        elif name == b"dkim2-signature":
            existing_sig.append(hdr.decode("utf-8", errors="surrogateescape"))

    # Out-of-range numbers are refused even with the gate bypassed: the next
    # i= and m= below are computed from them.
    range_error = chain_range_error(existing_mi, existing_sig)
    if range_error:
        raise SigningRefused(f"not signing: {range_error}")

    if (existing_mi or existing_sig) and not skip_upstream_check:
        _gate_upstream(raw, headers, existing_mi, existing_sig, dns_data,
                       skip_timestamp_check, allow_null_body_recipe,
                       signing_domain=domain)

    # Determine version numbers
    top_mi = None
    mi_version = 1
    if existing_mi:
        top_mi = max(existing_mi, key=_get_version_from_mi)
        mi_version = _get_version_from_mi(top_mi) + 1

    sig_seq = 1
    if existing_sig:
        sig_seq = max(_get_seq_from_sig(h) for h in existing_sig) + 1

    # Build Message-Instance header
    mi_hdr = build_message_instance(headers, body, version=mi_version, algs=algs)

    # draft-06 §9.1/§9.2.5: a hop that leaves both hashes unchanged adds no new
    # Message-Instance at all — it signs against the existing top instance and
    # reuses its m=.  Emitting an instance with identical hashes and no Recipe
    # is not forbidden, but §9.1 still calls it "most likely to be pointless
    # and a waste of time and energy"; this implementation avoids it by
    # default, and verifiers must still tolerate one from elsewhere.
    if top_mi is not None and _mi_hashes(top_mi) == _mi_hashes(mi_hdr):
        mi_version = _get_version_from_mi(top_mi)
        mi_hdr = None

    # Build DKIM2-Signature header
    sig_hdr = build_dkim2_signature(
        existing_mi, existing_sig, mi_hdr,
        domain, selector, private_key, algorithm,
        mailfrom=mailfrom, rcptto=rcptto,
        seq=sig_seq, mi_version=mi_version,
        timestamp=timestamp,
        next_domain=next_domain, flags=flags,
    )

    # Reassemble the message with new headers prepended
    # Normalise line endings in original
    raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

    output = sig_hdr.encode("utf-8") + b"\r\n"
    if mi_hdr is not None:
        output += mi_hdr.encode("utf-8") + b"\r\n"
    output += raw

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Sign an email with DKIM2 (draft-ietf-dkim-dkim2-spec-06)")
    parser.add_argument("message", help="Path to raw email file (- for stdin)")
    parser.add_argument("-s", "--selector", required=True,
                        help="DKIM2 selector name")
    parser.add_argument("-d", "--domain", required=True,
                        help="Signing domain")
    parser.add_argument("-k", "--keyfile", required=True,
                        help="Path to PEM private key file")
    parser.add_argument("--mailfrom", default="<>",
                        help="MAIL FROM value (default: <>)")
    parser.add_argument("--rcptto", action="append",
                        help="RCPT TO value(s) (repeatable)")
    parser.add_argument("--timestamp", type=int, default=None,
                        help="Unix timestamp (default: current time)")
    parser.add_argument("--next-domain",
                        help="Next-hop domain (nd=); emits an nd= chain "
                             "tag instead of mf=/rt=")
    parser.add_argument("--flag", action="append", dest="flags",
                        help="Signature flag (f=); repeatable")
    parser.add_argument("--hash", dest="hash_algs", default="sha256",
                        choices=["sha256", "sha512", "both"],
                        help="hash algorithm(s) for the Message-Instance h= tag "
                             "(spec-06 §3.1; default sha256)")
    parser.add_argument("--allow-null-body-recipe", action="store_true",
                        help="sign even when the top Message-Instance has a "
                             "null body Recipe that no upstream signature "
                             "covers (default: refuse; a signed null top "
                             "needs no option)")
    parser.add_argument("--dns-json",
                        default=os.environ.get("DKIM2_DNS_JSON"),
                        help="dns.json with keys to verify an existing chain "
                             "(default: $DKIM2_DNS_JSON)")
    parser.add_argument("--ignore-timestamps", action="store_true",
                        dest="skip_timestamp_check",
                        help="skip the timestamp check when verifying an "
                             "existing chain")
    args = parser.parse_args()

    if args.message == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(args.message).read_bytes()

    rcptto = args.rcptto or ["unknown@example.com"]
    if args.dns_json:
        os.environ["DKIM2_DNS_JSON"] = args.dns_json

    algs = ["sha256", "sha512"] if args.hash_algs == "both" else [args.hash_algs]

    try:
        result = sign_message(raw, args.selector, args.domain, args.keyfile,
                              mailfrom=args.mailfrom, rcptto=rcptto,
                              timestamp=args.timestamp,
                              next_domain=args.next_domain, flags=args.flags,
                              algs=algs,
                              skip_timestamp_check=args.skip_timestamp_check,
                              allow_null_body_recipe=args.allow_null_body_recipe)
    except SigningRefused as e:
        print(f"dkim2sign: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()
