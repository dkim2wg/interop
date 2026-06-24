#!/usr/bin/env python3
"""
DKIM2 signer - draft-ietf-dkim-dkim2-spec-01

Takes a raw email, selector, domain, and keyfile and produces a signed
message with Message-Instance and DKIM2-Signature headers on stdout.
"""

import argparse
import base64
import hashlib
import io
import json
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

# Headers to exclude from the header hash
_EXCLUDED_PREFIXES = (b"x-", b"arc-")
_EXCLUDED_NAMES = {b"received", b"return-path", b"delivered-to",
                   b"message-instance",
                   b"dkim2-signature", b"dkim-signature",
                   b"authentication-results"}


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


def compute_header_hash(headers: list[bytes]) -> bytes:
    """Compute the SHA-256 hash of canonicalized, sorted headers (Section 5.2).

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
    # bottom-up (last occurrence first), matching recipe numbering.
    # Reverse before sorting so Python's stable sort preserves bottom-up order.
    canon_headers.reverse()
    canon_headers.sort(key=lambda x: x[0])

    # Concatenate with CRLF separators and a trailing CRLF
    data = b"\r\n".join(ch for _, ch in canon_headers)
    if data:
        data += b"\r\n"

    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Canonicalization for body hash (Section 5.1)
# ---------------------------------------------------------------------------

def compute_body_hash(body: bytes) -> bytes:
    """Compute the SHA-256 hash of the canonicalized body (Section 5.1).

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

    return hashlib.sha256(body).digest()


# ---------------------------------------------------------------------------
# Build Message-Instance header
# ---------------------------------------------------------------------------

def build_message_instance(headers: list[bytes], body: bytes,
                           version: int = 1, recipe: dict | None = None) -> str:
    """Build a Message-Instance header field value.

    Returns the complete header as a string (including field name).
    Trailing semicolon is included per spec ABNF (tag-list grammar).
    """
    h_hash = compute_header_hash(headers)
    b_hash = compute_body_hash(body)
    value = f"m={version}; h=sha256:{b64(h_hash)}:{b64(b_hash)}"
    if recipe is not None:
        value += f"; r={b64json(recipe)}"
    value += ";"
    return f"Message-Instance: {value}"


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
    """Extract a tag value from a DKIM2-style tag-list header value."""
    # header_value is the part after "HeaderName: "
    for part in header_value.split(";"):
        part = part.strip()
        if part.startswith(tag + "="):
            return part[len(tag) + 1:].strip()
    return None


def _get_version_from_mi(hdr: str) -> int:
    """Extract m= value from a Message-Instance header string."""
    # hdr is "Message-Instance: m=N; ..."
    colon = hdr.find(":")
    value = hdr[colon + 1:] if colon != -1 else hdr
    m = _extract_tag(value, "m")
    return int(m) if m else 0


def _get_seq_from_sig(hdr: str) -> int:
    """Extract i= value from a DKIM2-Signature header string."""
    colon = hdr.find(":")
    value = hdr[colon + 1:] if colon != -1 else hdr
    v = _extract_tag(value, "i")
    return int(v) if v else 0


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
    # Per draft-ietf-dkim-dkim2-spec-01 Section 9.5:
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
                          new_mi: str, domain: str, selector: str,
                          private_key, algorithm: str,
                          mailfrom: str = "<>",
                          rcptto: list[str] | None = None,
                          seq: int = 1, mi_version: int = 1,
                          timestamp: int | None = None,
                          next_domain: str | None = None,
                          flags: list[str] | None = None) -> str:
    """Build a complete DKIM2-Signature header.

    If next_domain is given, the signature carries an nd= tag for an imaginary
    forwarding hop (draft-03 §9.3) and omits mf=/rt=. Otherwise it carries
    mf=/rt= as usual. Any flags are emitted as an f= tag (draft-03 §8.10).

    Returns the full header string including field name.
    """
    if timestamp is None:
        timestamp = int(time.time())

    # draft-03 §9.3: an nd= hop carries nd= instead of mf=/rt=.
    if next_domain:
        chain = f"nd={next_domain}"
    else:
        mf_b64 = b64(mailfrom.encode("utf-8"))
        rt_list = rcptto or ["unknown@example.com"]
        rt_b64 = ",".join(b64(r.encode("utf-8")) for r in rt_list)
        chain = f"mf={mf_b64}; rt={rt_b64}"

    f_tag = f" f={','.join(flags)};" if flags else ""

    # Build the incomplete signature header with sel:alg: (null/empty string per spec §9.6).
    # Trailing semicolon included per spec ABNF (tag-list grammar).
    incomplete = (
        f"DKIM2-Signature: i={seq}; m={mi_version}; t={timestamp}; "
        f"d={domain}; {chain}; s={selector}:{algorithm}:;{f_tag}"
    )

    # Collect all MI headers including the new one
    all_mi = mi_headers + [new_mi]

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

def sign_message(source: "Source", selector: str, domain: str, keyfile: str,
                 mailfrom: str = "<>", rcptto: list[str] | None = None,
                 timestamp: int | None = None) -> bytes:
    """Sign a raw email message with DKIM2.

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

    # Determine version numbers
    mi_version = 1
    if existing_mi:
        mi_version = max(_get_version_from_mi(h) for h in existing_mi) + 1

    sig_seq = 1
    if existing_sig:
        sig_seq = max(_get_seq_from_sig(h) for h in existing_sig) + 1

    # Build Message-Instance header
    mi_hdr = build_message_instance(headers, body, version=mi_version)

    # Build DKIM2-Signature header
    sig_hdr = build_dkim2_signature(
        existing_mi, existing_sig, mi_hdr,
        domain, selector, private_key, algorithm,
        mailfrom=mailfrom, rcptto=rcptto,
        seq=sig_seq, mi_version=mi_version,
        timestamp=timestamp,
    )

    # Reassemble the message with new headers prepended
    # Normalise line endings in original
    raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

    output = sig_hdr.encode("utf-8") + b"\r\n"
    output += mi_hdr.encode("utf-8") + b"\r\n"
    output += raw

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Sign an email with DKIM2 (draft-ietf-dkim-dkim2-spec-01)")
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
    args = parser.parse_args()

    if args.message == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(args.message).read_bytes()

    rcptto = args.rcptto or ["unknown@example.com"]

    result = sign_message(raw, args.selector, args.domain, args.keyfile,
                          mailfrom=args.mailfrom, rcptto=rcptto,
                          timestamp=args.timestamp)

    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()
