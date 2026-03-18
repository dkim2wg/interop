#!/usr/bin/env python3
"""
DKIM2 verifier - draft-clayton-dkim2-spec-08

Takes a signed email and verifies its DKIM2 signatures using public keys
from a dns.json file or DNS TXT records.

Exits 0 if all signatures verify, non-zero otherwise.
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils


# ---------------------------------------------------------------------------
# Reuse canonicalization from dkim2sign
# ---------------------------------------------------------------------------

from dkim2sign import (
    parse_message,
    _header_name,
    _should_exclude_header,
    canonicalize_header_field,
    compute_header_hash,
    compute_body_hash,
    canonicalize_sig_header,
    _extract_tag,
    _get_version_from_mi,
    _get_seq_from_sig,
    b64,
    b64json,
)


# ---------------------------------------------------------------------------
# DNS key lookup
# ---------------------------------------------------------------------------

def load_dns_json(path: str) -> dict:
    """Load a dns.json file mapping domain -> selector -> records."""
    return json.loads(Path(path).read_text())


def parse_dkim1_txt(txt: str) -> dict:
    """Parse a DKIM1 TXT record into a dict of tag -> value."""
    result = {}
    for part in txt.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def lookup_public_key(domain: str, selector: str, dns_data: dict):
    """Look up a public key from dns.json.

    Returns (key_object, key_type_str) or raises on failure.
    """
    domain_records = dns_data.get(domain)
    if not domain_records:
        raise KeyError(f"Domain {domain!r} not found in dns.json")

    selector_key = f"{selector}._domainkey"
    records = domain_records.get(selector_key)
    if not records:
        raise KeyError(f"Selector {selector_key!r} not found for {domain}")

    # records is a list of [type, value] pairs; find the TXT record
    for rec_type, rec_value in records:
        if rec_type.lower() == "txt":
            tags = parse_dkim1_txt(rec_value)
            key_type = tags.get("k", "rsa")
            pub_b64 = tags.get("p", "")
            pub_bytes = base64.b64decode(pub_b64)

            if key_type == "ed25519":
                # Ed25519 public key is raw 32 bytes
                # But some implementations prefix with algorithm identifier bytes
                # Try raw first, then as DER
                if len(pub_bytes) == 32:
                    return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes), "ed25519"
                else:
                    # May have DER prefix - try stripping it
                    # Ed25519 DER prefix is 12 bytes: 30 2a 30 05 06 03 2b 65 70 03 21 00
                    if len(pub_bytes) > 32:
                        raw = pub_bytes[-32:]
                        return ed25519.Ed25519PublicKey.from_public_bytes(raw), "ed25519"
                    return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes), "ed25519"
            elif key_type == "rsa":
                # RSA public key is DER-encoded SubjectPublicKeyInfo
                return serialization.load_der_public_key(pub_bytes), "rsa"
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

    raise KeyError(f"No TXT record found for {selector_key}.{domain}")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def extract_mi_headers(headers: list[bytes]) -> list[str]:
    """Extract all Message-Instance headers as strings."""
    result = []
    for hdr in headers:
        if _header_name(hdr) == b"message-instance":
            result.append(hdr.decode("utf-8", errors="surrogateescape"))
    return result


def extract_sig_headers(headers: list[bytes]) -> list[str]:
    """Extract all DKIM2-Signature headers as strings."""
    result = []
    for hdr in headers:
        if _header_name(hdr) == b"dkim2-signature":
            result.append(hdr.decode("utf-8", errors="surrogateescape"))
    return result


def _get_header_value(hdr: str) -> str:
    """Get the value part of a header (after the first colon)."""
    colon = hdr.find(":")
    return hdr[colon + 1:].strip() if colon != -1 else hdr


def verify_message_instance(mi_hdr: str, headers: list[bytes], body: bytes) -> list[str]:
    """Verify the hashes in a Message-Instance header against the message.

    Returns a list of errors (empty = success).
    """
    errors = []
    value = _get_header_value(mi_hdr)
    h_b64 = _extract_tag(value, "h")
    if not h_b64:
        return ["Message-Instance: missing h= tag"]

    try:
        h_obj = json.loads(base64.b64decode(h_b64))
    except Exception as e:
        return [f"Message-Instance: failed to decode h= tag: {e}"]

    # Verify header hash
    h_info = h_obj.get("h")
    if not h_info or len(h_info) != 2:
        errors.append("Message-Instance: invalid h.h format")
    else:
        h_alg, h_val = h_info
        if h_alg != "sha256":
            errors.append(f"Message-Instance: unsupported header hash algorithm: {h_alg}")
        else:
            expected = compute_header_hash(headers)
            actual = base64.b64decode(h_val)
            if expected != actual:
                errors.append(
                    f"Message-Instance: header hash mismatch\n"
                    f"  expected: {b64(expected)}\n"
                    f"  got:      {h_val}"
                )

    # Verify body hash
    b_info = h_obj.get("b")
    if not b_info or len(b_info) != 2:
        errors.append("Message-Instance: invalid h.b format")
    else:
        b_alg, b_val = b_info
        if b_alg != "sha256":
            errors.append(f"Message-Instance: unsupported body hash algorithm: {b_alg}")
        else:
            expected = compute_body_hash(body)
            actual = base64.b64decode(b_val)
            if expected != actual:
                errors.append(
                    f"Message-Instance: body hash mismatch\n"
                    f"  expected: {b64(expected)}\n"
                    f"  got:      {b_val}"
                )

    return errors


def verify_dkim2_signature(sig_hdr: str, mi_headers: list[str],
                           other_sig_headers: list[str],
                           dns_data: dict) -> list[str]:
    """Verify a single DKIM2-Signature header.

    Args:
        sig_hdr: The DKIM2-Signature header string to verify
        mi_headers: All Message-Instance headers in the message
        other_sig_headers: All DKIM2-Signature headers with lower i= values
        dns_data: DNS records dict from dns.json

    Returns a list of errors (empty = success).
    """
    errors = []
    value = _get_header_value(sig_hdr)

    # Extract required tags
    i_val = _extract_tag(value, "i")
    v_val = _extract_tag(value, "v")
    d_val = _extract_tag(value, "d")
    s_b64 = _extract_tag(value, "s")

    if not all([i_val, v_val, d_val, s_b64]):
        return [f"DKIM2-Signature i={i_val}: missing required tags"]

    # Decode s= tag
    try:
        s_obj = json.loads(base64.b64decode(s_b64))
    except Exception as e:
        return [f"DKIM2-Signature i={i_val}: failed to decode s= tag: {e}"]

    # s= is an array of [selector, algorithm, value] arrays
    if not isinstance(s_obj, list) or len(s_obj) < 1:
        return [f"DKIM2-Signature i={i_val}: invalid s= format (expected array of arrays)"]

    # Verify the first signature item (TODO: support multiple for algorithm agility)
    first_item = s_obj[0]
    if not isinstance(first_item, list) or len(first_item) != 3:
        return [f"DKIM2-Signature i={i_val}: invalid s= item format (expected [selector, algorithm, value])"]

    selector, algorithm, sig_value_b64 = first_item

    # Look up public key
    try:
        public_key, key_type = lookup_public_key(d_val, selector, dns_data)
    except (KeyError, ValueError) as e:
        return [f"DKIM2-Signature i={i_val}: key lookup failed: {e}"]

    # Normalise algorithm names: "rsa-sha256" and "rsa" are equivalent
    ALG_ALIASES = {"rsa-sha256": "rsa", "ed25519-sha256": "ed25519"}
    norm_algorithm = ALG_ALIASES.get(algorithm, algorithm)

    if norm_algorithm != key_type:
        errors.append(
            f"DKIM2-Signature i={i_val}: algorithm mismatch: "
            f"sig says {algorithm!r}, key is {key_type!r}"
        )

    # Reconstruct the incomplete signature with empty s= value,
    # following the DKIM1 convention for b=.
    s_tag_pos = sig_hdr.rfind("s=")
    if s_tag_pos == -1:
        return [f"DKIM2-Signature i={i_val}: cannot find s= tag in header"]
    incomplete_sig = sig_hdr[:s_tag_pos + 2]

    # Collect MI headers up to version v=
    mi_version = int(v_val)
    relevant_mi = sorted(
        [h for h in mi_headers if _get_version_from_mi(h) <= mi_version],
        key=_get_version_from_mi,
    )
    prior_sigs = sorted(other_sig_headers, key=_get_seq_from_sig)

    # Per draft-clayton-dkim2-spec-08 Section 11.5:
    # 1. All MI headers in ascending v= order
    # 2. All prior DKIM2-Signature headers in ascending i= order
    # 3. The incomplete DKIM2-Signature being verified
    ordered: list[str] = []
    ordered.extend(relevant_mi)  # already sorted by version
    ordered.extend(prior_sigs)   # already sorted by sequence
    ordered.append(incomplete_sig)

    # Canonicalize and hash
    canon = [canonicalize_sig_header(h) for h in ordered]
    data = b"\r\n".join(canon)
    if data:
        data += b"\r\n"
    digest = hashlib.sha256(data).digest()

    # Verify signature
    sig_bytes = base64.b64decode(sig_value_b64)

    try:
        if norm_algorithm == "ed25519":
            public_key.verify(sig_bytes, digest)
        elif norm_algorithm == "rsa":
            public_key.verify(
                sig_bytes,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        else:
            errors.append(f"DKIM2-Signature i={i_val}: unsupported algorithm: {algorithm}")
            return errors
    except Exception as e:
        errors.append(f"DKIM2-Signature i={i_val}: signature verification FAILED: {e}")

    return errors


def verify_message(raw: bytes, dns_data: dict, full_chain: bool = False,
                   verbose: bool = False) -> list[str]:
    """Verify all DKIM2 signatures in a message.

    If full_chain is True, walks backwards through MI versions, undoing
    recipes at each step and verifying that each MI's hashes match the
    reconstructed message state, and each DKIM2-Signature verifies against
    the MI/sig headers that existed at that point.

    Returns a list of errors (empty = all passed).
    """
    headers, body = parse_message(raw)
    all_errors = []

    mi_headers = extract_mi_headers(headers)
    sig_headers = extract_sig_headers(headers)

    if not sig_headers:
        return ["No DKIM2-Signature headers found"]
    if not mi_headers:
        return ["No Message-Instance headers found"]

    # Collect the non-MI, non-sig headers for hash verification
    content_headers = []
    for hdr in headers:
        name = _header_name(hdr)
        if name not in (b"message-instance", b"dkim2-signature"):
            content_headers.append(hdr)

    if not full_chain:
        # Simple mode: verify highest MI against current message, verify all sigs
        for mi_hdr in mi_headers:
            errs = verify_message_instance(mi_hdr, content_headers, body)
            all_errors.extend(errs)

        sig_by_seq = sorted(sig_headers, key=_get_seq_from_sig)
        for idx, sig_hdr in enumerate(sig_by_seq):
            prior_sigs = sig_by_seq[:idx]
            errs = verify_dkim2_signature(sig_hdr, mi_headers, prior_sigs, dns_data)
            all_errors.extend(errs)

        return all_errors

    # Full chain validation: walk backwards through MI versions
    from dkim2undo import decode_recipes, reconstruct_headers, reconstruct_body

    mi_by_version = {}
    for mi_hdr in mi_headers:
        v = _get_version_from_mi(mi_hdr)
        mi_by_version[v] = mi_hdr

    sig_by_seq = sorted(sig_headers, key=_get_seq_from_sig)

    versions = sorted(mi_by_version.keys(), reverse=True)
    highest = versions[0]

    current_content_headers = list(content_headers)
    current_body = body

    for version in versions:
        mi_hdr = mi_by_version[version]

        if verbose:
            print(f"Verifying MI v={version}...", file=sys.stderr)

        # Verify this MI's hashes against the current message state
        errs = verify_message_instance(mi_hdr, current_content_headers, current_body)
        if errs:
            for e in errs:
                all_errors.append(f"v={version}: {e}")
        elif verbose:
            print(f"  MI v={version} hashes: OK", file=sys.stderr)

        # Verify all DKIM2-Signatures that reference this MI version (v= tag)
        for idx, sig_hdr in enumerate(sig_by_seq):
            sig_value = _get_header_value(sig_hdr)
            sig_v = _extract_tag(sig_value, "v")
            if sig_v and int(sig_v) == version:
                i_val = _extract_tag(sig_value, "i")
                # Collect MI headers up to this version
                relevant_mi = [mi_by_version[v] for v in sorted(mi_by_version)
                               if v <= version]
                prior_sigs = sig_by_seq[:idx]
                errs = verify_dkim2_signature(
                    sig_hdr, relevant_mi, prior_sigs, dns_data
                )
                if errs:
                    all_errors.extend(errs)
                elif verbose:
                    print(f"  DKIM2-Signature i={i_val}: OK", file=sys.stderr)

        # If there's a lower version, undo recipes to reconstruct previous state
        if version > versions[-1]:
            recipes = decode_recipes(mi_hdr)
            if recipes is not None:
                h_recipes = recipes.get("h")
                if h_recipes and isinstance(h_recipes, dict) and len(h_recipes) > 0:
                    try:
                        current_content_headers = reconstruct_headers(
                            current_content_headers, h_recipes
                        )
                        if verbose:
                            print(f"  Undid header recipes for v={version}",
                                  file=sys.stderr)
                    except ValueError as e:
                        all_errors.append(
                            f"v={version}: failed to undo header recipes: {e}"
                        )

                b_recipes = recipes.get("b")
                if b_recipes and isinstance(b_recipes, list):
                    try:
                        current_body = reconstruct_body(
                            current_body, b_recipes
                        )
                        if verbose:
                            print(f"  Undid body recipes for v={version}",
                                  file=sys.stderr)
                    except ValueError as e:
                        all_errors.append(
                            f"v={version}: failed to undo body recipes: {e}"
                        )

    return all_errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Verify DKIM2 signatures (draft-clayton-dkim2-spec-08)")
    parser.add_argument("message", help="Path to signed email file (- for stdin)")
    parser.add_argument("--dns-json", required=True,
                        help="Path to dns.json with public keys")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print detailed verification results")
    parser.add_argument("--full-chain", action="store_true",
                        help="Walk backwards through all MI versions, "
                             "undoing recipes and verifying each signature")
    args = parser.parse_args()

    if args.message == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(args.message).read_bytes()

    dns_data = load_dns_json(args.dns_json)
    errors = verify_message(raw, dns_data, full_chain=args.full_chain,
                            verbose=args.verbose)

    if args.verbose or errors:
        headers, _ = parse_message(raw)
        sig_headers = extract_sig_headers(headers)
        mi_headers = extract_mi_headers(headers)
        print(f"Message-Instance headers: {len(mi_headers)}")
        print(f"DKIM2-Signature headers:  {len(sig_headers)}")
        for sig in sig_headers:
            value = _get_header_value(sig)
            i_val = _extract_tag(value, "i")
            d_val = _extract_tag(value, "d")
            s_b64 = _extract_tag(value, "s")
            if s_b64:
                try:
                    s_obj = json.loads(base64.b64decode(s_b64))
                    if isinstance(s_obj, list) and len(s_obj) >= 1 and len(s_obj[0]) >= 2:
                        print(f"  i={i_val} d={d_val} selector={s_obj[0][0]} algorithm={s_obj[0][1]}")
                    else:
                        print(f"  i={i_val} d={d_val}")
                except Exception:
                    print(f"  i={i_val} d={d_val}")
            else:
                print(f"  i={i_val} d={d_val}")

    if errors:
        print("")
        for err in errors:
            print(f"ERROR: {err}")
        sys.exit(1)
    else:
        if args.verbose:
            print("")
        print("PASS: all signatures verified")
        sys.exit(0)


if __name__ == "__main__":
    main()
