#!/usr/bin/env python3
"""
DKIM2 verifier - draft-ietf-dkim-dkim2-spec-04

Takes a signed email and verifies its DKIM2 signatures using public keys
from a dns.json file or DNS TXT records.

Exits 0 if all signatures verify, non-zero otherwise.
"""

import argparse
import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import re
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils


# ---------------------------------------------------------------------------
# Reuse canonicalization from dkim2sign
# ---------------------------------------------------------------------------

from dkim2sign import (
    parse_message,
    _to_bytes,
    _header_name,
    _should_exclude_header,
    canonicalize_header_field,
    compute_header_hash,
    compute_body_hash,
    HASH_ALGS,
    canonicalize_sig_header,
    _extract_tag,
    _tag_names,
    _get_version_from_mi,
    _get_seq_from_sig,
    b64,
    b64json,
    Source,
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
            # h= (hash algorithm list) MUST be ignored per spec-04 Section 10.3
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
            elif key_type in ("rsa", "rsa-sha256"):
                # RSA public key is DER-encoded SubjectPublicKeyInfo
                return serialization.load_der_public_key(pub_bytes), "rsa"
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

    raise KeyError(f"No TXT record found for {selector_key}.{domain}")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _domain_from_addr(addr: str) -> str:
    """Extract lowercase domain from '<local@domain>' or 'local@domain'."""
    addr = addr.strip().strip("<>")
    at = addr.rfind("@")
    return addr[at + 1:].lower() if at >= 0 else addr.lower()


def _relaxed_domain_match(d1: str, d2: str) -> bool:
    """Return True if d1 equals d2 or d1 is a subdomain of d2."""
    d1, d2 = d1.lower(), d2.lower()
    return d1 == d2 or d1.endswith("." + d2)


def _envelope_addr_equal(a: str, b: str) -> bool:
    """Exact envelope-address match per spec "Check the Chain-of-Custody":
    domains are compared case-insensitively, local-parts case-sensitively.
    Surrounding angle brackets are ignored so bracketed and bare forms
    compare equal; the null sender (<>) matches only the null sender."""
    a = a.strip().strip("<>")
    b = b.strip().strip("<>")
    a_at, b_at = a.rfind("@"), b.rfind("@")
    if a_at < 0 or b_at < 0:
        return a == b
    return a[:a_at] == b[:b_at] and a[a_at + 1:].lower() == b[b_at + 1:].lower()


def _bracket_errors(sig_headers: list[str]) -> list[str]:
    """Spec §7.5/§7.6: every present mf= and rt= entry MUST be a bracketed
    RFC5321 path (matches <...>, incl. <>). nd= hops carry no mf/rt and are
    skipped (checked implicitly since their mf=/rt= tags are absent)."""
    errs = []
    for sig_hdr in sig_headers:
        value = _get_header_value(sig_hdr)
        i_val = _extract_tag(value, "i")
        for tag, section in (("mf", "5"), ("rt", "6")):
            raw = _extract_tag(value, tag)
            if not raw:
                continue
            for part in raw.split(","):
                part = part.strip()
                if not part:
                    continue
                dec = base64.b64decode(part).decode("utf-8", errors="surrogateescape")
                if not (dec.startswith("<") and dec.endswith(">")):
                    errs.append(
                        f"DKIM2-Signature i={i_val}: {tag}= is not a bracketed "
                        f"RFC5321 path (spec 7.{section})"
                    )
    return errs


def _chain_custody_errors(sig_by_seq: list[str]) -> list[str]:
    """Validate §8.2/§11.4 chain-of-custody across consecutive signatures.

    For each adjacent pair (ascending i=), either the lower signature carries
    nd= (which MUST exactly match the higher signature's d=), or the higher
    signature's mf= domain MUST relaxed-match an rt= domain of the lower one.
    """
    errors = []
    for k in range(1, len(sig_by_seq)):
        cur_val = _get_header_value(sig_by_seq[k])
        prev_val = _get_header_value(sig_by_seq[k - 1])
        cur_i = _extract_tag(cur_val, "i")
        prev_i = _extract_tag(prev_val, "i")
        prev_nd = _extract_tag(prev_val, "nd")
        if prev_nd:
            # draft-04 §11.4: nd= MUST exactly match the next sig's d=.
            cur_d = _extract_tag(cur_val, "d") or ""
            if prev_nd.lower() != cur_d.lower():
                errors.append(
                    f"DKIM2-Signature i={prev_i} MAIL nd= does not match"
                )
            continue
        cur_mf_b64 = _extract_tag(cur_val, "mf")
        prev_rt_raw = _extract_tag(prev_val, "rt")
        if not cur_mf_b64:
            errors.append(
                f"DKIM2-Signature i={cur_i} MAIL FROM <> did not match"
            )
            continue
        if not prev_rt_raw:
            errors.append(
                f"DKIM2-Signature i={prev_i} RCPT TO <> did not match"
            )
            continue
        cur_mf = base64.b64decode(cur_mf_b64).decode("utf-8", errors="surrogateescape")
        prev_rts = [
            base64.b64decode(rt.strip()).decode("utf-8", errors="surrogateescape")
            for rt in prev_rt_raw.split(",") if rt.strip()
        ]
        cur_mf_domain = _domain_from_addr(cur_mf)
        if not any(_relaxed_domain_match(cur_mf_domain, _domain_from_addr(rt))
                   for rt in prev_rts):
            errors.append(
                f"DKIM2-Signature i={cur_i} MAIL FROM {cur_mf} did not match"
            )
    return errors


def _strip_fws(s: str) -> str:
    """Remove folding whitespace from a tag value.

    Per spec-04 §2.12 folding whitespace may appear inside a base64 string or
    around the colons of an s= item, and MUST be ignored when the value is
    used.  Selectors, algorithm names and base64 never contain significant
    whitespace, so removing all of it is safe.
    """
    return s.translate(_FWS_TABLE)


_FWS_TABLE = {ord(c): None for c in " \t\r\n"}


def _sig_flags(sig_hdr: str) -> list[str]:
    """Return the f= flag list of a DKIM2-Signature header (draft-04 §8.10)."""
    f = _extract_tag(_get_header_value(sig_hdr), "f")
    return [x.strip() for x in f.split(",") if x.strip()] if f else []


def _flag_enforcement_errors(sig_by_seq: list[str], mi_headers: list[str]) -> list[str]:
    """Enforce the donotmodify/donotexplode flags (draft-04 §11.8).

    feedback/feedhere are recognised but carry no verifier enforcement.
    """
    errors = []
    # Map MI version -> (header_hash, body_hash)
    mi_hash = {}
    for mi in mi_headers:
        val = _get_header_value(mi)
        m = _extract_tag(val, "m")
        h = _extract_tag(val, "h")
        if m is None or h is None:
            continue
        parts = h.split(":")
        if len(parts) >= 3:
            mi_hash[int(m)] = (parts[1], parts[2])

    sigs = []
    for s in sig_by_seq:
        val = _get_header_value(s)
        sigs.append({
            "i": _extract_tag(val, "i"),
            "m": _extract_tag(val, "m"),
            "flags": _sig_flags(s),
        })

    for p in sigs:
        if "donotmodify" in p["flags"] and p["m"] is not None:
            m = int(p["m"])
            if m in mi_hash and (m + 1) in mi_hash and mi_hash[m] != mi_hash[m + 1]:
                errors.append(
                    f"DKIM2-Signature i={p['i']}: message modified despite "
                    f"donotmodify request"
                )
        if "donotexplode" in p["flags"] and p["i"] is not None:
            for q in sigs:
                if (q["i"] is not None and int(q["i"]) > int(p["i"])
                        and "exploded" in q["flags"]):
                    errors.append(
                        f"DKIM2-Signature i={q['i']}: message exploded despite "
                        f"donotexplode request at i={p['i']}"
                    )
    return errors


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


def _b64decode_strict(val: str) -> bytes | None:
    """Decode a base64 value, returning None (never raising) if malformed.

    Uses validate=True so stray non-alphabet characters are rejected instead
    of silently discarded (the default base64.b64decode behaviour, which
    would otherwise turn a corrupt hash value into a wrong-but-decodable one).
    """
    try:
        return base64.b64decode(val, validate=True)
    except (binascii.Error, ValueError):
        return None


def parse_hash_sets(h_tag: str) -> list[tuple[str, str, str]]:
    """Parse a spec-05 §7.3 h= value into (alg, header_hash, body_hash) triples.

    Hash names are lowercased: RFC 5234 makes ABNF quoted strings
    case-insensitive, so "SHA256" is a syntactically valid hash-name.

    Per spec-04 §2.12, folding whitespace may appear inside a base64 string
    (or around the colons) and MUST be ignored when the value is used, so
    every field is run through _strip_fws rather than a bare .strip().
    """
    sets = []
    for item in h_tag.split(","):
        parts = _strip_fws(item).split(":")
        if len(parts) != 3:
            continue
        sets.append((parts[0].lower(), parts[1], parts[2]))
    return sets


def verify_message_instance(mi_hdr: str, headers: list[bytes], body: bytes) -> list[str]:
    """Verify the hashes in a Message-Instance header against the message.

    Returns a list of errors (empty = success).
    """
    errors = []
    value = _get_header_value(mi_hdr)
    m_val = _extract_tag(value, "m")

    # §11.2: a malformed r= payload is reported specifically, regardless of
    # what else is wrong with this Message-Instance header. Two distinct
    # failure kinds, kept distinct rather than both being called "invalid
    # JSON": a bad base64 r= value never even reaches JSON parsing -- §11.2
    # lists this as a plain syntax error -- while a JSON parse failure is
    # the more specific "contains invalid JSON" case.
    r_tag = _extract_tag(value, "r")
    if r_tag:
        r_bytes = _b64decode_strict(r_tag)
        if r_bytes is None:
            errors.append(
                f"PERMERROR Message-Instance m={m_val} syntax error"
            )
        else:
            try:
                json.loads(r_bytes)
            except json.JSONDecodeError:
                errors.append(
                    f"PERMERROR Message-Instance m={m_val} contains invalid JSON"
                )

    h_tag = _extract_tag(value, "h")
    if not h_tag:
        return errors + ["Message-Instance: missing h= tag"]

    sets = parse_hash_sets(h_tag)
    if not sets:
        return errors + [f"Message-Instance: invalid h= format (got {h_tag!r})"]

    # spec-05 §7.3: an algorithm MUST NOT be present more than once.
    seen = set()
    for alg, _, _ in sets:
        if alg in seen:
            return errors + [f"PERMERROR Message-Instance m={m_val} has a duplicate hash algorithm"]
        seen.add(alg)

    # §3.4: ignore hash-sets naming algorithms we do not implement, but an MI
    # with no implemented hash-set cannot be verified and must fail closed.
    usable = [s for s in sets if s[0] in HASH_ALGS]
    if not usable:
        return errors + [f"Message-Instance m={m_val} no supported hash algorithm"]

    # All implemented hash-sets must pass (mirrors §11.6 for signatures). A
    # malformed base64 value in one hash-set is itself a PERMERROR (§11.2:
    # verifiers MUST meticulously validate format and values); it does not
    # abort the whole MI check, mirroring the non-short-circuit "all usable
    # hash-sets are checked" behaviour of a hash mismatch below.
    for alg, h_val, b_val in usable:
        h_actual = _b64decode_strict(h_val)
        if h_actual is None:
            errors.append(
                f"PERMERROR Message-Instance m={m_val} {alg} header hash is "
                f"not valid base64 (got {h_val!r})"
            )
        else:
            expected = compute_header_hash(headers, alg)
            if expected != h_actual:
                errors.append(
                    f"Message-Instance: {alg} header hash mismatch\n"
                    f"  expected: {b64(expected)}\n"
                    f"  got:      {h_val}"
                )

        b_actual = _b64decode_strict(b_val)
        if b_actual is None:
            errors.append(
                f"PERMERROR Message-Instance m={m_val} {alg} body hash is "
                f"not valid base64 (got {b_val!r})"
            )
        else:
            expected = compute_body_hash(body, alg)
            if expected != b_actual:
                errors.append(
                    f"Message-Instance: {alg} body hash mismatch\n"
                    f"  expected: {b64(expected)}\n"
                    f"  got:      {b_val}"
                )

    return errors


def _check_signature_duplicates(sig_items, i_val) -> list[str]:
    """spec-05 §8.9 duplicate/limit rules for one DKIM2-Signature s= tag.

    A Selector MUST NOT appear more than once. The same signing algorithm may
    appear at most twice, and only with distinct Selectors. Selector matching is
    case-insensitive (a Selector is a Domain, §3.5).
    """
    errors = []
    selectors = [sel.lower() for sel, _, _ in sig_items]
    if len(set(selectors)) != len(selectors):
        errors.append(f"PERMERROR DKIM2-Signature i={i_val} has a duplicate selector")
    counts = {}
    for _, alg, _ in sig_items:
        counts[alg.lower()] = counts.get(alg.lower(), 0) + 1
    if any(n > 2 for n in counts.values()):
        errors.append(f"PERMERROR DKIM2-Signature i={i_val} has too many signatures")
    return errors


def verify_dkim2_signature(sig_hdr: str, mi_headers: list[str],
                           other_sig_headers: list[str],
                           dns_data: dict,
                           skip_timestamp_check: bool = False) -> list[str]:
    """Verify a single DKIM2-Signature header.

    Args:
        sig_hdr: The DKIM2-Signature header string to verify
        mi_headers: All Message-Instance headers in the message
        other_sig_headers: All DKIM2-Signature headers with lower i= values
        dns_data: DNS records dict from dns.json
        skip_timestamp_check: if True, skip §10.3 14-day expiry check

    Returns a list of errors (empty = success).
    """
    errors = []
    value = _get_header_value(sig_hdr)

    # §8: "there MUST be only one of each kind" of tag.
    seen = _tag_names(value)
    dups = sorted({n for n in seen if seen.count(n) > 1})
    if dups:
        return [f"DKIM2-Signature: duplicate tag {dups[0]!r} not permitted (§8)"]

    # Extract required tags
    i_val = _extract_tag(value, "i")
    m_val = _extract_tag(value, "m")
    t_val0 = _extract_tag(value, "t")
    d_val = _extract_tag(value, "d")
    s_tag = _extract_tag(value, "s")
    nd_val = _extract_tag(value, "nd")
    mf_val = _extract_tag(value, "mf")
    rt_val = _extract_tag(value, "rt")

    # draft-04 §8: i= m= t= d= s= MUST be present; plus either nd= or both
    # mf= and rt= (and nd= excludes mf=/rt=).
    if not all([i_val, m_val, t_val0, d_val, s_tag]):
        for tag_name, tag_val in (
            ("i", i_val), ("m", m_val), ("t", t_val0), ("d", d_val), ("s", s_tag),
        ):
            if not tag_val:
                return [f"DKIM2-Signature i={i_val} tag={tag_name} missing"]
    if nd_val and (mf_val or rt_val):
        return [f"DKIM2-Signature i={i_val} tag=nd was unexpected"]
    if not nd_val and not (mf_val and rt_val):
        return [f"DKIM2-Signature i={i_val} tag=mf missing"]

    # §7.3 SHOULD: n= nonce must not exceed 64 characters
    n_val = _extract_tag(value, "n")
    if n_val and len(n_val) > 64:
        return [f"DKIM2-Signature i={i_val}: n= nonce exceeds 64 characters ({len(n_val)})"]

    # §10.3 SHOULD: reject signatures more than 14 days old or in the future
    t_val = _extract_tag(value, "t")
    if t_val and not skip_timestamp_check:
        try:
            ts = int(t_val)
            now = int(time.time())
            if ts > now + 300:
                return [f"DKIM2-Signature i={i_val}: timestamp is in the future"]
            if now > ts + 14 * 24 * 3600:
                return [f"DKIM2-Signature i={i_val}: signature has expired (age > 14 days)"]
        except ValueError:
            pass

    # Relaxed d<->mf per-sig check (mirrors Perl Verifier.pm:326-333): the
    # envelope MAIL FROM domain must equal or be a subdomain of d=, unless
    # the sender is the null sender (<>).
    if mf_val:
        decoded_mf = base64.b64decode(mf_val).decode("utf-8", errors="surrogateescape")
        if decoded_mf != "<>":
            mf_domain = _domain_from_addr(decoded_mf)
            if not _relaxed_domain_match(mf_domain, d_val):
                errors.append(
                    f"DKIM2-Signature i={i_val} MAIL FROM and d= do not match"
                )
                return errors

    # Two parallel views of each s= item.  The *raw* fields keep whatever
    # folding whitespace the producer inserted, and are what we blank out of
    # the raw header below.  The *semantic* fields have FWS removed per §2.12
    # ("folding whitespace ... MUST be ignored when the value is used"), so a
    # fold anywhere inside the item -- including between the selector colon
    # and the algorithm token -- doesn't corrupt the selector, the algorithm
    # name or the base64 signature.
    sig_items_raw = []
    sig_items = []
    for part in s_tag.split(","):
        fields = part.split(":", 2)
        if len(fields) != 3:
            return [f"DKIM2-Signature i={i_val}: invalid s= item format: {part!r}"]
        sig_items_raw.append(fields)
        sig_items.append([_strip_fws(f) for f in fields])

    # spec-05 §8.9: duplicate-selector and too-many-signatures checks must run
    # before any DNS lookup or crypto work.
    dup_errors = _check_signature_duplicates(sig_items, i_val)
    if dup_errors:
        return dup_errors

    # Build the incomplete signature (the signed form) by blanking each s=
    # item's signature value in place.  This is independent of tag order and
    # whitespace: we simply remove the base64 signature bytes wherever they
    # appear, leaving selector:algorithm: and every other tag untouched.
    incomplete_sig = sig_hdr
    for selector, algorithm, sig_value_b64 in sig_items_raw:
        incomplete_sig = incomplete_sig.replace(
            f"{selector}:{algorithm}:{sig_value_b64}",
            f"{selector}:{algorithm}:",
        )

    mi_version = int(m_val)
    relevant_mi = sorted(
        [h for h in mi_headers if _get_version_from_mi(h) <= mi_version],
        key=_get_version_from_mi,
    )
    prior_sigs = sorted(other_sig_headers, key=_get_seq_from_sig)

    ordered: list[str] = []
    ordered.extend(relevant_mi)
    ordered.extend(prior_sigs)
    ordered.append(incomplete_sig)

    canon = [canonicalize_sig_header(h) for h in ordered]
    data = b"".join(canon)
    digest = hashlib.sha256(data).digest()

    ALG_ALIASES = {"rsa-sha256": "rsa", "ed25519-sha256": "ed25519"}

    # §10.6: ALL s= items must verify; any crypto failure is an error
    verified_any = False
    item_err = None
    for selector, algorithm, sig_value_b64 in sig_items:
        try:
            public_key, key_type = lookup_public_key(d_val, selector, dns_data)
        except (KeyError, ValueError) as e:
            if item_err is None:
                item_err = f"DKIM2-Signature i={i_val}: key lookup failed: {e}"
            continue

        # §3.2: RSA keys MUST be at least 1024 bits; reject shorter keys
        # (permerror) rather than trusting a weak signature.
        if key_type == "rsa" and getattr(public_key, "key_size", 0) < 1024:
            item_err = (
                f"DKIM2-Signature i={i_val}: RSA key too short "
                f"({public_key.key_size} bits < 1024, §3.2)"
            )
            continue

        norm_algorithm = ALG_ALIASES.get(algorithm, algorithm)
        if norm_algorithm != key_type:
            item_err = (
                f"DKIM2-Signature i={i_val}: algorithm mismatch: "
                f"sig says {algorithm!r}, key is {key_type!r}"
            )
            continue

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
                item_err = f"DKIM2-Signature i={i_val}: unsupported algorithm: {algorithm}"
                continue
        except Exception as e:
            errors.append(f"DKIM2-Signature i={i_val}: signature verification FAILED: {e}")
            return errors
        verified_any = True

    if not verified_any:
        errors.append(item_err or f"DKIM2-Signature i={i_val}: no verifiable signature items")

    return errors


@dataclass
class VerifyResult:
    ok: bool                      # True iff verification passed
    status: str                   # 'pass', 'fail', 'permerror', 'temperror', 'none'
    failing_i: int | None         # i= of the signature that failed, None on pass
    domain: str | None            # d= of the failing/passing signature
    message: str                  # one-line human-readable summary
    errors: list[str] = field(default_factory=list)  # all error detail strings


def _classify_status(errors: list[str]) -> str:
    """Map collected errors to a result status string."""
    if not errors:
        return 'pass'
    e = errors[0].lower()
    if 'no dkim2-signature' in e:
        return 'none'
    if 'temperror' in e:
        return 'temperror'
    # Crypto/hash/custody failures
    if any(k in e for k in ('failed', 'mismatch', 'break', 'expired', 'not match')):
        return 'fail'
    # Structural/format problems
    return 'permerror'


def _extract_failing_i(errors: list[str]) -> int | None:
    """Extract the first i= value mentioned in any error string."""
    for err in errors:
        m = re.search(r'\bi=(\d+)\b', err)
        if m:
            return int(m.group(1))
    return None


def _make_result(errors: list[str], top_sig_i: int, top_domain: str) -> VerifyResult:
    if not errors:
        return VerifyResult(
            ok=True, status='pass', failing_i=None, domain=top_domain,
            message=f'pass: DKIM2-Signature i={top_sig_i} d={top_domain}',
            errors=[],
        )
    status = _classify_status(errors)
    failing_i = _extract_failing_i(errors)
    return VerifyResult(
        ok=False, status=status, failing_i=failing_i,
        domain=top_domain if failing_i == top_sig_i else None,
        message=errors[0], errors=errors,
    )


def verify_message(source: "Source", dns_data: dict, full_chain: bool = False,
                   verbose: bool = False,
                   skip_timestamp_check: bool = False,
                   mail_from: str | None = None,
                   rcpt_to: list[str] | None = None) -> "VerifyResult":
    """Verify all DKIM2 signatures in a message.

    If full_chain is True, walks backwards through MI versions, undoing
    recipes at each step and verifying that each MI's hashes match the
    reconstructed message state, and each DKIM2-Signature verifies against
    the MI/sig headers that existed at that point.

    Returns a VerifyResult (ok=True on success).
    """
    raw = _to_bytes(source)
    headers, body = parse_message(raw)
    all_errors = []

    mi_headers = extract_mi_headers(headers)
    sig_headers = extract_sig_headers(headers)

    if not sig_headers:
        return VerifyResult(ok=False, status='none', failing_i=None, domain=None,
                            message='no DKIM2-Signature headers',
                            errors=['no DKIM2-Signature headers'])
    if not mi_headers:
        return VerifyResult(ok=False, status='permerror', failing_i=None, domain=None,
                            message='no Message-Instance headers',
                            errors=['no Message-Instance headers'])

    # Spec-01 §9/§10: top DKIM2-Signature must cover the topmost MI
    max_mi_version = max(_get_version_from_mi(h) for h in mi_headers)
    top_sig = max(sig_headers, key=_get_seq_from_sig)
    top_sig_value = _get_header_value(top_sig)
    top_sig_seq = _extract_tag(top_sig_value, "i")
    top_sig_m = _extract_tag(top_sig_value, "m")
    top_sig_m_int = int(top_sig_m) if top_sig_m else 0
    if top_sig_m_int != max_mi_version:
        top_sig_i = _get_seq_from_sig(top_sig)
        top_domain = _extract_tag(_get_header_value(top_sig), 'd') or ''
        msg = (f"top signature i={top_sig_seq} m={top_sig_m_int} does not cover "
               f"topmost MI m={max_mi_version}")
        return VerifyResult(ok=False, status='permerror', failing_i=top_sig_i,
                            domain=top_domain, message=msg, errors=[msg])

    # Local policy: the top (highest-i=) DKIM2-Signature MUST NOT carry nd=.
    # nd= only ever legitimately appears together with a subsequent, higher-i=
    # signature that takes over custody; a top-of-chain nd= means the chain
    # is incomplete/tampered, so reject before any further checks run.
    if _extract_tag(top_sig_value, "nd"):
        top_i = _get_seq_from_sig(top_sig)
        msg = f"DKIM2-Signature i={top_sig_seq} unexpected nd= tag"
        return VerifyResult(ok=False, status='permerror', failing_i=top_i,
                            domain=_extract_tag(top_sig_value, 'd') or '',
                            message=msg, errors=[msg])

    # Envelope MAIL FROM / RCPT TO checks (spec §"Check the Chain-of-Custody"):
    # exact match against the top signature's declared mf=/rt=, domains
    # lowercased, local-part case-sensitive. Applies regardless of
    # full_chain/simple mode. rt= MAY carry extra recipients beyond what was
    # actually delivered; every delivered RCPT TO must be present in the set.
    if mail_from is not None or rcpt_to:
        top_i = _get_seq_from_sig(top_sig)
        top_mf_b64 = _extract_tag(top_sig_value, "mf")
        top_rt_raw = _extract_tag(top_sig_value, "rt")
        top_mf = (base64.b64decode(top_mf_b64).decode("utf-8", errors="surrogateescape")
                  if top_mf_b64 else None)
        top_rts = [
            base64.b64decode(rt.strip()).decode("utf-8", errors="surrogateescape")
            for rt in (top_rt_raw.split(",") if top_rt_raw else []) if rt.strip()
        ]

        if mail_from is not None:
            if top_mf is None or not _envelope_addr_equal(mail_from, top_mf):
                all_errors.append(
                    f"DKIM2-Signature i={top_i} MAIL FROM {mail_from} did not match"
                )
        for rcpt in (rcpt_to or []):
            if not any(_envelope_addr_equal(rcpt, rt) for rt in top_rts):
                all_errors.append(
                    f"DKIM2-Signature i={top_i} RCPT TO {rcpt} did not match"
                )

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

        # §8.2/§11.4: inter-sig chain custody (nd= or mf=/rt=)
        all_errors.extend(_chain_custody_errors(sig_by_seq))
        # §11.8: donotmodify/donotexplode enforcement
        all_errors.extend(_flag_enforcement_errors(sig_by_seq, mi_headers))
        # §7.5/§7.6: mf=/rt= MUST be bracketed RFC5321 paths
        all_errors.extend(_bracket_errors(sig_by_seq))

        for idx, sig_hdr in enumerate(sig_by_seq):
            prior_sigs = sig_by_seq[:idx]
            errs = verify_dkim2_signature(sig_hdr, mi_headers, prior_sigs, dns_data,
                                          skip_timestamp_check=skip_timestamp_check)
            all_errors.extend(errs)

        top_sig_i = _get_seq_from_sig(top_sig)
        top_domain = _extract_tag(_get_header_value(top_sig), 'd') or ''
        return _make_result(all_errors, top_sig_i, top_domain)

    # Full chain validation: walk backwards through MI versions
    from dkim2undo import decode_recipes, reconstruct_headers, reconstruct_body

    mi_by_version = {}
    for mi_hdr in mi_headers:
        v = _get_version_from_mi(mi_hdr)
        mi_by_version[v] = mi_hdr

    sig_by_seq = sorted(sig_headers, key=_get_seq_from_sig)

    # §8.2/§11.4: inter-sig chain custody check (full-chain mode)
    all_errors.extend(_chain_custody_errors(sig_by_seq))
    # §11.8: donotmodify/donotexplode enforcement
    all_errors.extend(_flag_enforcement_errors(sig_by_seq, mi_headers))
    # §7.5/§7.6: mf=/rt= MUST be bracketed RFC5321 paths
    all_errors.extend(_bracket_errors(sig_by_seq))

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
                # A self-describing PERMERROR already names its own m=
                # (e.g. "PERMERROR Message-Instance m=2 contains invalid
                # JSON"); prefixing "v=2: " on top of that would double up
                # the same information and stop the text from being the
                # verbatim §11.2 string. Only non-PERMERROR errors (which
                # don't otherwise say which version they're about) get the
                # v= prefix.
                if e.startswith("PERMERROR"):
                    all_errors.append(e)
                else:
                    all_errors.append(f"v={version}: {e}")
        elif verbose:
            print(f"  MI v={version} hashes: OK", file=sys.stderr)

        # Verify all DKIM2-Signatures that reference this MI version (m= tag)
        for idx, sig_hdr in enumerate(sig_by_seq):
            sig_value = _get_header_value(sig_hdr)
            sig_m = _extract_tag(sig_value, "m")
            if sig_m and int(sig_m) == version:
                i_val = _extract_tag(sig_value, "i")
                # Collect MI headers up to this version
                relevant_mi = [mi_by_version[v] for v in sorted(mi_by_version)
                               if v <= version]
                prior_sigs = sig_by_seq[:idx]
                errs = verify_dkim2_signature(
                    sig_hdr, relevant_mi, prior_sigs, dns_data,
                    skip_timestamp_check=skip_timestamp_check,
                )
                if errs:
                    all_errors.extend(errs)
                elif verbose:
                    print(f"  DKIM2-Signature i={i_val}: OK", file=sys.stderr)

        # If there's a lower version, undo recipes to reconstruct previous state
        if version > versions[-1]:
            # A malformed r= is already reported (as the specific §11.2
            # invalid-JSON PERMERROR) by the verify_message_instance() call
            # above; don't let the same failure crash decode_recipes() here
            # with an uncaught exception.
            try:
                recipes = decode_recipes(mi_hdr)
            except (ValueError, TypeError):
                recipes = None
            if recipes is not None:
                # draft-04 §5.1: a present "h" that is JSON null is a syntax
                # error (distinct from an absent "h", which means headers
                # were unchanged); mirrors dkim2undo.py's rejection.
                if "h" in recipes and recipes["h"] is None:
                    all_errors.append(
                        f"v={version}: header recipe is null: not permitted"
                    )
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

    top_sig_i = _get_seq_from_sig(top_sig)
    top_domain = _extract_tag(_get_header_value(top_sig), 'd') or ''
    return _make_result(all_errors, top_sig_i, top_domain)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Verify DKIM2 signatures (draft-ietf-dkim-dkim2-spec-04)")
    parser.add_argument("message", help="Path to signed email file (- for stdin)")
    parser.add_argument("--dns-json", required=True,
                        help="Path to dns.json with public keys")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print detailed verification results")
    parser.add_argument("--full-chain", action="store_true",
                        help="Accepted for compatibility; full-chain validation "
                             "is the default")
    parser.add_argument("--ignore-timestamps", "--skip-timestamp-check",
                        dest="skip_timestamp_check", action="store_true",
                        help="Disable the §10.3 timestamp (14-day/future) check")
    parser.add_argument("--mail-from",
                        help="Envelope MAIL FROM to check against the top "
                             "signature's mf= tag")
    parser.add_argument("--rcpt-to", action="append",
                        help="Envelope RCPT TO to check against the top "
                             "signature's rt= tag (repeatable)")
    args = parser.parse_args()

    if args.message == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(args.message).read_bytes()

    dns_data = load_dns_json(args.dns_json)
    # Full-chain validation is the default; --full-chain kept for compatibility.
    result = verify_message(raw, dns_data, full_chain=True,
                            verbose=args.verbose,
                            skip_timestamp_check=args.skip_timestamp_check,
                            mail_from=args.mail_from,
                            rcpt_to=args.rcpt_to)

    if args.verbose or not result.ok:
        headers, _ = parse_message(raw)
        sig_headers = extract_sig_headers(headers)
        mi_headers = extract_mi_headers(headers)
        print(f"Message-Instance headers: {len(mi_headers)}")
        print(f"DKIM2-Signature headers:  {len(sig_headers)}")
        for sig in sig_headers:
            value = _get_header_value(sig)
            i_val = _extract_tag(value, "i")
            d_val = _extract_tag(value, "d")
            s_tag = _extract_tag(value, "s")
            if s_tag:
                first = s_tag.split(",")[0].split(":", 2)
                if len(first) >= 2:
                    print(f"  i={i_val} d={d_val} selector={first[0]} algorithm={first[1]}")
                else:
                    print(f"  i={i_val} d={d_val}")
            else:
                print(f"  i={i_val} d={d_val}")

    if not result.ok:
        print("")
        if result.errors:
            for err in result.errors:
                print(f"ERROR: {err}")
        else:
            print(f"ERROR: {result.message}")
        sys.exit(1)
    else:
        if args.verbose:
            print("")
        print(f"PASS: {result.message}")
        sys.exit(0)


if __name__ == "__main__":
    main()
