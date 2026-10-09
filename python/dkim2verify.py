#!/usr/bin/env python3
"""
DKIM2 verifier - draft-ietf-dkim-dkim2-spec-06

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
    _sig_has_valid_i,
    _is_ascii_digits,
    chain_range_error,
    b64,
    b64json,
    Source,
)
from dkim2undo import (
    MalformedRecipe,
    decode_recipes,
    loads_recipe,
    reconstruct_body,
    reconstruct_headers,
    validate_recipes,
)


# ---------------------------------------------------------------------------
# DNS key lookup
# ---------------------------------------------------------------------------

def load_dns_json(path: str) -> dict:
    """Load a dns.json file mapping domain -> selector -> records."""
    return json.loads(Path(path).read_text())


class KeyRecordError(Exception):
    """A key record that exists but MUST NOT be used (spec-06 §11.5).

    `what` completes "public key <selector> ...": "has multiple records",
    "has a syntax error", "has been revoked" or "algorithm mismatch".
    """

    def __init__(self, what: str):
        super().__init__(what)
        self.what = what


_KEY_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_WSP = " \t\r\n"
# RFC 6376 §3.2 tag-value: VALCHARs, with WSP/FWS only between them. Every
# value is checked, including tags that are otherwise ignored, so a NUL, DEL
# or 8-bit byte anywhere makes the record a syntax error (spec-06 §11.5).
_KEY_TAG_VALUE = re.compile(r"(?:[\x21-\x3a\x3c-\x7e]+(?:[ \t\r\n]+[\x21-\x3a\x3c-\x7e]+)*)?")


def parse_key_record(txt: str) -> dict | None:
    """Parse a key record as a whole tag-list (dkim2-dns-00 §3.2, §3.4.1).

    Returns tag -> value, or None if the record is not a valid tag-list: a
    spec that is not `name = value`, a bad tag name, a value outside the
    tag-value grammar, a repeated tag, or a v=
    that is not the first tag or not exactly "DKIM1". Empty specs (e.g. after
    a trailing ';') are skipped. Tag names are case sensitive.
    """
    tags: dict[str, str] = {}
    for spec in txt.split(";"):
        if not spec.strip(_WSP):
            continue
        if "=" not in spec:
            return None
        name, val = spec.split("=", 1)
        name = name.strip(_WSP)
        val = val.strip(_WSP)
        if (not _KEY_TAG_NAME.fullmatch(name) or name in tags
                or not _KEY_TAG_VALUE.fullmatch(val)):
            return None
        tags[name] = val
    if "v" in tags and (next(iter(tags)) != "v" or tags["v"] != "DKIM1"):
        return None
    return tags


def lookup_public_key(domain: str, selector: str, dns_data: dict):
    """Look up and validate a public key from dns.json.

    dns.json maps domain -> "<selector>._domainkey" -> list of [type, value]
    records. A TXT value may be a string, or a list of strings: the
    character-strings of one RR, concatenated with nothing between them
    (dkim2-dns-00 §3.4.2.2). More than one TXT record is an error.

    Returns (key_object, key_type) with key_type "rsa" or "ed25519".
    Raises KeyError if there is no record (absent key), KeyRecordError if
    the record exists but MUST NOT be used.
    """
    domain_records = dns_data.get(domain)
    if not domain_records:
        raise KeyError(f"Domain {domain!r} not found in dns.json")

    selector_key = f"{selector}._domainkey"
    records = domain_records.get(selector_key)
    if not records:
        raise KeyError(f"Selector {selector_key!r} not found for {domain}")

    txts = [v for t, v in records if t.lower() == "txt"]
    if not txts:
        raise KeyError(f"No TXT record found for {selector_key}.{domain}")
    if len(txts) > 1:
        raise KeyRecordError("has multiple records")
    txt = txts[0] if isinstance(txts[0], str) else "".join(txts[0])

    tags = parse_key_record(txt)
    if tags is None or "p" not in tags:
        raise KeyRecordError("has a syntax error")
    # h= (retired), n=, s=, t= and unknown tags are ignored (spec-06 §11.5).
    p = _strip_fws(tags["p"])
    if p == "":
        raise KeyRecordError("has been revoked")
    key_type = tags.get("k", "rsa")
    if key_type not in ("rsa", "ed25519"):
        raise KeyRecordError("algorithm mismatch")
    pub_bytes = _b64decode_strict(p)
    if not pub_bytes:
        raise KeyRecordError("has a syntax error")

    if key_type == "ed25519":
        # RFC 8463: p= is the raw 32-byte Ed25519 public key.
        if len(pub_bytes) != 32:
            raise KeyRecordError("has a syntax error")
        return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes), "ed25519"
    # RSA: DER-encoded SubjectPublicKeyInfo, which must hold an RSA key.
    try:
        key = serialization.load_der_public_key(pub_bytes)
    except (ValueError, TypeError):
        raise KeyRecordError("has a syntax error")
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyRecordError("has a syntax error")
    return key, "rsa"


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
    """Exact envelope-address match per spec "Check the Chain of Custody":
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
    """Validate §8.2/§11.4 Chain of Custody across consecutive signatures.

    For each adjacent pair (ascending i=), either the lower signature carries
    nd= (which MUST exactly match the higher signature's d=), or the higher
    signature's mf= domain MUST relaxed-match an rt= domain of the lower one.

    A §9.3 bridge -- an nd= signature after a real hop, made by a Forwarder to
    span the gap between the domain it received the message at and the domain
    it sends from -- has no mf=, so for it the value that MUST relaxed-match
    the lower hop's rt= is its d=: the key §9.3 requires it to be made with.
    """
    errors = []
    for k in range(1, len(sig_by_seq)):
        cur_val = _get_header_value(sig_by_seq[k])
        prev_val = _get_header_value(sig_by_seq[k - 1])
        cur_i = _extract_tag(cur_val, "i")
        prev_i = _extract_tag(prev_val, "i")
        prev_nd = _extract_tag(prev_val, "nd")
        if prev_nd:
            # draft-06 §11.4: nd= MUST exactly match the next sig's d=.
            cur_d = _extract_tag(cur_val, "d") or ""
            if prev_nd.lower() != cur_d.lower():
                errors.append(
                    f"DKIM2-Signature i={prev_i} MAIL nd= does not match"
                )
            continue
        cur_mf_b64 = _extract_tag(cur_val, "mf")
        prev_rt_raw = _extract_tag(prev_val, "rt")
        if not prev_rt_raw:
            errors.append(
                f"DKIM2-Signature i={prev_i} RCPT TO <> did not match"
            )
            continue
        prev_rts = [
            base64.b64decode(rt.strip()).decode("utf-8", errors="surrogateescape")
            for rt in prev_rt_raw.split(",") if rt.strip()
        ]

        cur_nd = _extract_tag(cur_val, "nd")
        if cur_nd:
            cur_d = _extract_tag(cur_val, "d") or ""
            if not any(_relaxed_domain_match(cur_d, _domain_from_addr(rt))
                       for rt in prev_rts):
                errors.append(
                    f"DKIM2-Signature i={cur_i} nd= hop d={cur_d} did not match RCPT TO"
                )
            continue

        if not cur_mf_b64:
            errors.append(
                f"DKIM2-Signature i={cur_i} MAIL FROM <> did not match"
            )
            continue
        cur_mf = base64.b64decode(cur_mf_b64).decode("utf-8", errors="surrogateescape")
        cur_mf_domain = _domain_from_addr(cur_mf)
        if not any(_relaxed_domain_match(cur_mf_domain, _domain_from_addr(rt))
                   for rt in prev_rts):
            errors.append(
                f"DKIM2-Signature i={cur_i} MAIL FROM {cur_mf} did not match"
            )
    return errors


def _strip_fws(s: str) -> str:
    """Remove folding whitespace from a tag value.

    Per spec-06 §2.12 folding whitespace may appear inside a base64 string or
    around the colons of an s= item, and MUST be ignored when the value is
    used.  Selectors, algorithm names and base64 never contain significant
    whitespace, so removing all of it is safe.
    """
    return s.translate(_FWS_TABLE)


_FWS_TABLE = {ord(c): None for c in " \t\r\n"}


# spec-06 §7 / §8 tag-list syntax, checked over the whole field (follow-up
# review F.1). FWS is any WSP, with each CRLF followed by WSP; written so it
# cannot be split ambiguously (no backtracking blow-up on a bad field).
_FWS_RE = r"[ \t]*(?:\r\n[ \t]+)*"
_X_TAG_CHAR = r"[\x21-\x3a\x3c-\x7e]"
_TAG_SPEC = re.compile(
    rf"{_FWS_RE}[A-Za-z][A-Za-z0-9_]*{_FWS_RE}={_FWS_RE}"
    rf"(?:{_X_TAG_CHAR}(?:{_FWS_RE}{_X_TAG_CHAR})*)?{_FWS_RE}")
_EMPTY_SPEC = re.compile(_FWS_RE)
# §3.5 selector (labels joined by '.'); §8.9 sig-name and §7.3 hash-name.
# No FWS inside either: "rsa- sha256" is not normalised to a known name.
_SELECTOR_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")
_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")


def _tag_list_ok(value: str) -> bool:
    """Every ';'-separated fragment is empty or a well-formed tag-spec.

    A junk fragment, a bad tag name or a NUL/DEL/8-bit byte in any value
    (known or unknown tag) makes the whole field a syntax error; it is never
    skipped so the rest can be verified."""
    return all(_EMPTY_SPEC.fullmatch(f) or _TAG_SPEC.fullmatch(f)
               for f in value.split(";"))


def _sig_syntax_ok(value: str) -> bool:
    """§8 tag-list plus §8.9 s= items: each exactly selector:algorithm:value.

    FWS is allowed (trimmed) around the ',' and ':'s and inside the base64
    value, but not inside the selector or algorithm name."""
    if not _tag_list_ok(value):
        return False
    s_tag = _extract_tag(value, "s")
    if s_tag is None:
        return True  # reported as a missing tag
    for item in s_tag.split(","):
        parts = [p.strip(_WSP) for p in item.split(":")]
        if (len(parts) != 3 or not _SELECTOR_RE.fullmatch(parts[0])
                or not _NAME_RE.fullmatch(parts[1])):
            return False
    return True


def _mi_syntax_ok(value: str) -> bool:
    """§7 tag-list plus §7.3 h= hash-sets: each exactly name:hash:hash, with
    no FWS inside the hash name and both digests present."""
    if not _tag_list_ok(value):
        return False
    h_tag = _extract_tag(value, "h")
    if h_tag is None:
        return True  # reported as a missing tag
    for item in h_tag.split(","):
        parts = [p.strip(_WSP) for p in item.split(":")]
        if (len(parts) != 3 or not _NAME_RE.fullmatch(parts[0])
                or not _strip_fws(parts[1]) or not _strip_fws(parts[2])):
            return False
    return True


def _sig_flags(sig_hdr: str) -> list[str]:
    """Return the f= flag list of a DKIM2-Signature header (draft-06 §8.10)."""
    f = _extract_tag(_get_header_value(sig_hdr), "f")
    return [x.strip() for x in f.split(",") if x.strip()] if f else []


def _flag_enforcement_errors(sig_by_seq: list[str], mi_headers: list[str]) -> list[str]:
    """Enforce the donotmodify/donotexplode flags (draft-06 §11.8).

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


def _malformed_recipe_error(m_val) -> str:
    """§11.2-style text for a Recipe that parses as JSON but cannot be applied."""
    return f"PERMERROR Message-Instance m={m_val} has a malformed Recipe"


def parse_hash_sets(h_tag: str) -> list[tuple[str, str, str]]:
    """Parse a spec-06 §7.3 h= value into (alg, header_hash, body_hash) triples.

    Hash names are lowercased: RFC 5234 makes ABNF quoted strings
    case-insensitive, so "SHA256" is a syntactically valid hash-name.

    Per spec-06 §2.12, folding whitespace may appear inside a base64 string
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


def _mi_duplicate_tag_error(mi_hdr: str) -> str | None:
    """spec-06 §7: tag identifiers are case insignificant and there MUST be
    only one of each kind, so `h=..; H=..` or `m=1; M=1` is a syntax error."""
    names = _tag_names(_get_header_value(mi_hdr))  # lowercased
    if len(set(names)) != len(names):
        m_val = _extract_tag(_get_header_value(mi_hdr), "m")
        return f"PERMERROR Message-Instance m={m_val} syntax error"
    return None


def verify_message_instance(mi_hdr: str, headers: list[bytes], body: bytes,
                            headers_only: bool = False) -> list[str]:
    """Verify the hashes in a Message-Instance header against the message.

    Returns a list of errors (empty = success).

    With headers_only set, the message being checked has no body -- as with the
    returned original in a DSN's text/rfc822-headers part (spec-06 §12.1.2) --
    so only the header hash is compared and body is ignored.
    """
    errors = []
    value = _get_header_value(mi_hdr)
    m_val = _extract_tag(value, "m")

    dup = _mi_duplicate_tag_error(mi_hdr)
    if dup:
        return [dup]

    # §11.2: a malformed r= payload is reported specifically, regardless of
    # what else is wrong with this Message-Instance header. Two distinct
    # failure kinds, kept distinct rather than both being called "invalid
    # JSON": a bad base64 r= value never even reaches JSON parsing -- §11.2
    # lists this as a plain syntax error -- while a JSON parse failure is
    # the more specific "contains invalid JSON" case.
    r_tag = _extract_tag(value, "r")
    if r_tag:
        # §2.12: FWS inside the value MUST be ignored when it is used. A list
        # manager's r= runs to several hundred bytes and arrives folded with
        # CRLF+HTAB; the strict decoder below rejects any whitespace, so strip
        # it first (found replaying real Mailman/Sympa output, 2026-10-04).
        r_bytes = _b64decode_strict(re.sub(r"\s+", "", r_tag))
        if r_bytes is None:
            errors.append(
                f"PERMERROR Message-Instance m={m_val} syntax error"
            )
        else:
            try:
                recipes = loads_recipe(r_bytes)
            except ValueError:
                # json.JSONDecodeError, and UnicodeDecodeError for a payload
                # that is not valid UTF-8 (a Perl producer writes Recipe
                # literals as raw octets; a Latin-1 or EUC-KR line makes the
                # whole JSON undecodable). Both are ValueErrors; catching only
                # the former let the latter escape as a traceback.
                errors.append(
                    f"PERMERROR Message-Instance m={m_val} contains invalid JSON"
                )
            else:
                # Valid JSON that is not a well-formed Recipe (§5: a "c"
                # that is not two integers, not 1 <= start <= end, or that
                # does not ascend past the previous "c"; a "b" that is not
                # base64; a literal carrying CR or LF) is a third, distinct
                # failure. This is the message-independent part; the
                # per-list upper bound is checked where the Recipe is
                # applied (full-chain undo) and reported under the same text.
                try:
                    validate_recipes(recipes)
                except MalformedRecipe:
                    errors.append(_malformed_recipe_error(m_val))

    h_tag = _extract_tag(value, "h")
    if not h_tag:
        return errors + ["Message-Instance: missing h= tag"]

    sets = parse_hash_sets(h_tag)
    if not sets:
        return errors + [f"Message-Instance: invalid h= format (got {h_tag!r})"]

    # spec-06 §7.3: an algorithm MUST NOT be present more than once.
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

        if headers_only:
            continue

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
    """spec-06 §8.9 duplicate/limit rules for one DKIM2-Signature s= tag.

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
        errors.append(f"PERMERROR DKIM2-Signature i={i_val} has more selectors than allowed")
    return errors


# Implemented signature algorithms (spec-06 §3) -> the k= key type they need.
SIG_ALGS = {"rsa-sha256": "rsa", "ed25519-sha256": "ed25519"}


def _blank_signature_values(sig_hdr: str) -> str:
    """The incomplete (signed) form of a DKIM2-Signature header: every s=
    item's signature value removed, everything else byte-for-byte."""
    colon = sig_hdr.find(":")
    parts = sig_hdr[colon + 1:].split(";")
    for idx, part in enumerate(parts):
        if "=" not in part:
            continue
        name, val = part.split("=", 1)
        if name.strip().lower() != "s":
            continue
        inner = val.strip()
        lead = val[:len(val) - len(val.lstrip())]
        trail = val[len(val.rstrip()):]
        blanked = ",".join(":".join(item.split(":", 2)[:2]) + ":"
                           for item in inner.split(","))
        parts[idx] = f"{name}={lead}{blanked}{trail}"
        break
    return sig_hdr[:colon + 1] + ";".join(parts)


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

    # draft-06 §8: i= m= t= d= s= MUST be present; plus either nd= or both
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

    # §8.4: sig-t-tag = 1*DIGIT. Checked even when the age check is skipped.
    if not _is_ascii_digits(t_val0):
        return [f"PERMERROR DKIM2-Signature i={i_val} syntax error"]

    # §7.3 SHOULD: n= nonce must not exceed 64 characters
    n_val = _extract_tag(value, "n")
    if n_val and len(n_val) > 64:
        return [f"DKIM2-Signature i={i_val}: n= nonce exceeds 64 characters ({len(n_val)})"]

    # §10.3 SHOULD: reject signatures more than 14 days old or in the future
    t_val = _extract_tag(value, "t")
    if t_val and not skip_timestamp_check:
        ts = int(t_val)  # 1*DIGIT (checked above); Python ints don't overflow
        now = int(time.time())
        if ts > now + 300:
            return [f"DKIM2-Signature i={i_val}: timestamp is in the future"]
        if now > ts + 14 * 24 * 3600:
            return [f"DKIM2-Signature i={i_val}: signature has expired (age > 14 days)"]

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
    # fold anywhere inside the item -- including between the Selector colon
    # and the algorithm token -- doesn't corrupt the Selector, the algorithm
    # name or the base64 signature.
    sig_items_raw = []
    sig_items = []
    for part in s_tag.split(","):
        fields = part.split(":", 2)
        if len(fields) != 3:
            return [f"DKIM2-Signature i={i_val}: invalid s= item format: {part!r}"]
        sig_items_raw.append(fields)
        sig_items.append([_strip_fws(f) for f in fields])

    # spec-06 §8.9: duplicate-selector and excess-selector checks must run
    # before any DNS lookup or crypto work.
    dup_errors = _check_signature_duplicates(sig_items, i_val)
    if dup_errors:
        return dup_errors

    # §3.4/§8.9: only rsa-sha256 and ed25519-sha256 (byte-for-byte; tag
    # values are case significant, §8) are implemented. Items naming any
    # other algorithm are ignored entirely -- no key lookup, no crypto. A
    # known item's value must be non-empty base64 (FWS removed), checked
    # here before any key lookup.
    if not any(alg in SIG_ALGS for _, alg, _ in sig_items):
        return [f"FAIL DKIM2-Signature i={i_val} has no signature with a "
                f"supported algorithm"]
    usable_items = []
    for selector, algorithm, sig_value_b64 in sig_items:
        if algorithm not in SIG_ALGS:
            continue
        sig_bytes = _b64decode_strict(sig_value_b64)
        if not sig_bytes:
            return [f"PERMERROR DKIM2-Signature i={i_val} syntax error"]
        usable_items.append((selector, algorithm, sig_bytes))

    # Build the incomplete signature (the signed form) by blanking each s=
    # item's signature value in place, leaving selector:algorithm: and every
    # other tag untouched. One pass over the header (linear in its length).
    incomplete_sig = _blank_signature_values(sig_hdr)

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

    # Spec "E" outcome rules (§11.5, §11.6). Fetch every implemented item's
    # key first: a record that is present but unusable makes the whole
    # signature a PERMERROR even if another item would verify (all items
    # MUST be checked; a revoked key is not one we may skip). An absent
    # record only skips its item.
    keyed = []
    first_absent = None
    for selector, algorithm, sig_bytes in usable_items:
        try:
            public_key, key_type = lookup_public_key(d_val, selector, dns_data)
        except KeyRecordError as e:
            return [f"PERMERROR DKIM2-Signature i={i_val} public key {selector} {e.what}"]
        except KeyError:
            if first_absent is None:
                first_absent = selector
            continue

        if SIG_ALGS[algorithm] != key_type:
            return [f"PERMERROR DKIM2-Signature i={i_val} public key "
                    f"{selector} algorithm mismatch"]

        # §3.2: RSA keys MUST be at least 1024 bits. A shorter key is a
        # present-but-unusable key: PERMERROR for the whole signature.
        if key_type == "rsa" and getattr(public_key, "key_size", 0) < 1024:
            return [f"PERMERROR DKIM2-Signature i={i_val} public key "
                    f"{selector} is shorter than 1024 bits"]
        keyed.append((selector, key_type, public_key, sig_bytes))

    if not keyed:
        return [f"PERMERROR DKIM2-Signature i={i_val} public key "
                f"{first_absent} does not exist"]

    # Verify every item that has a key; any failure is FAIL naming the
    # Selector (§11.6).
    failed = []
    for selector, key_type, public_key, sig_bytes in keyed:
        try:
            if key_type == "ed25519":
                public_key.verify(sig_bytes, digest)
            else:
                public_key.verify(
                    sig_bytes,
                    digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )
        except Exception:
            failed.append(selector)
    if failed:
        errors.append(f"FAIL DKIM2-Signature i={i_val} {failed[0]} incorrect signature")

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
    # A self-declared §11 PERMERROR is a permerror whatever its wording
    # ("... public key sel algorithm mismatch" is not a crypto failure).
    if e.startswith('permerror'):
        return 'permerror'
    if e.startswith('fail'):
        return 'fail'
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
                   rcpt_to: list[str] | None = None,
                   headers_only: bool = False,
                   allow_unsigned_mi: bool = False) -> "VerifyResult":
    """Verify all DKIM2 signatures in a message.

    If full_chain is True, walks backwards through MI versions, undoing
    recipes at each step and verifying that each MI's hashes match the
    reconstructed message state, and each DKIM2-Signature verifies against
    the MI/sig headers that existed at that point.

    If headers_only is True the message has no body, as with the returned
    original in a DSN's text/rfc822-headers part (spec-06 §12.1.2). Signatures
    and the chain are checked as usual, but of the Message-Instance content
    check only the top instance's header hash can be, so only that is --
    nothing further down the chain can be undone without a body to undo into,
    which is why headers_only overrides full_chain.

    If allow_unsigned_mi is True (outbound mode, used by the signer gate) a
    Message-Instance above the top DKIM2-Signature's m= is allowed: it is the
    instance the caller is about to sign.  It is still checked against the
    content and undone like any other; every signature must still verify.

    Returns a VerifyResult (ok=True on success).
    """
    raw = _to_bytes(source)
    headers, body = parse_message(raw)
    all_errors = []

    mi_headers = extract_mi_headers(headers)
    sig_headers = extract_sig_headers(headers)

    for h in mi_headers:
        if _extract_tag(_get_header_value(h), "m") is None:
            msg = "PERMERROR Message-Instance has a malformed m= tag"
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])
        msg = _mi_duplicate_tag_error(h)
        if msg:
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])

    # A DKIM2-Signature without an i= that is a positive integer cannot be
    # placed in the chain or keyed.  It is a PERMERROR, never silently
    # skipped: a signer gate counting "coverage" by m= must not be fooled by
    # a junk signature that names an m= but signs nothing.
    for h in sig_headers:
        if not _sig_has_valid_i(h):
            msg = "PERMERROR DKIM2-Signature has a missing or malformed i= tag"
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])

    # Every i= and m= is a chain number (1*DIGIT, at most 3 digits, 1..100,
    # and no more than MAX_CHAIN_LENGTH), before the gap loops below walk
    # 1..max.
    range_error = chain_range_error(mi_headers, sig_headers)
    if range_error:
        return VerifyResult(ok=False, status='permerror', failing_i=None,
                            domain=None, message=range_error, errors=[range_error])

    # spec-06 §7, §8: the whole field must be a well-formed tag-list, with
    # well-formed s= items and h= hash-sets (follow-up review F.1-F.3).
    for h in mi_headers:
        if not _mi_syntax_ok(_get_header_value(h)):
            msg = (f"PERMERROR Message-Instance "
                   f"m={_extract_tag(_get_header_value(h), 'm')} syntax error")
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])
    for h in sig_headers:
        if not _sig_syntax_ok(_get_header_value(h)):
            i_val = _extract_tag(_get_header_value(h), "i")
            msg = f"PERMERROR DKIM2-Signature i={i_val} syntax error"
            return VerifyResult(ok=False, status='permerror',
                                failing_i=_get_seq_from_sig(h),
                                domain=None, message=msg, errors=[msg])

    seen_m = set()
    for h in mi_headers:
        mv = _get_version_from_mi(h)
        if mv in seen_m:
            msg = f"duplicate Message-Instance m={mv}"
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])
        seen_m.add(mv)

    # spec-06 §7.1: Message-Instance m= and DKIM2-Signature i= values must be
    # contiguous from 1.  Structural, so checked before any crypto.  (A
    # missing top instance in outbound mode is not a gap: the caller adds it.)
    for label, name, vals in (
            ("Message-Instance", "m", seen_m),
            ("DKIM2-Signature", "i",
             {_get_seq_from_sig(h) for h in sig_headers})):
        for n in range(1, (max(vals) if vals else 0) + 1):
            if n not in vals:
                msg = f"PERMERROR missing {label} {name}={n}"
                return VerifyResult(ok=False, status='permerror',
                                    failing_i=None, domain=None,
                                    message=msg, errors=[msg])

    mi_only = allow_unsigned_mi and not sig_headers and bool(mi_headers)
    if not sig_headers and not mi_only:
        return VerifyResult(ok=False, status='none', failing_i=None, domain=None,
                            message='no DKIM2-Signature headers',
                            errors=['no DKIM2-Signature headers'])
    if not mi_headers:
        return VerifyResult(ok=False, status='permerror', failing_i=None, domain=None,
                            message='no Message-Instance headers',
                            errors=['no Message-Instance headers'])

    max_mi_version = max(_get_version_from_mi(h) for h in mi_headers)
    top_sig = None
    if not mi_only:
        # Spec-01 §9/§10: top DKIM2-Signature must cover the topmost MI
        max_mi_version = max(_get_version_from_mi(h) for h in mi_headers)
        top_sig = max(sig_headers, key=_get_seq_from_sig)
        top_sig_value = _get_header_value(top_sig)
        top_sig_seq = _extract_tag(top_sig_value, "i")
        top_sig_m = _extract_tag(top_sig_value, "m")
        top_sig_m_int = int(top_sig_m) if top_sig_m else 0
        if top_sig_m_int != max_mi_version and not (
                allow_unsigned_mi and top_sig_m_int < max_mi_version):
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
        if _extract_tag(top_sig_value, "nd") and not allow_unsigned_mi:
            top_i = _get_seq_from_sig(top_sig)
            msg = f"DKIM2-Signature i={top_sig_seq} unexpected nd= tag"
            return VerifyResult(ok=False, status='permerror', failing_i=top_i,
                                domain=_extract_tag(top_sig_value, 'd') or '',
                                message=msg, errors=[msg])

    # Envelope MAIL FROM / RCPT TO checks (spec §"Check the Chain of Custody"):
    # exact match against the top signature's declared mf=/rt=, domains
    # lowercased, local-part case-sensitive. Applies regardless of
    # full_chain/simple mode. rt= MAY carry extra recipients beyond what was
    # actually delivered; every delivered RCPT TO must be present in the set.
    if (mail_from is not None or rcpt_to) and top_sig is not None:
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

    if not full_chain or headers_only:
        # Simple mode: verify highest MI against current message, verify all sigs
        if headers_only:
            top_mi = max(mi_headers, key=_get_version_from_mi)
            all_errors.extend(verify_message_instance(
                top_mi, content_headers, b"", headers_only=True))
        else:
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
    # spec-06 §5: once an instance's body Recipe is null the previous body
    # cannot be recreated, so every lower instance is checked on its header
    # hash only (header Recipes are mandatory, so header history still is).
    body_unchecked_below = None

    for version in versions:
        mi_hdr = mi_by_version[version]

        if verbose:
            print(f"Verifying MI v={version}...", file=sys.stderr)

        # Verify this MI's hashes against the current message state
        errs = verify_message_instance(
            mi_hdr, current_content_headers, current_body,
            headers_only=body_unchecked_below is not None)
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

        # If there's a lower version, undo Recipes to reconstruct previous state
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
                # draft-06 §5.1: a present "h" that is JSON null is a syntax
                # error (distinct from an absent "h", which means headers
                # were unchanged); mirrors dkim2undo.py's rejection.
                if "h" in recipes and recipes["h"] is None:
                    all_errors.append(
                        f"v={version}: header recipe is null: not permitted"
                    )
                # A Recipe that cannot be applied (§5: a "c" range past the
                # items present, or any structural fault the hash check
                # above already named) is the §11.2 malformed-Recipe
                # PERMERROR; verify_message_instance() may have reported
                # the structural part already, so don't list it twice. The
                # reconstruction stops here: the lower instances cannot be
                # checked against a state we could not rebuild.
                def _malformed(e):
                    msg = _malformed_recipe_error(version)
                    if msg not in all_errors:
                        all_errors.append(msg)
                    if verbose:
                        print(f"  Malformed Recipe in m={version}: {e}",
                              file=sys.stderr)

                h_recipes = recipes.get("h")
                if h_recipes and isinstance(h_recipes, dict) and len(h_recipes) > 0:
                    try:
                        current_content_headers = reconstruct_headers(
                            current_content_headers, h_recipes
                        )
                        if verbose:
                            print(f"  Undid header recipes for v={version}",
                                  file=sys.stderr)
                    except MalformedRecipe as e:
                        _malformed(e)
                        break
                    except ValueError as e:
                        all_errors.append(
                            f"v={version}: failed to undo header recipes: {e}"
                        )

                b_recipes = recipes.get("b")
                if "b" in recipes and b_recipes is None:
                    # Null body Recipe: header history is still walked.
                    if body_unchecked_below is None:
                        body_unchecked_below = version
                        if verbose:
                            print(f"  Body not checked below m={version}: "
                                  f"null body Recipe", file=sys.stderr)
                elif (b_recipes and isinstance(b_recipes, list)
                      and body_unchecked_below is None):
                    try:
                        current_body = reconstruct_body(
                            current_body, b_recipes
                        )
                        if verbose:
                            print(f"  Undid body recipes for v={version}",
                                  file=sys.stderr)
                    except MalformedRecipe as e:
                        _malformed(e)
                        break
                    except ValueError as e:
                        all_errors.append(
                            f"v={version}: failed to undo body recipes: {e}"
                        )

    top_sig_i = _get_seq_from_sig(top_sig) if top_sig else 0
    top_domain = (_extract_tag(_get_header_value(top_sig), 'd') or '') if top_sig else ''
    result = _make_result(all_errors, top_sig_i, top_domain)
    if result.ok and body_unchecked_below is not None:
        result.message += (f" (body not checked below m={body_unchecked_below}: "
                           f"null body Recipe)")
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Verify DKIM2 signatures (draft-ietf-dkim-dkim2-spec-06)")
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
