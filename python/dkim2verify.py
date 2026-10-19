#!/usr/bin/env python3
"""
DKIM2 verifier - draft-ietf-dkim-dkim2-spec-07

Takes a signed email and verifies its DKIM2 signatures using public keys
from a dns.json file or DNS TXT records (dkim2dns; looked up in the
background as soon as the header fields are known).

The chain is checked by the planned walk (dkim2plan): every instance's
header and body hashes come from one pass over the message, without
rebuilding any previous version.  --undo-walk rebuilds each version from
the Recipes instead (dkim2undo); the two give the same verdicts.

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
    _get_mi_from_sig,
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
from dkim2plan import BodyPass, plan_chain, recipe_actions
from dkim2dns import DNSTempError, LiveDNS
from dkim2domain import (
    addr_domain, from_is_authentic, relaxed_match, signing_domain,
)


# ---------------------------------------------------------------------------
# DNS key lookup
# ---------------------------------------------------------------------------

def load_dns_json(path: str) -> dict:
    """Load a dns.json file mapping domain -> selector -> records."""
    return json.loads(Path(path).read_text())


class KeyRecordError(Exception):
    """A key record that exists but MUST NOT be used (-07 §14.5).

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
# or 8-bit byte anywhere makes the record a syntax error (-07 §14.5).
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


def lookup_public_key(domain: str, selector: str, dns_data):
    """Look up and validate a public key.

    dns_data is either a dns.json dict or a live key source (dkim2dns
    LiveDNS / MessageKeys: anything with txt_records(name)).

    dns.json maps domain -> "<selector>._domainkey" -> list of [type, value]
    records. A TXT value may be a string, or a list of strings: the
    character-strings of one RR, concatenated with nothing between them
    (dkim2-dns-00 §3.4.2.2). More than one TXT record is an error.

    Returns (key_object, key_type) with key_type "rsa" or "ed25519".
    Raises KeyError if there is no record (absent key), KeyRecordError if
    the record exists but MUST NOT be used, DNSTempError if a live lookup
    could not be completed.
    """
    if not isinstance(dns_data, dict):
        txts = dns_data.txt_records(f"{selector}._domainkey.{domain}")
        if len(txts) > 1:
            raise KeyRecordError("has multiple records")
        return _parse_key_txt(txts[0])

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
    return _parse_key_txt(txts[0] if isinstance(txts[0], str) else "".join(txts[0]))


def _parse_key_txt(txt: str):
    """Validate one key record's text: (key_object, key_type)."""
    tags = parse_key_record(txt)
    if tags is None or "p" not in tags:
        raise KeyRecordError("has a syntax error")
    # h= (retired), n=, s=, t= and unknown tags are ignored (-07 §14.5).
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
    """-07 §10.5/§10.6: every present mf= and rt= entry MUST be a bracketed
    RFC5321 path (matches <...>, incl. <>). nd= hops carry no mf/rt and are
    skipped (checked implicitly since their mf=/rt= tags are absent)."""
    errs = []
    for sig_hdr in sig_headers:
        value = _get_header_value(sig_hdr)
        i_val = _extract_tag(value, "i")
        for tag in ("mf", "rt"):
            raw = _extract_tag(value, tag)
            if not raw:
                continue
            for part in raw.split(","):
                part = part.strip()
                if not part:
                    continue
                dec = base64.b64decode(part).decode("utf-8", errors="surrogateescape")
                if not (dec.startswith("<") and dec.endswith(">")):
                    # -07 §10.5/§10.6: not a bracketed RFC5321 path.
                    errs.append(f"PERMERROR: DKIM2-Signature i={i_val} syntax error")
    return errs


def _decode_path(b64val: str) -> str:
    """A decoded mf= or rt= entry ('' if it is not base64 at all)."""
    try:
        return base64.b64decode(_strip_fws(b64val)).decode(
            "utf-8", errors="surrogateescape")
    except (binascii.Error, ValueError):
        return ""


def _rt_domains(sig_value: str) -> list[str]:
    """The A-label domains of a signature's rt= addresses (literals left
    out: a domain literal never relaxed-matches anything)."""
    raw = _extract_tag(sig_value, "rt") or ""
    out = []
    for part in raw.split(","):
        if part.strip():
            dom = addr_domain(_decode_path(part))
            if dom is not None:
                out.append(dom)
    return out


def _chain_custody_errors(sig_by_seq: list[str]) -> list[str]:
    """draft -07 §7.1 item 1, §14.4: the Chain of Custody, as the contract's
    C4 steps.  Every failure is a PERMERROR.

    For every signature S with a non-null mf= and no nd=, the mf= domain
    must relaxed-match S's d=.  Then for each S above i=1, with P the
    signature below it:

    1. P has nd=: S's d= must equal it (ignoring case); nothing else is
       checked for S.
    2. S has nd= (a §12.3 bridge, which has no mf=) or S's mf= is <>: some
       rt= domain of P must relaxed-match S's d=.
    3. Otherwise S's mf= domain must relaxed-match some rt= domain of P.

    Relaxed matching strips labels from the left of its first argument only
    (§7.2), and a domain literal never matches.
    """
    errors = []
    for k, sig in enumerate(sig_by_seq):
        val = _get_header_value(sig)
        i_val = _extract_tag(val, "i")
        raw_d = _extract_tag(val, "d") or ""
        d = signing_domain(raw_d)
        nd = _extract_tag(val, "nd")
        mf_raw = _extract_tag(val, "mf")
        mf = _decode_path(mf_raw) if mf_raw else None
        null_mf = mf is not None and mf.strip() == "<>"

        if k > 0:
            prev = _get_header_value(sig_by_seq[k - 1])
            prev_i = _extract_tag(prev, "i")
            prev_nd = _extract_tag(prev, "nd")
            if prev_nd:
                if prev_nd.strip().lower() != raw_d.strip().lower():
                    errors.append(
                        f"PERMERROR: DKIM2-Signature i={prev_i} nd= does not match")
            elif nd or null_mf:
                if not any(relaxed_match(rt, d) for rt in _rt_domains(prev)):
                    errors.append(
                        f"PERMERROR: DKIM2-Signature i={i_val} d= does not "
                        f"match the rt= of i={prev_i}")
            elif mf is not None:
                mf_d = addr_domain(mf)
                if mf_d is None or not any(relaxed_match(mf_d, rt)
                                           for rt in _rt_domains(prev)):
                    errors.append(
                        f"PERMERROR: DKIM2-Signature i={i_val} mf= does not "
                        f"match the rt= of i={prev_i}")

        if mf is not None and not null_mf and not nd:
            mf_d = addr_domain(mf)
            if mf_d is None or not relaxed_match(mf_d, d):
                errors.append(
                    f"PERMERROR: DKIM2-Signature i={i_val} MAIL FROM and d= "
                    f"do not match")
    return errors


def _from_fields(headers: list[bytes]) -> list[bytes]:
    return [h for h in headers if _header_name(h) == b"from"]


def _from_authentic_errors(content_headers: list[bytes],
                           mi_by_version: dict[int, str],
                           sig_by_seq: list[str]) -> list[str]:
    """draft -07 §11, §14.8: the From in effect when each signature was made
    must be Authentic for it (contract C5, Ruling 19).

    State k is the header fields as they were when Message-Instance m=k was
    the highest; state k-1 is state k with m=k's header Recipe undone.  The
    pairs checked are (From at state m(i=1), signature i=1) and, for each
    i >= 2 where some instance k with m(i-1) < k <= m(i) has a "from" key in
    its header Recipe, (From at state m(i), signature i).  A From replaced
    before any signature covered it (an unsigned ingress m=1 that a list
    rewrote in m=2 before signing i=1) is never checked, nor are instances
    above the top signature's m= (the signer checks those itself).  If a
    header Recipe cannot be undone the walk stops there: that is reported as
    invalid JSON already, and states below it are not checked.
    """
    sigs = []
    for h in sig_by_seq:
        val = _get_header_value(h)
        sigs.append((_get_seq_from_sig(h), _get_mi_from_sig(h) or 0,
                     _extract_tag(val, "d") or ""))
    sigs.sort()

    # Walk down from the top instance, keeping each state and whether that
    # instance's header Recipe replaced From.
    states: dict[int, list[bytes]] = {}
    changes_from: set[int] = set()
    headers = list(content_headers)
    for version in sorted(mi_by_version, reverse=True):
        states[version] = headers
        if version == 1:
            break
        try:
            recipes = decode_recipes(mi_by_version[version])
        except (ValueError, TypeError):
            break
        h = recipes.get("h") if isinstance(recipes, dict) else None
        if not isinstance(h, dict) or not h:
            continue
        if any(isinstance(k, str) and k.lower() == "from" for k in h):
            changes_from.add(version)
        try:
            headers = reconstruct_headers(headers, h)
        except ValueError:
            break

    errors: list[str] = []
    prev_m = None
    for i_val, m_val, d in sigs:
        if i_val == 1:
            due = True
        else:
            due = prev_m is not None and any(prev_m < k <= m_val for k in changes_from)
        prev_m = m_val
        if not due or m_val not in states:
            continue
        if not from_is_authentic(_from_fields(states[m_val]), d):
            msg = f"PERMERROR: DKIM2-Signature i={i_val} matching From is not authentic"
            if msg not in errors:
                errors.append(msg)
    return errors


def _strip_fws(s: str) -> str:
    """Remove folding whitespace from a tag value.

    Per -07 §2.12 folding whitespace may appear inside a base64 string or
    around the colons of an s= item, and MUST be ignored when the value is
    used.  Selectors, algorithm names and base64 never contain significant
    whitespace, so removing all of it is safe.
    """
    return s.translate(_FWS_TABLE)


_FWS_TABLE = {ord(c): None for c in " \t\r\n"}


# -07 §8 tag-list syntax, checked over the whole field (follow-up
# review F.1). FWS is any WSP, with each CRLF followed by WSP; written so it
# cannot be split ambiguously (no backtracking blow-up on a bad field).
_FWS_RE = r"[ \t]*(?:\r\n[ \t]+)*"
_X_TAG_CHAR = r"[\x21-\x3a\x3c-\x7e]"
_TAG_SPEC = re.compile(
    rf"{_FWS_RE}[A-Za-z][A-Za-z0-9_]*{_FWS_RE}={_FWS_RE}"
    rf"(?:{_X_TAG_CHAR}(?:{_FWS_RE}{_X_TAG_CHAR})*)?{_FWS_RE}")
_EMPTY_SPEC = re.compile(_FWS_RE)
# §3.6 selector (labels joined by '.'); §10.9 sig-name and §9.3 hash-name.
# No FWS inside either: "rsa- sha256" is not normalised to a known name.
_SELECTOR_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")
_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")


def _tag_list_ok(value: str) -> bool:
    """draft -07 §8 tag-list: tag-specs separated by ';', with an optional
    ';' after the last one.  So every fragment but a final one must be a
    well-formed tag-spec: an empty fragment (";;", or a leading ';') is a
    syntax error, as is a junk fragment, a bad tag name or a NUL/DEL/8-bit
    byte in any value (known or unknown tag).  The field is never skipped so
    the rest can be verified."""
    if _EMPTY_SPEC.fullmatch(value):
        return True     # no tags at all: reported as missing tags
    frags = value.split(";")
    if len(frags) > 1 and _EMPTY_SPEC.fullmatch(frags[-1]):
        frags.pop()
    return all(_TAG_SPEC.fullmatch(f) for f in frags)


def _sig_syntax_ok(value: str) -> bool:
    """§8 tag-list plus §10.9 s= items: each exactly selector:algorithm:value.

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
    """§8 tag-list plus §9.3 h= hash-sets: each exactly name:hash:hash, with
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
    """Return the f= flag list of a DKIM2-Signature header (-07 §10.10).

    No flag is enforced by the verifier: -07 removed donotmodify and
    donotexplode, and "exploded" is information for the receiver."""
    f = _extract_tag(_get_header_value(sig_hdr), "f")
    return [x.strip() for x in f.split(",") if x.strip()] if f else []


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
    """§14.2 text for a Recipe that parses as JSON but cannot be applied:
    it breaks the §5 schema."""
    return f"PERMERROR: Message-Instance m={m_val} contains invalid JSON"


def parse_hash_sets(h_tag: str) -> list[tuple[str, str, str]]:
    """Parse a -07 §9.3 h= value into (alg, header_hash, body_hash) triples.

    Hash names are lowercased: RFC 5234 makes ABNF quoted strings
    case-insensitive, so "SHA256" is a syntactically valid hash-name.

    Per -07 §2.12, folding whitespace may appear inside a base64 string
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
    """-07 §8: tag identifiers are case insignificant and there MUST be
    only one of each kind, so `h=..; H=..` or `m=1; M=1` is a syntax error."""
    names = _tag_names(_get_header_value(mi_hdr))  # lowercased
    if len(set(names)) != len(names):
        m_val = _extract_tag(_get_header_value(mi_hdr), "m")
        return f"PERMERROR: Message-Instance m={m_val} syntax error"
    return None


def verify_message_instance(mi_hdr: str, headers: list[bytes], body: bytes,
                            headers_only: bool = False) -> list[str]:
    """Verify the hashes in a Message-Instance header against the message.

    Returns a list of errors (empty = success).

    With headers_only set, the message being checked has no body -- as with the
    returned original in a DSN's text/rfc822-headers part (-07 §16.3) --
    so only the header hash is compared and body is ignored.
    """
    return check_message_instance(
        mi_hdr, lambda alg: compute_header_hash(headers, alg),
        lambda alg: compute_body_hash(body, alg), headers_only)


def _recipe_field_errors(value: str, m_val) -> list[str]:
    """The §14.2 errors of a Message-Instance's r= on its own: base64 that
    does not decode ("syntax error"), JSON that does not parse or breaks the
    §5 schema ("contains invalid JSON").  Message-independent: a Recipe that
    does not fit the message is found where it is applied."""
    errors = []
    r_tag = _extract_tag(value, "r")
    if r_tag:
        # §2.12: FWS inside the value MUST be ignored when it is used. A list
        # manager's r= runs to several hundred bytes and arrives folded with
        # CRLF+HTAB; the strict decoder below rejects any whitespace, so strip
        # it first (found replaying real Mailman/Sympa output, 2026-10-04).
        r_bytes = _b64decode_strict(re.sub(r"\s+", "", r_tag))
        if r_bytes is None:
            errors.append(
                f"PERMERROR: Message-Instance m={m_val} syntax error"
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
                errors.append(_malformed_recipe_error(m_val))
            else:
                # Valid JSON that breaks the §5 schema (a step without
                # exactly one of "c"/"d"/"u"; a "c" that is not two
                # integers, not 1 <= start <= end, or that does not ascend
                # past the previous "c"; a "u" that is not canonical base64;
                # a literal carrying CR or LF; "h": {}) is invalid JSON too.
                # This is the message-independent part; the per-list upper
                # bound is checked where the Recipe is applied (full-chain
                # undo) and reported under the same text.
                try:
                    validate_recipes(recipes)
                except MalformedRecipe:
                    errors.append(_malformed_recipe_error(m_val))
    return errors


def _recipe_structure_errors(mi_headers: list[str]) -> list[str]:
    """Contract C9: every Message-Instance's r= checked on its own, highest
    m= first, before any §14.3 check -- not only those the chain walk
    reaches."""
    errors = []
    for mi_hdr in sorted(mi_headers, key=_get_version_from_mi, reverse=True):
        value = _get_header_value(mi_hdr)
        if _mi_duplicate_tag_error(mi_hdr):
            continue
        for e in _recipe_field_errors(value, _extract_tag(value, "m")):
            if e not in errors:
                errors.append(e)
    return errors


def check_message_instance(mi_hdr: str, header_hash, body_hash,
                           headers_only: bool = False) -> list[str]:
    """verify_message_instance() with the message's hashes supplied by
    header_hash(alg) and body_hash(alg) (the planned walk has no message
    to give it)."""
    errors = []
    value = _get_header_value(mi_hdr)
    m_val = _extract_tag(value, "m")

    dup = _mi_duplicate_tag_error(mi_hdr)
    if dup:
        return [dup]

    # §14.2: a malformed r= payload is reported specifically, regardless of
    # what else is wrong with this Message-Instance header. Two distinct
    # failure kinds, kept distinct rather than both being called "invalid
    # JSON": a bad base64 r= value never even reaches JSON parsing -- §14.2
    # lists this as a plain syntax error -- while a JSON parse failure is
    # the more specific "contains invalid JSON" case.
    errors.extend(_recipe_field_errors(value, m_val))

    h_tag = _extract_tag(value, "h")
    if not h_tag:
        return errors + [f"PERMERROR: Message-Instance m={m_val} tag=h missing"]

    sets = parse_hash_sets(h_tag)
    if not sets:
        return errors + [f"PERMERROR: Message-Instance m={m_val} syntax error"]

    # -07 §9.3: an algorithm MUST NOT be present more than once.
    seen = set()
    for alg, _, _ in sets:
        if alg in seen:
            return errors + [f"PERMERROR: Message-Instance m={m_val} has a duplicate hash algorithm"]
        seen.add(alg)

    # §3.5: ignore hash-sets naming algorithms we do not implement, but an MI
    # with no implemented hash-set cannot be verified and must fail closed.
    usable = [s for s in sets if s[0] in HASH_ALGS]
    if not usable:
        return errors + [f"PERMERROR: Message-Instance m={m_val} has no supported "
                         f"hash algorithm"]

    # All implemented hash-sets must pass (mirrors §14.6 for signatures). A
    # malformed base64 value in one hash-set is itself a PERMERROR (§14.2:
    # verifiers MUST meticulously validate format and values); it does not
    # abort the whole MI check, mirroring the non-short-circuit "all usable
    # hash-sets are checked" behaviour of a hash mismatch below.
    for alg, h_val, b_val in usable:
        h_actual = _b64decode_strict(h_val)
        if h_actual is None:
            errors.append(f"PERMERROR: Message-Instance m={m_val} syntax error")
        else:
            expected = header_hash(alg)
            if expected != h_actual:
                errors.append(
                    f"FAIL: Message-Instance m={m_val} header hash {alg} mismatch")

        if headers_only:
            continue

        b_actual = _b64decode_strict(b_val)
        if b_actual is None:
            errors.append(f"PERMERROR: Message-Instance m={m_val} syntax error")
        else:
            expected = body_hash(alg)
            if expected != b_actual:
                errors.append(
                    f"FAIL: Message-Instance m={m_val} body hash {alg} mismatch")

    return errors


def _check_signature_duplicates(sig_items, i_val) -> list[str]:
    """-07 §10.9 duplicate/limit rules for one DKIM2-Signature s= tag.

    A Selector MUST NOT appear more than once. The same signing algorithm may
    appear at most twice, and only with distinct Selectors. Selector matching is
    case-insensitive (a Selector is a Domain, §3.6).
    """
    errors = []
    selectors = [sel.lower() for sel, _, _ in sig_items]
    if len(set(selectors)) != len(selectors):
        errors.append(f"PERMERROR: DKIM2-Signature i={i_val} has a duplicate selector")
    counts = {}
    for _, alg, _ in sig_items:
        counts[alg.lower()] = counts.get(alg.lower(), 0) + 1
    if any(n > 2 for n in counts.values()):
        errors.append(f"PERMERROR: DKIM2-Signature i={i_val} has more selectors than allowed")
    return errors


# -07 §14.3 timestamp limits, in seconds.
MAX_AGE = 14 * 24 * 3600
MAX_FUTURE = 24 * 3600

# Implemented signature algorithms (-07 §3; MLDSA44-Ed25519-SHA512, §3.4, is
# not implemented yet and is disregarded like any unknown algorithm, §3.5) -> the k= key type they need.
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
        dns_data: DNS records dict from dns.json, or a live key source
        skip_timestamp_check: if True, skip the §14.3 timestamp checks

    Returns a list of errors (empty = success).
    """
    errors = []
    value = _get_header_value(sig_hdr)

    # §8: a tag-list with a duplicate tag-name is invalid.
    seen = _tag_names(value)
    dups = sorted({n for n in seen if seen.count(n) > 1})
    if dups:
        return [f"PERMERROR: DKIM2-Signature i={_extract_tag(value, 'i')} syntax error"]

    # Extract required tags
    i_val = _extract_tag(value, "i")
    m_val = _extract_tag(value, "m")
    t_val0 = _extract_tag(value, "t")
    d_val = _extract_tag(value, "d")
    s_tag = _extract_tag(value, "s")
    nd_val = _extract_tag(value, "nd")
    mf_val = _extract_tag(value, "mf")
    rt_val = _extract_tag(value, "rt")

    # -07 §10: i= m= t= d= s= MUST be present; plus either nd= or both
    # mf= and rt= (and nd= excludes mf=/rt=).
    if not all([i_val, m_val, t_val0, d_val, s_tag]):
        for tag_name, tag_val in (
            ("i", i_val), ("m", m_val), ("t", t_val0), ("d", d_val), ("s", s_tag),
        ):
            if not tag_val:
                return [f"PERMERROR: DKIM2-Signature i={i_val or ''} tag={tag_name} missing"]
    # -07 §10: nd= excludes mf= and rt=; without nd= both are required.
    if nd_val and (mf_val or rt_val):
        return [f"PERMERROR: DKIM2-Signature i={i_val} "
                f"tag={'mf' if mf_val else 'rt'} was unexpected"]
    if not nd_val and not (mf_val and rt_val):
        return [f"PERMERROR: DKIM2-Signature i={i_val} "
                f"tag={'rt' if mf_val else 'mf'} missing"]

    # §10.4: sig-t-tag = 1*DIGIT. Checked even when the age check is skipped.
    if not _is_ascii_digits(t_val0):
        return [f"PERMERROR: DKIM2-Signature i={i_val} syntax error"]

    # §10.3 SHOULD: n= nonce must not exceed 64 characters
    n_val = _extract_tag(value, "n")
    if n_val and len(n_val) > 64:
        return [f"PERMERROR: DKIM2-Signature i={i_val} n= nonce exceeds 64 "
                f"characters ({len(n_val)})"]

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
            return [f"PERMERROR: DKIM2-Signature i={i_val} syntax error"]
        sig_items_raw.append(fields)
        sig_items.append([_strip_fws(f) for f in fields])

    # -07 §10.9: duplicate-selector and excess-selector checks must run
    # before any DNS lookup or crypto work.
    dup_errors = _check_signature_duplicates(sig_items, i_val)
    if dup_errors:
        return dup_errors

    # §3.5/§10.9: only rsa-sha256 and ed25519-sha256 (byte-for-byte; tag
    # values are case significant, §8) are implemented. Items naming any
    # other algorithm are ignored entirely -- no key lookup, no crypto. A
    # known item's value must be non-empty base64 (FWS removed), checked
    # here before any key lookup.
    usable_items = []
    for selector, algorithm, sig_value_b64 in sig_items:
        if algorithm not in SIG_ALGS:
            continue
        sig_bytes = _b64decode_strict(sig_value_b64)
        if not sig_bytes:
            return [f"PERMERROR: DKIM2-Signature i={i_val} syntax error"]
        usable_items.append((selector, algorithm, sig_bytes))

    # -07 §14.3: not Validly Signed if t= is more than 14 days before now,
    # or more than one day after it.  After every §14.2 check of this field
    # and before any key lookup (contract C9: §14 section order).
    t_val = _extract_tag(value, "t")
    if t_val and not skip_timestamp_check:
        ts = int(t_val)  # 1*DIGIT (checked above); Python ints don't overflow
        now = int(time.time())
        if ts > now + MAX_FUTURE:
            return [f"PERMERROR: DKIM2-Signature i={i_val} signature is from the future"]
        if now > ts + MAX_AGE:
            return [f"PERMERROR: DKIM2-Signature i={i_val} signature expired"]

    # A local check (contract C6), ranked with the §14.5 key errors.
    if not usable_items:
        return [f"PERMERROR: DKIM2-Signature i={i_val} has no signature with a "
                f"supported algorithm"]

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

    # Spec "E" outcome rules (§14.5, §14.6). Fetch every implemented item's
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
            return [f"PERMERROR: DKIM2-Signature i={i_val} public key {selector} {e.what}"]
        except DNSTempError:
            return [f"TEMPERROR: DKIM2-Signature i={i_val} public key {selector} "
                    f"could not be fetched"]
        except KeyError:
            if first_absent is None:
                first_absent = selector
            continue

        if SIG_ALGS[algorithm] != key_type:
            return [f"PERMERROR: DKIM2-Signature i={i_val} public key "
                    f"{selector} algorithm mismatch"]

        # §3.2: RSA keys MUST be at least 1024 bits. A shorter key is a
        # present-but-unusable key: PERMERROR for the whole signature.
        if key_type == "rsa" and getattr(public_key, "key_size", 0) < 1024:
            return [f"PERMERROR: DKIM2-Signature i={i_val} public key "
                    f"{selector} is shorter than 1024 bits"]
        keyed.append((selector, key_type, public_key, sig_bytes))

    if not keyed:
        return [f"PERMERROR: DKIM2-Signature i={i_val} public key "
                f"{first_absent} does not exist"]

    # Verify every item that has a key; any failure is FAIL naming the
    # Selector (-07 §14.6): "selector <s1> incorrect signature" when every
    # checkable item failed, else "signature <s1> signature <s2> failed"
    # naming one that passed and one that failed.
    failed, passed = [], []
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
        else:
            passed.append(selector)
    if failed and passed:
        errors.append(f"FAIL: DKIM2-Signature i={i_val} signature {passed[0]} "
                      f"signature {failed[0]} failed")
    elif failed:
        errors.append(f"FAIL: DKIM2-Signature i={i_val} selector {failed[0]} "
                      f"incorrect signature")

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
    """The result status for collected errors: the state the first error
    declares (-07 §14.1, every error is "<STATE>: <text>")."""
    if not errors:
        return 'pass'
    e = errors[0]
    if e.startswith('TEMPERROR:'):
        return 'temperror'
    if e.startswith('FAIL:'):
        return 'fail'
    return 'permerror'


def _extract_failing_i(errors: list[str]) -> int | None:
    """Extract the first i= value mentioned in any error string."""
    for err in errors:
        m = re.search(r'\bi=(\d+)\b', err)
        if m:
            return int(m.group(1))
    return None


# Contract C9: the -07 §14 section each error string belongs to.  Anything
# not named here (syntax, missing, duplicate, "is not signed", Recipe
# errors, local limits) is §14.2, header field validity.
_C9_SECTIONS = (
    (3, re.compile(r" signature (?:expired|is from the future)$")),
    (4, re.compile(r" unexpected nd= tag| nd= does not match$| does not match the rt= of i="
                   r"| MAIL FROM and d= do not match$| (?:MAIL FROM|RCPT TO) .* did not match$")),
    (5, re.compile(r"^TEMPERROR: | public key | has no signature with a supported algorithm")),
    (6, re.compile(r"^FAIL: DKIM2-Signature ")),
    (7, re.compile(r"^FAIL: Message-Instance ")),
    (8, re.compile(r" matching From is not authentic$")),
)
_C9_BY_NUMBER = {3, 5, 6, 8}


def _c9_key(err: str, walk_errors=frozenset()):
    """Sort key for contract C9: §14 section order; within §14.3, §14.5,
    §14.6 and §14.8 (checks made per signature) the lowest i= first.  The
    other sections keep the order their checks found them in: §14.2 as the
    header fields are read, §14.4 as C4 walks the chain (unexpected nd=,
    the envelope, then each signature up from i=1), §14.7 top down (a lower
    instance is rebuilt from the one above it).  A Recipe that does not fit
    the message (in `walk_errors`) is found by that walk, and ranks there,
    after the hash checks of the instances above it."""
    if err in walk_errors:
        return (7, 0)
    for section, rx in _C9_SECTIONS:
        if rx.search(err):
            if section in _C9_BY_NUMBER:
                m = re.search(r"\bi=(\d+)", err)
                return (section, int(m.group(1)) if m else 0)
            return (section, 0)
    return (2, 0)


def _primary_first(errors: list[str], walk_errors=frozenset()) -> list[str]:
    """`errors` in contract C9 order: the first is the PRIMARY error, whose
    state is the result.  Stable, so ties keep the order found."""
    return sorted(errors, key=lambda e: _c9_key(e, walk_errors))


def _make_result(errors: list[str], top_sig_i: int, top_domain: str,
                 walk_errors=frozenset()) -> VerifyResult:
    errors = _primary_first(errors, walk_errors)
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


@dataclass
class _Options:
    dns_data: object
    full_chain: bool = False
    verbose: bool = False
    skip_timestamp_check: bool = False
    mail_from: str | None = None
    rcpt_to: list[str] | None = None
    headers_only: bool = False
    allow_unsigned_mi: bool = False
    walk: str = "plan"
    walk_trace: list | None = None


@dataclass
class _Context:
    """What the header-field checks leave for the content and chain checks."""
    mi_headers: list[str]
    sig_headers: list[str]
    top_sig: str | None
    content_headers: list[bytes]
    all_errors: list[str]
    keys: object
    # Errors the chain walk found that rank with §14.7 though their text is
    # §14.2's: a Recipe that does not fit the message (contract C9).
    walk_errors: set = field(default_factory=set)


def _message_keys(dns_data):
    """The key source for one message: a dns.json dict as it is, a live
    source's per-message view (which prefetches)."""
    return dns_data.for_message() if hasattr(dns_data, "for_message") else dns_data


def _key_names(sig_headers: list[str]) -> list[str]:
    """Every distinct selector._domainkey.domain the signatures name, for the
    implemented algorithms only."""
    names = []
    for h in sig_headers:
        value = _get_header_value(h)
        d_val = _extract_tag(value, "d")
        s_tag = _extract_tag(value, "s")
        if not d_val or not s_tag:
            continue
        for item in s_tag.split(","):
            parts = [_strip_fws(f) for f in item.split(":", 2)]
            if len(parts) == 3 and parts[1] in SIG_ALGS:
                name = f"{parts[0]}._domainkey.{d_val}".lower()
                if name not in names:
                    names.append(name)
    return names


def _check_headers(headers: list[bytes], o: _Options):
    """Every check that needs only the header fields: a VerifyResult if one
    of them settles the verdict, else a _Context for the rest."""
    all_errors = []

    mi_headers = extract_mi_headers(headers)
    sig_headers = extract_sig_headers(headers)

    for h in mi_headers:
        if _extract_tag(_get_header_value(h), "m") is None:
            msg = "PERMERROR: Message-Instance m= tag=m missing"
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
            i_val = _extract_tag(_get_header_value(h), "i")
            msg = (f"PERMERROR: DKIM2-Signature i={i_val} syntax error"
                   if i_val is not None else
                   "PERMERROR: DKIM2-Signature i= tag=i missing")
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])

    # Every i= and m= is a chain number (1*DIGIT, at most 3 digits, 1..100,
    # and no more than MAX_CHAIN_LENGTH), before the gap loops below walk
    # 1..max.
    range_error = chain_range_error(mi_headers, sig_headers)
    if range_error:
        return VerifyResult(ok=False, status='permerror', failing_i=None,
                            domain=None, message=range_error, errors=[range_error])

    # -07 §8: the whole field must be a well-formed tag-list, with
    # well-formed s= items and h= hash-sets (follow-up review F.1-F.3).
    for h in mi_headers:
        if not _mi_syntax_ok(_get_header_value(h)):
            msg = (f"PERMERROR: Message-Instance "
                   f"m={_extract_tag(_get_header_value(h), 'm')} syntax error")
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])
    for h in sig_headers:
        if not _sig_syntax_ok(_get_header_value(h)):
            i_val = _extract_tag(_get_header_value(h), "i")
            msg = f"PERMERROR: DKIM2-Signature i={i_val or ''} syntax error"
            return VerifyResult(ok=False, status='permerror',
                                failing_i=_get_seq_from_sig(h),
                                domain=None, message=msg, errors=[msg])

    seen_m = set()
    for h in mi_headers:
        mv = _get_version_from_mi(h)
        if mv in seen_m:
            msg = f"PERMERROR: Message-Instance m={mv} appears more than once"
            return VerifyResult(ok=False, status='permerror', failing_i=None,
                                domain=None, message=msg, errors=[msg])
        seen_m.add(mv)

    # -07 §9.1: Message-Instance m= and DKIM2-Signature i= values must be
    # contiguous from 1.  Structural, so checked before any crypto.  (A
    # missing top instance in outbound mode is not a gap: the caller adds it.)
    for label, name, vals in (
            ("Message-Instance", "m", seen_m),
            ("DKIM2-Signature", "i",
             {_get_seq_from_sig(h) for h in sig_headers})):
        for n in range(1, (max(vals) if vals else 0) + 1):
            if n not in vals:
                msg = f"PERMERROR: {label} {name}={n} missing"
                return VerifyResult(ok=False, status='permerror',
                                    failing_i=None, domain=None,
                                    message=msg, errors=[msg])

    mi_only = o.allow_unsigned_mi and not sig_headers and bool(mi_headers)
    if not sig_headers and not mi_headers:
        # No DKIM2 header fields at all: result "none", with no error.
        return VerifyResult(ok=False, status='none', failing_i=None, domain=None,
                            message='no DKIM2 header fields', errors=[])
    if not sig_headers and not mi_only:
        msg = "PERMERROR: Message-Instance m=1 is not signed"
        return VerifyResult(ok=False, status='permerror', failing_i=None,
                            domain=None, message=msg, errors=[msg])
    if not mi_headers:
        top_m = max(_get_mi_from_sig(h) or 0 for h in sig_headers)
        msg = f"PERMERROR: Message-Instance m={top_m} missing"
        return VerifyResult(ok=False, status='permerror', failing_i=None,
                            domain=None, message=msg, errors=[msg])

    max_mi_version = max(_get_version_from_mi(h) for h in mi_headers)
    top_sig = None
    if not mi_only:
        # -07 §14.2: the top DKIM2-Signature must cover the topmost MI
        max_mi_version = max(_get_version_from_mi(h) for h in mi_headers)
        top_sig = max(sig_headers, key=_get_seq_from_sig)
        top_sig_value = _get_header_value(top_sig)
        top_sig_seq = _extract_tag(top_sig_value, "i")
        top_sig_m = _extract_tag(top_sig_value, "m")
        top_sig_m_int = int(top_sig_m) if top_sig_m else 0
        if top_sig_m_int != max_mi_version and not (
                o.allow_unsigned_mi and top_sig_m_int < max_mi_version):
            top_sig_i = _get_seq_from_sig(top_sig)
            top_domain = _extract_tag(_get_header_value(top_sig), 'd') or ''
            if top_sig_m_int > max_mi_version:
                msg = f"PERMERROR: Message-Instance m={top_sig_m_int} missing"
            else:
                msg = (f"PERMERROR: Message-Instance m={top_sig_m_int + 1} "
                       f"is not signed")
            return VerifyResult(ok=False, status='permerror', failing_i=top_sig_i,
                                domain=top_domain, message=msg, errors=[msg])

        # Local policy: the top (highest-i=) DKIM2-Signature MUST NOT carry nd=.
        # nd= only ever legitimately appears together with a subsequent, higher-i=
        # signature that takes over custody; a top-of-chain nd= means the chain
        # is incomplete/tampered, so reject before any further checks run.
        # A §14.4 error: collected, and ranked with the others (contract
        # C9), so a §14.2 or §14.3 error elsewhere still comes first.
        if _extract_tag(top_sig_value, "nd") and not o.allow_unsigned_mi:
            all_errors.append(
                f"PERMERROR: DKIM2-Signature i={top_sig_seq} unexpected nd= tag")

    # Envelope MAIL FROM / RCPT TO checks (-07 §14.4):
    # exact match against the top signature's declared mf=/rt=, domains
    # lowercased, local-part case-sensitive. Applies regardless of
    # full_chain/simple mode. rt= MAY carry extra recipients beyond what was
    # actually delivered; every delivered RCPT TO must be present in the set.
    if (o.mail_from is not None or o.rcpt_to) and top_sig is not None:
        top_i = _get_seq_from_sig(top_sig)
        top_mf_b64 = _extract_tag(top_sig_value, "mf")
        top_rt_raw = _extract_tag(top_sig_value, "rt")
        top_mf = (base64.b64decode(top_mf_b64).decode("utf-8", errors="surrogateescape")
                  if top_mf_b64 else None)
        top_rts = [
            base64.b64decode(rt.strip()).decode("utf-8", errors="surrogateescape")
            for rt in (top_rt_raw.split(",") if top_rt_raw else []) if rt.strip()
        ]

        if o.mail_from is not None:
            if top_mf is None or not _envelope_addr_equal(o.mail_from, top_mf):
                all_errors.append(
                    f"PERMERROR: DKIM2-Signature i={top_i} MAIL FROM {o.mail_from} did not match"
                )
        for rcpt in (o.rcpt_to or []):
            if not any(_envelope_addr_equal(rcpt, rt) for rt in top_rts):
                all_errors.append(
                    f"PERMERROR: DKIM2-Signature i={top_i} RCPT TO {rcpt} did not match"
                )

    # Collect the non-MI, non-sig headers for hash verification
    content_headers = []
    for hdr in headers:
        name = _header_name(hdr)
        if name not in (b"message-instance", b"dkim2-signature"):
            content_headers.append(hdr)

    # Start fetching every public key now, while the body arrives (a no-op
    # for a dns.json source).
    keys = _message_keys(o.dns_data)
    if hasattr(keys, "prefetch"):
        keys.prefetch(_key_names(sig_headers))

    return _Context(mi_headers, sig_headers, top_sig, content_headers,
                    all_errors, keys)


def _verify_simple(ctx: _Context, body: bytes, o: _Options) -> VerifyResult:
    """Simple mode: verify every MI against the current message (or, with
    headers_only, the top MI's header hash), and every signature."""
    all_errors = ctx.all_errors
    mi_headers, sig_headers = ctx.mi_headers, ctx.sig_headers
    if o.headers_only:
        top_mi = max(mi_headers, key=_get_version_from_mi)
        all_errors.extend(verify_message_instance(
            top_mi, ctx.content_headers, b"", headers_only=True))
    else:
        for mi_hdr in mi_headers:
            errs = verify_message_instance(mi_hdr, ctx.content_headers, body)
            all_errors.extend(errs)

    sig_by_seq = sorted(sig_headers, key=_get_seq_from_sig)

    # -07 §14.2: every r= on its own (contract C9)
    all_errors.extend(e for e in _recipe_structure_errors(mi_headers)
                      if e not in all_errors)
    # -07 §10.5/§10.6: mf=/rt= MUST be bracketed RFC5321 paths
    all_errors.extend(_bracket_errors(sig_by_seq))
    # -07 §7.1, §14.4: Chain of Custody
    all_errors.extend(_chain_custody_errors(sig_by_seq))
    # -07 §11, §14.8: every From the chain shows is Authentic
    mi_by_version, _ = _walk_order(ctx)
    all_errors.extend(_from_authentic_errors(ctx.content_headers,
                                             mi_by_version, sig_by_seq))

    for idx, sig_hdr in enumerate(sig_by_seq):
        prior_sigs = sig_by_seq[:idx]
        errs = verify_dkim2_signature(sig_hdr, mi_headers, prior_sigs, ctx.keys,
                                      skip_timestamp_check=o.skip_timestamp_check)
        all_errors.extend(errs)

    top_sig_i = _get_seq_from_sig(ctx.top_sig)
    top_domain = _extract_tag(_get_header_value(ctx.top_sig), 'd') or ''
    return _make_result(all_errors, top_sig_i, top_domain)


class _UndoWalk:
    """The reference walk: rebuild each previous message from the Recipes."""

    def __init__(self, content_headers: list[bytes], body: bytes):
        self.headers = list(content_headers)
        self.body = body

    def mi_errors(self, version, mi_hdr, headers_only):
        return verify_message_instance(mi_hdr, self.headers, self.body,
                                       headers_only=headers_only)

    def digests(self, version, with_body):
        return (compute_header_hash(self.headers),
                compute_body_hash(self.body) if with_body else None)

    def undo_headers(self, version, h_recipes):
        self.headers = reconstruct_headers(self.headers, h_recipes)

    def undo_body(self, version, b_recipes):
        self.body = reconstruct_body(self.body, b_recipes)


class _PlannedWalk:
    """The planned walk (dkim2plan): every instance's hashes are already
    known; undoing a Recipe only reports what the plan found."""

    def __init__(self, plan):
        self.plan = plan

    def mi_errors(self, version, mi_hdr, headers_only):
        hstate, segs = self.plan.state[version]
        return check_message_instance(
            mi_hdr, lambda alg: self.plan.headers.digest(hstate, alg),
            lambda alg: self.plan.body.digest(segs, alg), headers_only)

    def digests(self, version, with_body):
        hstate, segs = self.plan.state[version]
        return (self.plan.headers.digest(hstate, "sha256"),
                self.plan.body.digest(segs, "sha256") if with_body else None)

    def undo_headers(self, version, h_recipes):
        if version in self.plan.bad:
            raise MalformedRecipe(f"header Recipe at m={version}")

    def undo_body(self, version, b_recipes):
        if self.plan.recipe_error(version):
            raise MalformedRecipe(f"body Recipe at m={version}")


def _walk_order(ctx: _Context):
    mi_by_version = {}
    for mi_hdr in ctx.mi_headers:
        v = _get_version_from_mi(mi_hdr)
        mi_by_version[v] = mi_hdr
    return mi_by_version, sorted(mi_by_version.keys(), reverse=True)


def _verify_chain(ctx: _Context, walk, o: _Options) -> VerifyResult:
    """Full chain validation: walk backwards through MI versions, checking
    each instance against the message as `walk` says it was then."""
    all_errors = ctx.all_errors
    verbose = o.verbose
    mi_by_version, versions = _walk_order(ctx)

    sig_by_seq = sorted(ctx.sig_headers, key=_get_seq_from_sig)

    # -07 §14.2: every r= on its own (contract C9)
    all_errors.extend(e for e in _recipe_structure_errors(ctx.mi_headers)
                      if e not in all_errors)
    # -07 §10.5/§10.6: mf=/rt= MUST be bracketed RFC5321 paths
    all_errors.extend(_bracket_errors(sig_by_seq))
    # -07 §7.1, §14.4: Chain of Custody
    all_errors.extend(_chain_custody_errors(sig_by_seq))
    # -07 §11, §14.8: every From the chain shows is Authentic
    all_errors.extend(_from_authentic_errors(ctx.content_headers,
                                             mi_by_version, sig_by_seq))

    # Every DKIM2-Signature, from i=1 up, whether or not the chain walk
    # below reaches the instance it covers (contract C9 ranks what they find).
    for idx, sig_hdr in enumerate(sig_by_seq):
        sig_value = _get_header_value(sig_hdr)
        sig_m = _extract_tag(sig_value, "m")
        i_val = _extract_tag(sig_value, "i")
        version = int(sig_m) if sig_m and sig_m.isdigit() else 0
        relevant_mi = [mi_by_version[v] for v in sorted(mi_by_version)
                       if v <= version]
        errs = verify_dkim2_signature(
            sig_hdr, relevant_mi, sig_by_seq[:idx], ctx.keys,
            skip_timestamp_check=o.skip_timestamp_check,
        )
        if errs:
            all_errors.extend(errs)
        elif verbose:
            print(f"  DKIM2-Signature i={i_val}: OK", file=sys.stderr)

    # -07 §5.2: once an instance's body Recipe is null the previous body
    # cannot be recreated, so every lower instance is checked on its header
    # hash only (header Recipes are mandatory, so header history still is).
    body_unchecked_below = None

    for version in versions:
        mi_hdr = mi_by_version[version]

        if verbose:
            print(f"Verifying MI v={version}...", file=sys.stderr)

        # Verify this MI's hashes against the current message state
        errs = walk.mi_errors(version, mi_hdr, body_unchecked_below is not None)
        if o.walk_trace is not None:
            o.walk_trace.append(
                (version,) + walk.digests(version, body_unchecked_below is None))
        if errs:
            # Every error names its own m= (-07 §14.2, §14.7).
            all_errors.extend(e for e in errs if e not in all_errors)
        elif verbose:
            print(f"  MI v={version} hashes: OK", file=sys.stderr)

        # If there's a lower version, undo Recipes to reconstruct previous state
        if version > versions[-1]:
            # A malformed r= is already reported (as the specific §14.2
            # invalid-JSON PERMERROR) by the mi_errors() call above; don't
            # let the same failure crash decode_recipes() here with an
            # uncaught exception.
            try:
                recipes = decode_recipes(mi_hdr)
            except (ValueError, TypeError):
                recipes = None
            if recipes is not None:
                null_h, h_recipes, null_b, b_recipes = recipe_actions(recipes)

                # A Recipe that cannot be applied (§5: a "c" range past the
                # items present, or any structural fault the hash check
                # above already named) is reported as invalid JSON (-07
                # §14.2: it breaks the schema); mi_errors() may have reported
                # the structural part already, so don't list it twice. The
                # reconstruction stops here: the lower instances cannot be
                # checked against a state we could not rebuild.
                def _malformed(e):
                    msg = _malformed_recipe_error(version)
                    if msg not in all_errors:
                        all_errors.append(msg)
                        ctx.walk_errors.add(msg)
                    if verbose:
                        print(f"  Malformed Recipe in m={version}: {e}",
                              file=sys.stderr)

                # draft -07 §5.1: a present "h" that is JSON null (the null
                # header Recipe) is not allowed; validate_recipes() has
                # already reported it.
                if null_h:
                    _malformed("null header Recipe")
                    break
                if h_recipes is not None:
                    try:
                        walk.undo_headers(version, h_recipes)
                        if verbose:
                            print(f"  Undid header recipes for v={version}",
                                  file=sys.stderr)
                    except ValueError as e:
                        _malformed(e)
                        break

                if null_b:
                    # Null body Recipe: header history is still walked.
                    if body_unchecked_below is None:
                        body_unchecked_below = version
                        if verbose:
                            print(f"  Body not checked below m={version}: "
                                  f"null body Recipe", file=sys.stderr)
                elif b_recipes is not None and body_unchecked_below is None:
                    try:
                        walk.undo_body(version, b_recipes)
                        if verbose:
                            print(f"  Undid body recipes for v={version}",
                                  file=sys.stderr)
                    except ValueError as e:
                        _malformed(e)
                        break

    top_sig = ctx.top_sig
    top_sig_i = _get_seq_from_sig(top_sig) if top_sig else 0
    top_domain = (_extract_tag(_get_header_value(top_sig), 'd') or '') if top_sig else ''
    result = _make_result(all_errors, top_sig_i, top_domain, ctx.walk_errors)
    if result.ok and body_unchecked_below is not None:
        result.message += (f" (body not checked below m={body_unchecked_below}: "
                           f"null body Recipe)")
    return result


def _normalise_crlf(data: bytes) -> tuple[bytes, int]:
    """parse_message()'s line-ending rule (CRLF, lone CR and lone LF are all
    one line break, written CRLF), for a piece that does not end in CR.
    Returns the piece, copied only if it changes, and its line breaks."""
    n = data.count(b"\n")
    if data.count(b"\r") == n and data.count(b"\r\n") == n:
        return data, n
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data.replace(b"\n", b"\r\n"), data.count(b"\n")


class MessageVerifier:
    """Incremental verify_message(): feed() the raw message in chunks cut
    anywhere, then close() for the VerifyResult.

    The header fields are checked (and, with a live key source, every
    public key looked up in the background) as soon as the blank line after
    them arrives.  In full-chain mode the planned walk (dkim2plan) hashes
    the body as it arrives and holds only a partial line; otherwise (simple
    mode, headers_only, walk="undo", or a message the plan hands back to the
    undo walk) the body is kept and checked at close().
    """

    def __init__(self, dns_data, full_chain: bool = False, verbose: bool = False,
                 skip_timestamp_check: bool = False,
                 mail_from: str | None = None,
                 rcpt_to: list[str] | None = None,
                 headers_only: bool = False,
                 allow_unsigned_mi: bool = False,
                 walk: str = "plan",
                 walk_trace: list | None = None):
        if walk not in ("plan", "undo"):
            raise ValueError(f"walk must be 'plan' or 'undo', not {walk!r}")
        self.o = _Options(dns_data, full_chain, verbose, skip_timestamp_check,
                          mail_from, rcpt_to, headers_only, allow_unsigned_mi,
                          walk, walk_trace)
        self._held_cr = False       # a CR that may be the start of a CRLF
        self._head = bytearray()    # normalised header block, until it ends
        self._result = None         # settled by the header fields alone
        self._ctx = None
        self._plan = None
        self._pass = None           # BodyPass, or None to keep the body
        self._body = bytearray()

    def _normalise(self, data: bytes) -> tuple[bytes, int]:
        if self._held_cr:
            data = b"\r" + data
            self._held_cr = False
        if data.endswith(b"\r"):
            data = data[:-1]
            self._held_cr = True
        return _normalise_crlf(data)

    def feed(self, data: bytes) -> None:
        if not data:
            return
        data, nlf = self._normalise(data)
        start = 0
        if self._head is not None:
            start = self._split_head(data)
            if start is None:
                return
            nlf -= data.count(b"\n", 0, start)
        self._body_data(data, start, nlf)

    def _split_head(self, data: bytes) -> int | None:
        """Take the header fields from `data`: None if they go on past it,
        else where the body starts (after the blank line) once the header
        block is handled.  Only the header part is copied."""
        head = self._head
        # The blank line may start in the bytes already held.
        edge = bytes(head[-3:])
        cut = (edge + data[:3]).find(b"\r\n\r\n")
        if cut >= 0:
            cut -= len(edge)
            del head[len(head) + cut:]
        else:
            cut = data.find(b"\r\n\r\n")
            if cut < 0:
                head += data
                return None
            head += memoryview(data)[:cut]
        self._end_of_headers(bytes(head))
        return cut + 4

    def _body_data(self, data: bytes, start: int = 0,
                   nlf: int | None = None) -> None:
        """Body bytes data[start:]; nlf, if known, the LFs in them."""
        if self._result is not None or start >= len(data):
            return
        if self._pass is not None:
            self._pass.feed(data, start, nlf)
        else:
            self._body += memoryview(data)[start:]

    def _end_of_headers(self, header_block: bytes) -> None:
        self._head = None
        headers, _ = parse_message(header_block)
        checked = _check_headers(headers, self.o)
        if isinstance(checked, VerifyResult):
            self._result = checked
            return
        self._ctx = checked
        o = self.o
        if o.full_chain and not o.headers_only and o.walk == "plan":
            mi_by_version, versions = _walk_order(checked)
            self._plan = plan_chain(
                checked.content_headers, mi_by_version, versions,
                ("sha256",) if o.walk_trace is not None else ())
            if self._plan is not None:
                self._pass = BodyPass(self._plan.body)

    def close(self) -> VerifyResult:
        tail = b"\r\n" if self._held_cr else b""
        self._held_cr = False
        if self._head is not None:
            # No blank line yet: the CR held back may complete one.
            start = self._split_head(tail)
            if start is None:
                self._end_of_headers(bytes(self._head))
            else:
                self._body_data(tail, start)
        else:
            self._body_data(tail)
        if self._result is not None:
            return self._result
        o, ctx = self.o, self._ctx
        if not o.full_chain or o.headers_only:
            return _verify_simple(ctx, bytes(self._body), o)
        if self._pass is not None:
            self._pass.close()
            return _verify_chain(ctx, _PlannedWalk(self._plan), o)
        return _verify_chain(ctx, _UndoWalk(ctx.content_headers,
                                            bytes(self._body)), o)


def _chunks(source: "Source", size: int = 1 << 16):
    if isinstance(source, (bytes, bytearray)):
        yield bytes(source)
        return
    if isinstance(source, (str, Path)):
        with open(source, "rb") as fh:
            yield from iter(lambda: fh.read(size), b"")
        return
    yield from iter(lambda: source.read(size), b"")


def verify_message(source: "Source", dns_data, full_chain: bool = False,
                   verbose: bool = False,
                   skip_timestamp_check: bool = False,
                   mail_from: str | None = None,
                   rcpt_to: list[str] | None = None,
                   headers_only: bool = False,
                   allow_unsigned_mi: bool = False,
                   walk: str = "plan",
                   walk_trace: list | None = None) -> "VerifyResult":
    """Verify all DKIM2 signatures in a message.

    dns_data is a dns.json dict or a live key source (dkim2dns.LiveDNS).

    If full_chain is True, walks backwards through MI versions, verifying
    that each MI's hashes match the message as it was at that point, and
    each DKIM2-Signature verifies against the MI/sig headers that existed at
    that point.  walk="plan" (the default) works the previous versions' hashes
    out in one pass over the message (dkim2plan); walk="undo" rebuilds each
    previous message from the Recipes (dkim2undo) -- the reference the
    planned walk is tested against.  Both give the same verdict.  walk_trace,
    if a list, gets (m, sha256 header hash, sha256 body hash or None) for
    every instance the walk checks.

    If headers_only is True the message has no body, as with the returned
    original in a DSN's text/rfc822-headers part (-07 §16.3). Signatures
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
    o = _Options(dns_data, full_chain, verbose, skip_timestamp_check,
                 mail_from, rcpt_to, headers_only, allow_unsigned_mi,
                 walk, walk_trace)
    if full_chain and not headers_only and walk == "plan":
        v = MessageVerifier(dns_data, full_chain, verbose, skip_timestamp_check,
                            mail_from, rcpt_to, headers_only, allow_unsigned_mi,
                            walk, walk_trace)
        for chunk in _chunks(source):
            v.feed(chunk)
        return v.close()

    raw = _to_bytes(source)
    headers, body = parse_message(raw)
    checked = _check_headers(headers, o)
    if isinstance(checked, VerifyResult):
        return checked
    if not full_chain or headers_only:
        return _verify_simple(checked, body, o)
    return _verify_chain(checked, _UndoWalk(checked.content_headers, body), o)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Verify DKIM2 signatures (draft-ietf-dkim-dkim2-spec-07)")
    parser.add_argument("message", help="Path to signed email file (- for stdin)")
    parser.add_argument("--dns-json",
                        help="Path to dns.json with public keys (default: "
                             "look the keys up in DNS)")
    parser.add_argument("--no-prefetch", action="store_true",
                        help="With DNS keys, look each one up only when its "
                             "signature is checked")
    parser.add_argument("--undo-walk", action="store_true",
                        help="Check the chain by rebuilding every previous "
                             "version (the reference walk) instead of the "
                             "planned walk")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print detailed verification results")
    parser.add_argument("--full-chain", action="store_true",
                        help="Accepted for compatibility; full-chain validation "
                             "is the default")
    parser.add_argument("--ignore-timestamps", "--skip-timestamp-check",
                        dest="skip_timestamp_check", action="store_true",
                        help="Disable the §14.3 timestamp (14-day/future) check")
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

    if args.dns_json:
        dns_data = load_dns_json(args.dns_json)
    else:
        try:
            dns_data = LiveDNS(prefetch=not args.no_prefetch)
        except RuntimeError as e:   # no dnspython
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)
    # Full-chain validation is the default; --full-chain kept for compatibility.
    result = verify_message(raw, dns_data, full_chain=True,
                            walk="undo" if args.undo_walk else "plan",
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
