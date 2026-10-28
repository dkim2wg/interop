#!/usr/bin/env python3
"""
DKIM2 verifier - draft-ietf-dkim-dkim2-spec-07

Takes a signed email and verifies its DKIM2 signatures using public keys
from a dns.json file or DNS TXT records (dkim2dns; looked up in the
background as soon as the header fields are known, used only once the
chain walk has passed).

The checks run in contract C9's order, so the first error is the same
PRIMARY error every verifier reports: §14.2 structure, each
Message-Instance's content, the §14.7 chain walk, then the signatures.

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
    _is_ascii_digits,
    chain_number_error,
    MAX_CHAIN_LENGTH,
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

    # -08 §3.2, §14.5 (contract D7): a p= that is base64 but is not a key of
    # its type is "is malformed" (one that is not base64 at all stays "has a
    # syntax error", above).
    if key_type == "ed25519":
        # Exactly the raw 32-octet Ed25519 public key (RFC 8463); a DER
        # SubjectPublicKeyInfo is malformed.
        if len(pub_bytes) != 32:
            raise KeyRecordError("is malformed")
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes), "ed25519"
        except ValueError:
            raise KeyRecordError("is malformed")
    # RSA: DER-encoded SubjectPublicKeyInfo, which must hold an RSA key of
    # at least 1024 bits (-08 §3.2: MUST NOT validate a shorter one; up to
    # 4096 MUST verify, and a larger one may).
    try:
        key = serialization.load_der_public_key(pub_bytes)
    except (ValueError, TypeError):
        raise KeyRecordError("is malformed")
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 1024:
        raise KeyRecordError("is malformed")
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


def _paths_bracketed(value: str) -> bool:
    """-07 §10.5/§10.6: every present mf= and rt= entry MUST be a bracketed
    RFC5321 path (matches <...>, incl. <>); one that is not base64 is not.
    nd= hops carry no mf/rt, so have nothing to check."""
    for tag in ("mf", "rt"):
        raw = _extract_tag(value, tag)
        for part in (raw.split(",") if raw else []):
            if part.strip():
                dec = _decode_path(part)
                if not (dec.startswith("<") and dec.endswith(">")):
                    return False
    return True


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
    C4 steps.  Every failure is a FAIL (-08 §14.4, contract D5).

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
                        f"FAIL: DKIM2-Signature i={prev_i} nd= does not match")
            elif nd or null_mf:
                if not any(relaxed_match(rt, d) for rt in _rt_domains(prev)):
                    errors.append(
                        f"FAIL: DKIM2-Signature i={i_val} d= does not "
                        f"match the rt= of i={prev_i}")
            elif mf is not None:
                mf_d = addr_domain(mf)
                if mf_d is None or not any(relaxed_match(mf_d, rt)
                                           for rt in _rt_domains(prev)):
                    errors.append(
                        f"FAIL: DKIM2-Signature i={i_val} mf= does not "
                        f"match the rt= of i={prev_i}")

        if mf is not None and not null_mf and not nd:
            mf_d = addr_domain(mf)
            if mf_d is None or not relaxed_match(mf_d, d):
                errors.append(
                    f"FAIL: DKIM2-Signature i={i_val} MAIL FROM and d= "
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
            msg = f"FAIL: DKIM2-Signature i={i_val} matching From is not authentic"
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


def split_groups(value: str) -> list[list[str]] | None:
    """-08 §9.3 hash-any / §10.9 sig-any: groups separated by "|", each a
    list of items separated by "," ("," binds tighter).  FWS is allowed on
    either side of both, so items keep their own WSP for the caller to
    trim.  None if any member is empty (a leading, trailing or doubled "|"
    or ","): a syntax error (contract D2)."""
    groups = []
    for group in value.split("|"):
        items = group.split(",")
        if any(not it.strip(_WSP) for it in items):
            return None
        groups.append(items)
    return groups


_B64STRING_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def _b64string_ok(val: str) -> bool:
    """-08 §2.14 base64string grammar: non-empty, FWS inside ignored.  The
    padding is checked with the values (_mi_content_error), as before."""
    return _B64STRING_RE.fullmatch(_strip_fws(val)) is not None


def _sig_syntax_ok(value: str) -> bool:
    """§8 tag-list plus §10.9 s= sig-sets: each exactly
    selector:algorithm:value, in "|" groups of "," lists (contract D2).

    FWS is allowed (trimmed) around the ',', '|' and ':'s and inside the
    base64 value, but not inside the selector or algorithm name."""
    if not _tag_list_ok(value):
        return False
    s_tag = _extract_tag(value, "s")
    if s_tag is None:
        return True  # reported as a missing tag
    groups = split_groups(s_tag)
    if groups is None:
        return False
    for item in (it for g in groups for it in g):
        parts = [p.strip(_WSP) for p in item.split(":")]
        if (len(parts) != 3 or not _SELECTOR_RE.fullmatch(parts[0])
                or not _NAME_RE.fullmatch(parts[1])):
            return False
    return True


def _mi_syntax_ok(value: str) -> bool:
    """§8 tag-list plus §9.3 h= hash-sets: each exactly name:hash:hash, in
    "|" groups of "," lists (contract D2), with no FWS inside the hash name
    and both digests base64strings, whatever the algorithm (contract D3)."""
    if not _tag_list_ok(value):
        return False
    h_tag = _extract_tag(value, "h")
    if h_tag is None:
        return True  # reported as a missing tag
    groups = split_groups(h_tag)
    if groups is None:
        return False
    for item in (it for g in groups for it in g):
        parts = [p.strip(_WSP) for p in item.split(":")]
        if (len(parts) != 3 or not _NAME_RE.fullmatch(parts[0])
                or not _b64string_ok(parts[1]) or not _b64string_ok(parts[2])):
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


def parse_hash_groups(h_tag: str) -> list[list[tuple[str, str, str]]]:
    """Parse a -08 §9.3 h= value into "|" groups of "," lists of
    (alg, header_hash, body_hash) triples (malformed items left out: the
    syntax check reports them).

    Hash names are case-sensitive (-08 §2.14, %s"sha256" in §9.3), so
    "SHA256" is an algorithm we have not implemented.

    Per -08 §2.12, folding whitespace may appear inside a base64 string
    (or around the colons) and MUST be ignored when the value is used, so
    every field is run through _strip_fws rather than a bare .strip().
    """
    groups = []
    for group in h_tag.split("|"):
        sets = []
        for item in group.split(","):
            parts = _strip_fws(item).split(":")
            if len(parts) == 3:
                sets.append((parts[0], parts[1], parts[2]))
        groups.append(sets)
    return groups


def parse_hash_sets(h_tag: str) -> list[tuple[str, str, str]]:
    """Every hash-set of an h= value, in order, whatever its group."""
    return [hs for g in parse_hash_groups(h_tag) for hs in g]


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
                # bound is checked where the Recipe is applied (the chain
                # walk) and reported under the same text.
                try:
                    validate_recipes(recipes)
                except MalformedRecipe as e:
                    # Contract D6: one bad step is "Recipe <path> is
                    # invalid"; a whole-document fault is invalid JSON.
                    errors.append(_malformed_recipe_error(m_val) if e.path is None
                                  else f"PERMERROR: Message-Instance m={m_val} "
                                       f"Recipe {e.path} is invalid")
    return errors


def _mi_content_error(mi_hdr: str) -> str | None:
    """Contract C9 §14.2 content: the first thing wrong with one
    Message-Instance on its own, or None.  In order: its tag-list syntax
    (-07 §8, §9.3: whole-field syntax, a tag given twice in any case),
    missing tags, a duplicate hash algorithm, no implemented algorithm, its
    Recipe, then the hash values' base64.
    Checked for every instance, whether or not the chain walk reaches it."""
    value = _get_header_value(mi_hdr)
    m_val = _extract_tag(value, "m")
    syntax = f"PERMERROR: Message-Instance m={m_val} syntax error"
    names = _tag_names(value)
    if not _mi_syntax_ok(value) or len(set(names)) != len(names):
        return syntax

    h_tag = _extract_tag(value, "h")
    if not h_tag:
        return f"PERMERROR: Message-Instance m={m_val} tag=h missing"
    sets = parse_hash_sets(h_tag)
    if not sets:
        return syntax
    # -08 §9.3: an algorithm MUST NOT be present more than once, anywhere
    # in the tag (contract D2).  An algorithm we have not implemented is
    # not an error here: it is a PERMERROR hash-set in the §14.7 walk (D4).
    algs = [alg for alg, _, _ in sets]
    if len(set(algs)) != len(algs):
        return f"PERMERROR: Message-Instance m={m_val} has a duplicate hash algorithm"

    # §14.2: a malformed r= is reported specifically.  Two failure kinds,
    # kept distinct: a bad base64 value never reaches JSON parsing (a plain
    # syntax error), while a JSON parse or schema failure is "contains
    # invalid JSON".
    errors = _recipe_field_errors(value, m_val)
    if errors:
        return errors[0]

    # §14.2: verifiers MUST meticulously validate format and values: every
    # hash-set's values are padded base64, whatever its algorithm (§2.14,
    # contract D3).
    if any(_b64decode_strict(h) is None or _b64decode_strict(b) is None
           for alg, h, b in sets):
        return syntax
    return None


def _all_state(states: list[str]) -> str:
    """-08 §14.6 step 6 / §14.7 step 4: a "," list (sig-all, hash-all)."""
    if all(s == "pass" for s in states):
        return "pass"
    if all(s == "temperror" for s in states if s != "pass"):
        return "temperror"
    return "fail" if "fail" in states else "permerror"


def _any_state(states: list[str]) -> str:
    """-08 §14.6 step 7 / §14.7 step 5: the "|" groups (sig-any, hash-any)."""
    for s in ("pass", "temperror", "fail"):
        if s in states:
            return s
    return "permerror"


def _combine(groups: list[list[tuple[str, str | None]]],
             no_group_passed: str) -> str | None:
    """The reported error for "|" groups of "," lists of (state, error)
    item results, or None for a PASS (contract D3/D4).  One group: the
    first item, in tag order, whose own state is the group's.  More than
    one: `no_group_passed` for a FAIL, otherwise the first item, in tag
    order, with that state.  Every item has been evaluated already, so the
    answer does not depend on evaluation order."""
    state = _any_state([_all_state([s for s, _ in g]) for g in groups])
    if state == "pass":
        return None
    if state == "fail" and len(groups) > 1:
        return no_group_passed
    return next(e for g in groups for s, e in g if s == state)


def _mi_hash_errors(mi_hdr: str, header_hash, body_hash,
                    headers_only: bool = False) -> list[str]:
    """-08 §14.7 for one instance whose content is sound (_mi_content_error),
    as contract D4 combines it: each hash-set is PASS if its header and body
    hashes both match, FAIL if either does not (the header named first), and
    PERMERROR if we have not implemented its algorithm; then the "," lists
    and "|" groups are combined (_combine).  With headers_only (no body to
    check: an inbound DSN's headers, §16.4, or an instance below a null body
    Recipe) a set passes when its header hash matches."""
    value = _get_header_value(mi_hdr)
    m_val = _extract_tag(value, "m")
    who = f"Message-Instance m={m_val}"
    groups = []
    for group in parse_hash_groups(_extract_tag(value, "h")):
        results = []
        for alg, h_val, b_val in group:
            if alg not in HASH_ALGS:
                results.append(("permerror", f"PERMERROR: {who} algorithm {alg} unknown"))
            elif header_hash(alg) != _b64decode_strict(_strip_fws(h_val)):
                results.append(("fail", f"FAIL: {who} header hash {alg} mismatch"))
            elif not headers_only and body_hash(alg) != _b64decode_strict(_strip_fws(b_val)):
                results.append(("fail", f"FAIL: {who} body hash {alg} mismatch"))
            else:
                results.append(("pass", None))
        groups.append(results)
    err = _combine(groups, f"FAIL: {who} no group of hashes passed")
    return [err] if err else []


def check_message_instance(mi_hdr: str, header_hash, body_hash,
                           headers_only: bool = False) -> list[str]:
    """verify_message_instance() with the message's hashes supplied by
    header_hash(alg) and body_hash(alg) (the planned walk has no message
    to give it): the instance's content error, else its hash mismatches."""
    err = _mi_content_error(mi_hdr)
    if err:
        return [err]
    return _mi_hash_errors(mi_hdr, header_hash, body_hash, headers_only)


# Contract D3, local limit: -08 dropped "more selectors than allowed", and
# every s= item can cost a key lookup and a verify, so an s= tag may carry
# at most this many items (any algorithms, any groups).
MAX_SIGNATURES = 8


def _check_signature_duplicates(sig_items, i_val) -> list[str]:
    """-08 §10.9 rules for one DKIM2-Signature s= tag, across the whole tag
    (contract D2): a Selector MUST NOT appear more than once (compared
    without regard to case: a Selector is a Domain, §3.6), then the local
    limit of MAX_SIGNATURES items."""
    errors = []
    selectors = [sel.lower() for sel, _, _ in sig_items]
    if len(set(selectors)) != len(selectors):
        errors.append(f"PERMERROR: DKIM2-Signature i={i_val} has a duplicate selector")
    if len(sig_items) > MAX_SIGNATURES:
        errors.append(f"PERMERROR: DKIM2-Signature i={i_val} has more than "
                      f"{MAX_SIGNATURES} signatures")
    return errors


# -07 §14.3 timestamp limits, in seconds.
MAX_AGE = 14 * 24 * 3600
MAX_FUTURE = 24 * 3600

# Implemented signature algorithms (-08 §3) -> the k= key type they need.
# ML-DSA-44 (§3.4) is deferred (contract D8): "mldsa44", like the old
# "mldsa44-ed25519-sha512" and any other name, is an algorithm we have not
# implemented, a PERMERROR item (§14.6 step 4) that a "|" group can
# override.  Names are case-sensitive (§2.14).
SIG_ALGS = {"rsa-sha256": "rsa", "ed25519-sha256": "ed25519"}


def _blank_signature_values(sig_hdr: str) -> str:
    """The incomplete (signed) form of a DKIM2-Signature header: every s=
    item's signature value removed, everything else byte-for-byte -- the
    selectors, algorithm names and every ':' ',' '|' stay (-08 §12.8)."""
    colon = sig_hdr.find(":")
    parts = sig_hdr[colon + 1:].split(";")
    for idx, part in enumerate(parts):
        if "=" not in part:
            continue
        name, val = part.split("=", 1)
        if name.strip() != "s":
            continue
        inner = val.strip()
        lead = val[:len(val) - len(val.lstrip())]
        trail = val[len(val.rstrip()):]
        blanked = "|".join(
            ",".join(":".join(item.split(":", 2)[:2]) + ":"
                     for item in group.split(","))
            for group in inner.split("|"))
        parts[idx] = f"{name}={lead}{blanked}{trail}"
        break
    return sig_hdr[:colon + 1] + ";".join(parts)


def _sig_groups(s_tag: str) -> list[list[list[str]]]:
    """The s= sig-sets as "|" groups of "," lists of [selector, algorithm,
    value], FWS removed per §2.12 ("folding whitespace ... MUST be ignored
    when the value is used"), so a fold anywhere inside an item doesn't
    corrupt the Selector, the algorithm name or the base64 signature.  An
    item without three fields is left short (a syntax error)."""
    return [[[_strip_fws(f) for f in part.split(":", 2)]
             for part in group.split(",")]
            for group in s_tag.split("|")]


def _sig_items(s_tag: str) -> list[list[str]]:
    """Every s= item, in tag order, whatever its group (_sig_groups)."""
    return [it for g in _sig_groups(s_tag) for it in g]


def _sig_content_error(sig_hdr: str) -> str | None:
    """Contract C9 §14.2 content: the first thing wrong with one
    DKIM2-Signature on its own, or None.  In order: its tag-list syntax
    (-07 §8, §10.9: whole-field syntax, a tag given twice in any case),
    missing or unexpected tags (§10), the values' own syntax (t=, mf=/rt=,
    the s= signature values), the n= length, then a duplicate or excess
    Selector (§10.9).  Every check here comes before any key lookup."""
    value = _get_header_value(sig_hdr)
    i_val = _extract_tag(value, "i")
    syntax = f"PERMERROR: DKIM2-Signature i={i_val or ''} syntax error"
    names = _tag_names(value)
    if not _sig_syntax_ok(value) or len(set(names)) != len(names):
        return syntax

    # -07 §10: i= m= t= d= s= MUST be present; plus either nd= or both
    # mf= and rt= (and nd= excludes mf=/rt=).
    tags = {n: _extract_tag(value, n)
            for n in ("i", "m", "t", "d", "s", "nd", "mf", "rt")}
    for name in ("i", "m", "t", "d", "s"):
        if not tags[name]:
            return f"PERMERROR: DKIM2-Signature i={i_val or ''} tag={name} missing"
    nd_val, mf_val, rt_val = tags["nd"], tags["mf"], tags["rt"]
    if nd_val and (mf_val or rt_val):
        return (f"PERMERROR: DKIM2-Signature i={i_val} "
                f"tag={'mf' if mf_val else 'rt'} was unexpected")
    if not nd_val and not (mf_val and rt_val):
        return (f"PERMERROR: DKIM2-Signature i={i_val} "
                f"tag={'rt' if mf_val else 'mf'} missing")

    # §10.4: sig-t-tag = 1*DIGIT. Checked even when the age check is skipped.
    # §10.5/§10.6: mf= and rt= entries are bracketed paths.
    if not _is_ascii_digits(tags["t"]) or not _paths_bracketed(value):
        return syntax
    # §10.9: every item, whatever its algorithm, carries a non-empty base64
    # value (contract D3).
    items = _sig_items(tags["s"])
    if any(len(it) != 3 or not _b64decode_strict(it[2]) for it in items):
        return syntax

    # §10.3 SHOULD: n= nonce must not exceed 64 characters
    n_val = _extract_tag(value, "n")
    if n_val and len(n_val) > 64:
        return (f"PERMERROR: DKIM2-Signature i={i_val} n= nonce exceeds 64 "
                f"characters ({len(n_val)})")

    # -08 §10.9: the duplicate-selector check, then the local item limit.
    dup_errors = _check_signature_duplicates(items, i_val)
    return dup_errors[0] if dup_errors else None


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
    err = _sig_content_error(sig_hdr)
    if err:
        return [err]

    value = _get_header_value(sig_hdr)
    i_val = _extract_tag(value, "i")
    d_val = _extract_tag(value, "d")

    # -08 §14.3: not Fully Verified if t= is more than 14 days before now,
    # or more than one day after it.  After every §14.2 check of this field
    # and before any key lookup (contract C9: §14 section order).
    t_val = _extract_tag(value, "t")
    if not skip_timestamp_check:
        # 1*DIGIT (checked above).  int() refuses more than 4300 digits, and
        # any t= of 20 or more significant digits is far in the future.
        digits = t_val.lstrip("0") or "0"
        ts = int(digits) if len(digits) < 20 else 10 ** 20
        now = int(time.time())
        if ts > now + MAX_FUTURE:
            return [f"FAIL: DKIM2-Signature i={i_val} signature is from the future"]
        if now > ts + MAX_AGE:
            return [f"FAIL: DKIM2-Signature i={i_val} signature expired"]

    # Build the incomplete signature (the signed form) by blanking each s=
    # item's signature value in place, leaving selector:algorithm: and every
    # other tag untouched. One pass over the header (linear in its length).
    incomplete_sig = _blank_signature_values(sig_hdr)

    mi_version = _get_mi_from_sig(sig_hdr) or 0
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

    # -08 §14.5 and §14.6 as one step (contract D3, amending C9): every
    # sig-set, in s= order, gets its own result -- its key, then its
    # signature -- and then the "," lists and "|" groups are combined.  No
    # item is skipped, so the result does not depend on the order.
    who = f"DKIM2-Signature i={i_val}"
    groups = [[_sig_item_result(who, d_val, sel, alg, _b64decode_strict(val),
                                digest, dns_data)
               for sel, alg, val in group]
              for group in _sig_groups(_extract_tag(value, "s"))]
    err = _combine(groups, f"FAIL: {who} no group of signatures passed")
    return [err] if err else []


def _sig_item_result(who: str, d_val: str, selector: str, algorithm: str,
                     sig_bytes: bytes, digest: bytes, dns_data):
    """(state, error) for one sig-set (-08 §14.6 steps 3-4, contract D3):
    an algorithm we have not implemented is a PERMERROR, and no key is
    fetched for it; a key that cannot be fetched or used gives its §14.5
    error; then PASS or FAIL on the signature itself."""
    if algorithm not in SIG_ALGS:
        return "permerror", f"PERMERROR: {who} selector {selector} algorithm unknown"
    try:
        public_key, key_type = lookup_public_key(d_val, selector, dns_data)
    except KeyRecordError as e:
        return "permerror", f"PERMERROR: {who} public key {selector} {e.what}"
    except DNSTempError:
        return "temperror", f"TEMPERROR: {who} public key {selector} could not be fetched"
    except KeyError:
        return "permerror", f"PERMERROR: {who} public key {selector} does not exist"
    if SIG_ALGS[algorithm] != key_type:
        return "permerror", f"PERMERROR: {who} public key {selector} algorithm mismatch"
    try:
        if key_type == "ed25519":
            public_key.verify(sig_bytes, digest)
        else:
            public_key.verify(sig_bytes, digest, padding.PKCS1v15(),
                              utils.Prehashed(hashes.SHA256()))
    except Exception:
        return "fail", f"FAIL: {who} selector {selector} incorrect signature"
    return "pass", None


@dataclass
class VerifyResult:
    ok: bool                      # True iff verification passed
    status: str                   # 'pass', 'fail', 'permerror', 'temperror', 'none'
    failing_i: int | None         # i= of the signature that failed, None on pass
    domain: str | None            # d= of the failing/passing signature
    message: str                  # one-line human-readable summary
    errors: list[str] = field(default_factory=list)  # all error detail strings
    # -08 §13 (contract D9): a pass that checked everything.  False for any
    # result but pass, for a pass over a null body Recipe at some m=k >= 2
    # (the body hashes below it cannot be checked), for headers_only (no
    # body checked on purpose), and for an outbound pass over an instance
    # no signature covers yet.
    fully_verified: bool = False


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
        m = re.search(r'\bi=(\d{1,9})\b', err)
        if m:
            return int(m.group(1))
    return None


# Contract C9: the -08 §14 section each error string from the signature
# checks belongs to (§14.3 to §14.8; the §14.2 content of every signature
# has passed before any of them run).  §14.5 and §14.6 are one step per
# signature since -08 (contract D3 amends C9), ranked as "5".
_C9_SECTIONS = (
    (3, re.compile(r" signature (?:expired|is from the future)$")),
    (4, re.compile(r" unexpected nd= tag| nd= does not match$| does not match the rt= of i="
                   r"| MAIL FROM and d= do not match$| (?:MAIL FROM|RCPT TO) .* did not match$")),
    (5, re.compile(r"^TEMPERROR: | public key | selector \S+ (?:incorrect signature"
                   r"|algorithm unknown)$| no group of signatures passed$")),
    (8, re.compile(r" matching From is not authentic$")),
)
_C9_BY_NUMBER = {3, 5, 8}


def _c9_key(err: str):
    """Sort key for contract C9: §14 section order; within §14.3, §14.5+6
    and §14.8 (checks made per signature) the lowest i= first.  §14.4
    keeps the order C4 walks the chain in (unexpected nd=, the envelope,
    then each signature up from i=1)."""
    for section, rx in _C9_SECTIONS:
        if rx.search(err):
            if section in _C9_BY_NUMBER:
                m = re.search(r"\bi=(\d{1,9})\b", err)
                return (section, int(m.group(1)) if m else 0)
            return (section, 0)
    return (2, 0)


def _primary_first(errors: list[str]) -> list[str]:
    """`errors` in contract C9 order: the first is the PRIMARY error, whose
    state is the result.  Stable, so ties keep the order found."""
    return sorted(errors, key=_c9_key)


def _make_result(errors: list[str], top_sig_i: int,
                 top_domain: str) -> VerifyResult:
    """The result for `errors`, already in C9 order (the first is primary)."""
    if not errors:
        return VerifyResult(
            ok=True, status='pass', failing_i=None, domain=top_domain,
            message=f'pass: DKIM2-Signature i={top_sig_i} d={top_domain}',
            errors=[], fully_verified=True,
        )
    status = _classify_status(errors)
    failing_i = _extract_failing_i(errors)
    return VerifyResult(
        ok=False, status=status, failing_i=failing_i,
        domain=top_domain if failing_i == top_sig_i else None,
        message=errors[0], errors=errors,
    )


def _permerror(msg: str) -> VerifyResult:
    return VerifyResult(ok=False, status='permerror', failing_i=None,
                        domain=None, message=msg, errors=[msg])


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
    """What the header-field checks leave for the chain walk and the
    signature checks."""
    mi_headers: list[str]
    sig_headers: list[str]
    top_sig: str | None
    content_headers: list[bytes]
    keys: object


def _message_keys(dns_data):
    """The key source for one message: a dns.json dict as it is, a live
    source's per-message view (which prefetches)."""
    return dns_data.for_message() if hasattr(dns_data, "for_message") else dns_data


# At most this many keys are prefetched per message, so a message naming
# many cannot fan out into many lookups; any other key is looked up the
# ordinary way if it is ever needed.
PREFETCH_MAX = 8


def _key_names(sig_headers: list[str]) -> list[str]:
    """The distinct selector._domainkey.domain names to prefetch: the
    signatures' from the top (highest i=) down, implemented algorithms
    only, at most PREFETCH_MAX."""
    names = []
    for h in sorted(sig_headers, key=_get_seq_from_sig, reverse=True):
        value = _get_header_value(h)
        d_val = _extract_tag(value, "d")
        s_tag = _extract_tag(value, "s")
        if not d_val or not s_tag:
            continue
        for parts in _sig_items(s_tag):
            if len(parts) == 3 and parts[1] in SIG_ALGS:
                name = f"{parts[0]}._domainkey.{d_val}".lower()
                if name not in names:
                    names.append(name)
                    if len(names) == PREFETCH_MAX:
                        return names
    return names


def _duplicate_number_error(field: str, tag: str, numbers: list[int]) -> str | None:
    """A chain number given by more than one field: the LOWEST such number
    (contract C9), not the first met."""
    seen, twice = set(), set()
    for n in numbers:
        (twice if n in seen else seen).add(n)
    if twice:
        return f"PERMERROR: {field} {tag}={min(twice)} appears more than once"
    return None


def _structure_error(mi_headers: list[str], sig_headers: list[str],
                     o: _Options) -> str | None:
    """-07 §14.2 structure: what the field names and their m=/i= numbers
    alone decide, in contract C9's fixed sequence (a..h), so every verifier
    names the same fault first.  a..e decide which fields are in the chain
    at all, so they come before the gaps and the coverage (f..h) worked out
    from those fields.  None if the chain's shape is sound."""
    # a: more fields than a chain may have hops.
    for name, hdrs in (("Message-Instance", mi_headers),
                       ("DKIM2-Signature", sig_headers)):
        if len(hdrs) > MAX_CHAIN_LENGTH:
            return f"PERMERROR: more than {MAX_CHAIN_LENGTH} {name} fields"

    # b: a Message-Instance with no usable m=, top down.
    for h in mi_headers:
        m_val = _extract_tag(_get_header_value(h), "m")
        if m_val is None:
            return "PERMERROR: Message-Instance m= tag=m missing"
        err = chain_number_error("Message-Instance", "m", m_val)
        if err:
            return err

    # c: an m= given twice.
    have_m = [_get_version_from_mi(h) for h in mi_headers]
    err = _duplicate_number_error("Message-Instance", "m", have_m)
    if err:
        return err

    # d: a DKIM2-Signature with no usable i= (or an i=/m= out of range), top
    # down.  It cannot be placed in the chain or keyed, and is never
    # silently skipped: a signer gate counting "coverage" by m= must not be
    # fooled by a junk signature that names an m= but signs nothing.  A
    # missing m= is the field's own content, reported later.
    for h in sig_headers:
        value = _get_header_value(h)
        i_val = _extract_tag(value, "i")
        if i_val is None:
            return "PERMERROR: DKIM2-Signature i= tag=i missing"
        err = (chain_number_error("DKIM2-Signature", "i", i_val)
               or chain_number_error("DKIM2-Signature", "m",
                                     _extract_tag(value, "m"), i_val))
        if err:
            return err

    # e: an i= given twice.
    have_i = [_get_seq_from_sig(h) for h in sig_headers]
    err = _duplicate_number_error("DKIM2-Signature", "i", have_i)
    if err:
        return err

    # f: -07 §9.1, every instance from m=1 up to the highest there is, or
    # the highest the top signature covers (one naming an absent instance
    # is the same gap).
    top_m = (_get_mi_from_sig(max(sig_headers, key=_get_seq_from_sig)) or 0
             if sig_headers else 0)
    for n in range(1, max(have_m + [top_m]) + 1):
        if n not in have_m:
            return f"PERMERROR: Message-Instance m={n} missing"

    # g: an instance above every signature's m= is one nothing vouches for.
    # Not for an outbound signer (allow_unsigned_mi): it holds the instance
    # it is about to sign.
    if have_m and not o.allow_unsigned_mi:
        signed = max((_get_mi_from_sig(h) or 0 for h in sig_headers), default=0)
        if max(have_m) > signed:
            return f"PERMERROR: Message-Instance m={max(have_m)} is not signed"

    # h: every signature from i=1 up to the highest.
    for n in range(1, max(have_i, default=0) + 1):
        if n not in have_i:
            return f"PERMERROR: DKIM2-Signature i={n} missing"
    return None


def _check_headers(headers: list[bytes], o: _Options):
    """Every check that needs only the header fields and comes before the
    chain walk (contract C9: §14.2 structure, then each Message-Instance's
    content by ascending m=): a VerifyResult if one of them settles the
    verdict, else a _Context for the rest."""
    mi_headers = extract_mi_headers(headers)
    sig_headers = extract_sig_headers(headers)

    err = _structure_error(mi_headers, sig_headers, o)
    if err:
        return _permerror(err)
    if not sig_headers and not mi_headers:
        # No DKIM2 header fields at all: result "none", with no error.
        return VerifyResult(ok=False, status='none', failing_i=None, domain=None,
                            message='no DKIM2 header fields', errors=[])

    content = [e for e in map(_mi_content_error,
                              sorted(mi_headers, key=_get_version_from_mi)) if e]
    if content:
        return VerifyResult(ok=False, status='permerror', failing_i=None,
                            domain=None, message=content[0], errors=content)

    top_sig = max(sig_headers, key=_get_seq_from_sig) if sig_headers else None
    content_headers = [h for h in headers if _header_name(h)
                       not in (b"message-instance", b"dkim2-signature")]
    # Start fetching every public key now, while the body arrives (a no-op
    # for a dns.json source).  No key is used, nor any key error reported,
    # until the chain walk has passed (contract C9).
    keys = _message_keys(o.dns_data)
    if hasattr(keys, "prefetch"):
        keys.prefetch(_key_names(sig_headers))
    return _Context(mi_headers, sig_headers, top_sig, content_headers, keys)


def _envelope_errors(top_sig: str, o: _Options) -> list[str]:
    """-07 §14.4: the top signature's nd= and its mf=/rt= against the
    envelope, in the order C4 walks them.

    Local policy: the top (highest-i=) DKIM2-Signature MUST NOT carry nd=.
    nd= only ever legitimately appears together with a subsequent, higher-i=
    signature that takes over custody; a top-of-chain nd= means the chain is
    incomplete/tampered.  An outbound signer (allow_unsigned_mi) is the next
    hop, so it is not checked there.

    MAIL FROM / RCPT TO are an exact match against the top signature's
    declared mf=/rt=, domains lowercased, local-part case-sensitive.  rt=
    MAY carry extra recipients beyond what was actually delivered; every
    delivered RCPT TO must be present in the set."""
    errors = []
    value = _get_header_value(top_sig)
    top_i = _extract_tag(value, "i")
    if _extract_tag(value, "nd") and not o.allow_unsigned_mi:
        errors.append(f"FAIL: DKIM2-Signature i={top_i} unexpected nd= tag")
    mf_raw = _extract_tag(value, "mf")
    top_mf = _decode_path(mf_raw) if mf_raw else None
    rt_raw = _extract_tag(value, "rt")
    top_rts = [_decode_path(rt) for rt in (rt_raw.split(",") if rt_raw else [])
               if rt.strip()]
    if o.mail_from is not None:
        if top_mf is None or not _envelope_addr_equal(o.mail_from, top_mf):
            errors.append(
                f"FAIL: DKIM2-Signature i={top_i} MAIL FROM {o.mail_from} did not match")
    for rcpt in (o.rcpt_to or []):
        if not any(_envelope_addr_equal(rcpt, rt) for rt in top_rts):
            errors.append(
                f"FAIL: DKIM2-Signature i={top_i} RCPT TO {rcpt} did not match")
    return errors


def _signature_errors(ctx: _Context, mi_by_version: dict[int, str],
                      o: _Options) -> list[str]:
    """Everything after a chain walk that passed, in contract C9 order: each
    DKIM2-Signature's §14.2 content by ascending i=, then §14.3 timestamps,
    §14.4 custody, §14.5 keys, §14.6 signatures and §14.8 From, ranked."""
    sig_by_seq = sorted(ctx.sig_headers, key=_get_seq_from_sig)
    content = [e for e in map(_sig_content_error, sig_by_seq) if e]
    if content or not sig_by_seq:
        return content

    # -07 §7.1, §14.4: the envelope, then the Chain of Custody
    errors = _envelope_errors(ctx.top_sig, o) + _chain_custody_errors(sig_by_seq)
    for idx, sig_hdr in enumerate(sig_by_seq):
        errs = verify_dkim2_signature(sig_hdr, ctx.mi_headers, sig_by_seq[:idx],
                                      ctx.keys, o.skip_timestamp_check)
        errors.extend(errs)
        if not errs and o.verbose:
            print(f"  DKIM2-Signature i={_get_seq_from_sig(sig_hdr)}: OK",
                  file=sys.stderr)
    # -07 §11, §14.8: every From the chain shows is Authentic
    errors.extend(_from_authentic_errors(ctx.content_headers,
                                         mi_by_version, sig_by_seq))
    return _primary_first(errors)


def _result(ctx: _Context, errors: list[str], o: _Options) -> VerifyResult:
    top_sig = ctx.top_sig
    top_sig_i = _get_seq_from_sig(top_sig) if top_sig else 0
    top_domain = (_extract_tag(_get_header_value(top_sig), 'd') or '') if top_sig else ''
    result = _make_result(errors, top_sig_i, top_domain)
    if o.headers_only:
        result.fully_verified = False
    elif result.ok and o.allow_unsigned_mi:
        signed = _get_mi_from_sig(top_sig) or 0 if top_sig else 0
        if any(_get_version_from_mi(h) > signed for h in ctx.mi_headers):
            result.fully_verified = False
    return result


def _verify_simple(ctx: _Context, body: bytes, o: _Options) -> VerifyResult:
    """Simple mode: check every MI against the current message, highest m=
    first (or, with headers_only, the top MI's header hash), then every
    signature."""
    mi_by_version, versions = _walk_order(ctx)
    if o.headers_only and versions:
        errors = _mi_hash_errors(mi_by_version[versions[0]],
                                 lambda alg: compute_header_hash(ctx.content_headers, alg),
                                 None, headers_only=True)
    else:
        errors = []
        for version in versions:
            errors.extend(_mi_hash_errors(
                mi_by_version[version],
                lambda alg: compute_header_hash(ctx.content_headers, alg),
                lambda alg: compute_body_hash(body, alg)))
    if not errors:
        errors = _signature_errors(ctx, mi_by_version, o)
    return _result(ctx, errors, o)


class _UndoWalk:
    """The reference walk: rebuild each previous message from the Recipes."""

    def __init__(self, content_headers: list[bytes], body: bytes):
        self.headers = list(content_headers)
        self.body = body

    def mi_errors(self, version, mi_hdr, headers_only):
        return _mi_hash_errors(
            mi_hdr, lambda alg: compute_header_hash(self.headers, alg),
            lambda alg: compute_body_hash(self.body, alg), headers_only)

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
        return _mi_hash_errors(
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


def _walk_errors(ctx: _Context, walk, o: _Options,
                 mi_by_version: dict[int, str], versions: list[int]):
    """-07 §14.7, the chain walk: each instance from the top down, checked
    against the message as `walk` says it was then, and its Recipes undone
    to give the one below.  Returns (errors in walk order, the m= below
    which bodies were not checked or None).  A lower instance is rebuilt
    from the one above it, so the first error is the highest instance's."""
    errors = []
    verbose = o.verbose

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
            errors.extend(errs)
        elif verbose:
            print(f"  MI v={version} hashes: OK", file=sys.stderr)

        if version == versions[-1]:
            break
        # Every r= decodes and keeps the §5 schema (_mi_content_error has
        # passed), so what can still go wrong is a Recipe that does not fit
        # the message: a "c" range past the items present.  That is reported
        # as invalid JSON (-07 §14.2: it breaks the schema), ranked here, after
        # this instance's own hashes.  The reconstruction stops: the lower
        # instances cannot be checked against a state we could not rebuild.
        try:
            recipes = decode_recipes(mi_hdr)
        except (ValueError, TypeError):
            recipes = None
        if recipes is None:
            continue
        null_h, h_recipes, null_b, b_recipes = recipe_actions(recipes)

        def _malformed(e):
            errors.append(_malformed_recipe_error(version))
            if verbose:
                print(f"  Malformed Recipe in m={version}: {e}", file=sys.stderr)

        # draft -07 §5.1: a present "h" that is JSON null (the null header
        # Recipe) is not allowed; validate_recipes() has already refused it.
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
    return errors, body_unchecked_below


def _verify_chain(ctx: _Context, walk, o: _Options) -> VerifyResult:
    """Full chain validation: the chain walk, then (only if it passes, so no
    key is fetched for instances that do not describe the message) every
    signature (contract C9)."""
    mi_by_version, versions = _walk_order(ctx)
    errors, body_unchecked_below = _walk_errors(ctx, walk, o, mi_by_version,
                                                versions)
    if not errors:
        errors = _signature_errors(ctx, mi_by_version, o)
    result = _result(ctx, errors, o)
    if result.ok and body_unchecked_below is not None:
        # -08 §13 (contract D9): the result stays PASS, but not Fully Verified.
        result.fully_verified = False
        result.message += (f" (body not checked below m={body_unchecked_below}: "
                           f"null body Recipe; not fully verified)")
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
    them arrives; the keys are used only once the chain walk has passed, at
    close().  In full-chain mode the planned walk (dkim2plan) hashes
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
                first = re.split(r"[,|]", s_tag)[0].split(":", 2)
                if len(first) >= 2:  # (the first item of the first group)
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
