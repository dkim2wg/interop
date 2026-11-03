"""Address domains and the relaxed domain match (draft-ietf-dkim-dkim2-spec-09
§7.2, §18).

Shared by the signer (mf=/rt= are recorded with A-label domains, and the From
header field must be Authentic for the signing domain) and the verifier
(Chain of Custody, §14.4, and Authentic From, §14.8).
"""

import email.policy
import re
import encodings.idna


def domain_of(addr: str) -> tuple[str, bool]:
    """The domain of an address: (domain, is_literal).

    The text between the last '@' and the closing '>' (if any), lowercased,
    with one trailing dot removed (Postfix writes <a@example.com.>).  A
    domain literal (it starts with '[') is returned marked as one.  An
    address with no '@' (the null path <>) has the empty domain, which
    matches nothing.
    """
    addr = addr.strip()
    if addr.endswith(">"):
        addr = addr[:-1]
    at = addr.rfind("@")
    if at < 0:
        return "", False
    domain = addr[at + 1:].strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    return domain, domain.startswith("[")


def to_alabel(domain: str) -> str:
    """The domain with every non-ASCII label as its A-label (§18).

    Each label containing non-ASCII is lowercased and run through the stdlib
    IDNA ToASCII ("xn--" + Punycode); ASCII labels are lowercased.  No full
    UTS-46 mapping.  A label ToASCII rejects is left as it is (so it cannot
    match any ASCII signing domain).
    """
    labels = []
    for label in domain.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        try:
            labels.append(encodings.idna.ToASCII(label.lower()).decode("ascii"))
        except UnicodeError:
            labels.append(label.lower())
    return ".".join(labels)


def relaxed_match(p1: str, p2: str) -> bool:
    """§7.2 relaxed domain match of Parameter1 against Parameter2.

    Labels are removed from the left of p1 only, until it equals p2 (match)
    or has no dot left (no match).  A domain literal never matches.  Both
    are compared as given: callers pass lowercased A-labels.
    """
    if p1.startswith("[") or p2.startswith("["):
        return False
    while True:
        if p1 == p2:
            return True
        dot = p1.find(".")
        if dot < 0:
            return False
        p1 = p1[dot + 1:]


def addr_domain(addr: str) -> str | None:
    """domain_of() as a lowercased A-label, or None for a domain literal."""
    domain, literal = domain_of(addr)
    return None if literal else to_alabel(domain)


def signing_domain(d: str) -> str:
    """A d= or nd= value in the form relaxed_match() compares."""
    d = d.strip().lower()
    return to_alabel(d[:-1] if d.endswith(".") else d)


def _comma_outside_quotes(value: str) -> bool:
    """Does an address-list value hold a "," outside quoted-strings and
    comments?  (One pass: quoted-pairs are skipped, comments nest.)"""
    depth = 0           # comment nesting
    quoted = False
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == "\\":
            i += 2
            continue
        if quoted:
            if c == '"':
                quoted = False
        elif depth:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
        elif c == '"':
            quoted = True
        elif c == "(":
            depth = 1
        elif c == ",":
            return True
        i += 1
    return False


# from_mailbox() kinds.
FROM_OK = "ok"                  # one mailbox; the domain is returned
FROM_MANY = "many"              # more than one address (or From field)
FROM_LITERAL = "literal"        # one mailbox at a domain literal
FROM_NONE = "none"              # no From, or not a mailbox at all


def from_mailbox(from_fields: list[bytes]) -> tuple[str, str | None]:
    """-09 §11, §14.8 (contract E3.1 steps 1-2): classify the From header
    fields of one state of the message.  Returns (kind, domain):

    - FROM_MANY: more than one From field, or a value with a "," outside
      quotes and comments (a list of addresses, or a group of several);
    - FROM_NONE: no From field, a group without a ",", a value with no
      "@", or one that is not a mailbox (the stdlib address parser, used
      leniently, but display text with no angle brackets, "Name a@b", is
      not a mailbox);
    - FROM_LITERAL: one mailbox whose domain is a domain literal;
    - FROM_OK: one mailbox; domain is its lowercased A-label (§18), with
      no trailing dot.
    """
    if len(from_fields) > 1:
        return FROM_MANY, None
    if not from_fields:
        return FROM_NONE, None
    raw = from_fields[0]
    value = raw[raw.find(b":") + 1:].replace(b"\r\n", b"")
    text = value.decode("utf-8", errors="surrogateescape")
    if _comma_outside_quotes(text):
        return FROM_MANY, None
    if "@" not in text:
        return FROM_NONE, None
    # Contract C3 (2026-10-18 design): one trailing dot on the domain is dropped, as for
    # mf=/rt=. The stdlib parser rejects "a@b.example." outright, so it is
    # taken off first: the dot just before the closing ">" or the end.
    text = re.sub(r"(@[^@\s<>]*[^.\s<>@])\.(?=\s*>?\s*\Z)", r"\1", text, count=1)
    try:
        header = email.policy.default.header_factory("from", text)
        groups = header.groups
        if (len(groups) != 1 or groups[0].display_name is not None
                or len(groups[0].addresses) != 1):
            return FROM_NONE, None
        domain = groups[0].addresses[0].domain
        # Unquoted words with no "." between them in the local part:
        # "Name a@b" (display text without the angle brackets) is not one
        # mailbox, though the parser reads it as local-part "Name a".
        if any("missing '.' between words" in str(e) for e in header.defects):
            return FROM_NONE, None
    except Exception:       # anything the parser cannot make sense of
        return FROM_NONE, None
    domain = (domain or "").strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain:
        return FROM_NONE, None
    if domain.startswith("["):
        return FROM_LITERAL, None
    return FROM_OK, to_alabel(domain)


def from_is_authentic(from_fields: list[bytes], d: str) -> bool:
    """-09 §11, downward only: is the From header field Authentic for
    signing domain d with no Domain Policy Record lookup?  Exactly one
    mailbox (from_mailbox), not at a domain literal, whose domain
    relaxed-matches d (§7.2) once both are A-labels (§18).

    Signers use this (§12.4: downward is always valid); the verifier adds
    the upward match and the policy lookup (dkim2verify)."""
    kind, domain = from_mailbox(from_fields)
    return kind == FROM_OK and relaxed_match(domain, signing_domain(d))
