"""Address domains and the relaxed domain match (draft-ietf-dkim-dkim2-spec-07
§7.2, §18).

Shared by the signer (mf=/rt= are recorded with A-label domains, and the From
header field must be Authentic for the signing domain) and the verifier
(Chain of Custody, §14.4, and Authentic From, §14.8).
"""

import email.policy
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


def from_is_authentic(from_fields: list[bytes], d: str) -> bool:
    """-07 §11: is the From header field Authentic for signing domain d?

    `from_fields` are the raw From fields of one state of the message.
    There must be exactly one, holding exactly one mailbox (a display name
    and angle-addr, or a bare addr-spec; the stdlib address parser, used
    leniently, but display text with no angle brackets, "Name a@b", is not
    a mailbox), not a group, whose domain is not a domain literal and
    relaxed-matches d (§7.2) once both are A-labels (§18).
    """
    if len(from_fields) != 1:
        return False
    raw = from_fields[0]
    value = raw[raw.find(b":") + 1:].replace(b"\r\n", b"")
    try:
        header = email.policy.default.header_factory(
            "from", value.decode("utf-8", errors="surrogateescape"))
        groups = header.groups
        if (len(groups) != 1 or groups[0].display_name is not None
                or len(groups[0].addresses) != 1):
            return False
        domain = groups[0].addresses[0].domain
        # Unquoted words with no "." between them in the local part:
        # "Name a@b" (display text without the angle brackets) is not one
        # mailbox, though the parser reads it as local-part "Name a".
        if any("missing '.' between words" in str(e) for e in header.defects):
            return False
    except Exception:       # anything the parser cannot make sense of
        return False
    domain = (domain or "").strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain or domain.startswith("["):
        return False
    return relaxed_match(to_alabel(domain), signing_domain(d))
