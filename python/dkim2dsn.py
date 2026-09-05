#!/usr/bin/env python3
"""DKIM2 DSN handling (draft-ietf-dkim-dkim2-spec-06 §12.1, RFC 6522).

When a Forwarder receives a DKIM2-signed Delivery Status Notification for a
message it forwarded, it may propagate that DSN back towards the original
sender. The propagated DSN is a *new* message: the Forwarder rebuilds the
enclosed original to the state it was in when forwarded outward (undoing its
own Message-Instance modification and removing the DKIM2-Signature and
Message-Instance it added), then re-signs the whole DSN with MAIL FROM <> so
that it carries exactly one Message-Instance and one DKIM2-Signature (§12.1.1).

Before propagating, a Forwarder should authenticate the DSN: the returned
original must be one it sent and unaltered, checked from the header fields
alone when that is all the DSN carries (§12.1.2).
"""

import base64
import email
import sys
from email import policy

import dkim2sign
import dkim2undo
import dkim2verify


def _hval(hdr_str: str) -> str:
    """Return the value of a 'Name: value' header string."""
    colon = hdr_str.find(":")
    return hdr_str[colon + 1:] if colon != -1 else hdr_str


def _highest_sig_mailfrom(raw: bytes):
    """Return (mailfrom, count) for the highest-i DKIM2-Signature in raw."""
    headers, _ = dkim2sign.parse_message(raw)
    sigs = []
    for hdr in headers:
        if dkim2sign._header_name(hdr) == b"dkim2-signature":
            sigs.append(hdr.decode("utf-8", errors="surrogateescape"))
    if not sigs:
        return None, 0
    top = max(sigs, key=dkim2sign._get_seq_from_sig)
    mf_b64 = dkim2sign._extract_tag(_hval(top), "mf")
    mf = base64.b64decode(mf_b64).decode("utf-8", "surrogateescape") if mf_b64 else None
    return mf, len(sigs)


def _strip_top_sig(raw: bytes) -> bytes:
    """Remove the single highest-sequence DKIM2-Signature header from raw."""
    headers, body = dkim2sign.parse_message(raw)
    sig_idx = [i for i, h in enumerate(headers)
               if dkim2sign._header_name(h) == b"dkim2-signature"]
    if not sig_idx:
        return raw
    top_i = max(sig_idx,
                key=lambda i: dkim2sign._get_seq_from_sig(
                    headers[i].decode("utf-8", "surrogateescape")))
    kept = [h for j, h in enumerate(headers) if j != top_i]
    return b"".join(kept) + b"\r\n" + body


def _embedded_bytes(part) -> bytes:
    payload = part.get_payload()
    if isinstance(payload, list) and payload:
        return payload[0].as_bytes()
    return part.get_payload(decode=True) or payload.encode("utf-8", "surrogateescape")


def _parse_report(raw: bytes):
    """Parse a raw DSN and validate its RFC 6522 multipart/report structure.

    RFC 6522 defines the structure as exactly three parts: (1) a human-readable
    text part, (2) a message/delivery-status part, and (3) the returned message
    or its headers. Validate all three are present rather than just counting
    parts -- a report with two text/plain parts and an embedded original would
    pass a ">= 3" check without being a valid DSN.

    Returns (dsn, parts, orig_idx); raises ValueError on anything else.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    dsn = email.message_from_bytes(raw, policy=policy.compat32)
    ct = dsn.get_content_type()
    if ct != "multipart/report":
        raise ValueError(f"not a multipart/report DSN (got {ct})")

    parts = dsn.get_payload()
    if not isinstance(parts, list) or len(parts) < 3:
        raise ValueError("DSN must have at least three parts")

    if parts[0].get_content_type() != "text/plain":
        raise ValueError("DSN part 1 must be human-readable text/plain")

    if not any(p.get_content_type() == "message/delivery-status" for p in parts):
        raise ValueError("DSN missing required message/delivery-status part")

    orig_idx = None
    for i, p in enumerate(parts):
        if p.get_content_type() in ("message/rfc822", "text/rfc822-headers"):
            orig_idx = i
            break
    if orig_idx is None:
        raise ValueError("no embedded original message part")

    return dsn, parts, orig_idx


def _top_sig_tags(raw: bytes) -> dict | None:
    """Return the decoded tags of the highest-i DKIM2-Signature in raw.

    {"i": int, "d": str, "mf": str|None, "rt": [str]} -- enough for a caller to
    apply spec-06 §12.1.2 point 2 and decide whether the signature is one of
    its own. None when the message carries no DKIM2-Signature.
    """
    headers, _ = dkim2sign.parse_message(raw)
    sigs = [h.decode("utf-8", errors="surrogateescape") for h in headers
            if dkim2sign._header_name(h) == b"dkim2-signature"]
    if not sigs:
        return None
    top = _hval(max(sigs, key=dkim2sign._get_seq_from_sig))

    def _b64(val):
        return base64.b64decode(val).decode("utf-8", "surrogateescape") if val else None

    rt_raw = dkim2sign._extract_tag(top, "rt") or ""
    return {
        "i": int(dkim2sign._extract_tag(top, "i") or 0),
        "d": dkim2sign._extract_tag(top, "d") or "",
        "mf": _b64(dkim2sign._extract_tag(top, "mf")),
        "rt": [_b64(r.strip()) for r in rt_raw.split(",") if r.strip()],
    }


def authenticate(raw: bytes, dns_data: dict,
                 skip_timestamp_check: bool = False) -> dict:
    """Authenticate an inbound DSN before propagating it (spec-06 §12.1.2).

    The returned original's DKIM2 chain must verify, from its headers alone
    when the DSN carries only headers. Deciding whether the top signature is
    one the caller made (d= and mf=) is the caller's, since only it knows its
    own domains; `top` is reported for exactly that.

    Returns {ok, status, message, errors, top, headers_only, embedded}.
    Raises ValueError, as propagate does, when this is not an RFC 6522 DSN.
    """
    _, parts, orig_idx = _parse_report(raw)
    headers_only = parts[orig_idx].get_content_type() == "text/rfc822-headers"
    embedded = _embedded_bytes(parts[orig_idx])

    res = dkim2verify.verify_message(
        embedded, dns_data, headers_only=headers_only,
        skip_timestamp_check=skip_timestamp_check)

    return {
        "ok": res.ok,
        "status": res.status,
        "message": res.message,
        "errors": res.errors,
        "top": _top_sig_tags(embedded),
        "headers_only": headers_only,
        "embedded": embedded,
    }


def propagate(raw: bytes, forwarder_domain: str, keyfile: str,
              selector: str, domain: str, timestamp: int = None) -> dict:
    """Propagate a received DSN upstream. Returns {raw, upstream_mailfrom}."""
    dsn, parts, orig_idx = _parse_report(raw)

    headers_only = parts[orig_idx].get_content_type() == "text/rfc822-headers"
    embedded = _embedded_bytes(parts[orig_idx])

    # 1. Undo the Forwarder's outward modification. undo_message_instance both
    #    reconstructs the prior version AND drops the signatures that cover the
    #    removed MI (m > target) — i.e. it already removes the DKIM2-Signature
    #    the Forwarder added. Only when there is no MI to undo do we strip the
    #    Forwarder's signature by hand.
    mi_count, _ = _count_mi(embedded)
    stripped_by_undo = False
    if mi_count >= 2:
        try:
            embedded = dkim2undo.undo_message_instance(embedded)
            stripped_by_undo = True
        except ValueError:
            # body could not be regenerated — fall back to headers-only
            headers_only = True
    if not stripped_by_undo:
        embedded = _strip_top_sig(embedded)

    # 3. The propagated DSN is addressed to the MAIL FROM of the now-highest
    #    DKIM2-Signature.
    upstream, _ = _highest_sig_mailfrom(embedded)
    if not upstream:
        raise ValueError("no remaining DKIM2-Signature to derive upstream MAIL FROM")

    # 4. Rebuild the embedded part (headers-only fallback strips the body).
    new_inner = email.message_from_bytes(embedded, policy=policy.compat32)
    if headers_only:
        hdr_text = "".join(f"{k}: {v}\r\n" for k, v in new_inner.items())
        rebuilt = email.message_from_string("")
        rebuilt.set_type("text/rfc822-headers")
        rebuilt.set_payload(hdr_text)
        parts[orig_idx] = rebuilt
    else:
        parts[orig_idx].set_payload([new_inner])

    dsn.set_payload(parts)

    # 5/6. Re-sign the whole DSN as a NEW message: MAIL FROM <>, one MI, one sig.
    propagated = dkim2sign.sign_message(
        dsn.as_bytes(), selector, domain, keyfile,
        mailfrom="<>", rcptto=[upstream], timestamp=timestamp)
    return {"raw": propagated, "upstream_mailfrom": upstream}


def _count_mi(raw: bytes):
    headers, _ = dkim2sign.parse_message(raw)
    mis = [h for h in headers if dkim2sign._header_name(h) == b"message-instance"]
    return len(mis), mis


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Propagate a DKIM2 DSN upstream")
    ap.add_argument("--forwarder-domain")
    ap.add_argument("--domain")
    ap.add_argument("--selector")
    ap.add_argument("--key")
    ap.add_argument("--authenticate", action="store_true",
                    help="§12.1.2: check the returned original instead of propagating")
    ap.add_argument("--dns", help="path to dns.json key file (required with --authenticate)")
    ap.add_argument("--ignore-timestamps", action="store_true",
                    help="disable the §10.3 timestamp (14-day/future) check")
    args = ap.parse_args()

    if args.authenticate:
        if not args.dns:
            ap.error("--authenticate requires --dns")
        # Report the top signature's d= and mf= so the caller can apply
        # §12.1.2 point 2 -- deciding whether that signature is one of its own
        # -- which only the system receiving the DSN can do.
        auth = authenticate(sys.stdin.buffer.read(),
                            dkim2verify.load_dns_json(args.dns),
                            skip_timestamp_check=args.ignore_timestamps)
        if auth["headers_only"]:
            sys.stderr.write("returned original: header fields only\n")
        if auth["top"]:
            sys.stderr.write("top signature: i={i} d={d} mf={mf}\n".format(**auth["top"]))
        if not auth["ok"]:
            sys.stderr.write(f"FAIL: {auth['message']}\n")
            sys.exit(1)
        print("PASS: returned original verified")
        return

    for req in ("forwarder_domain", "domain", "selector", "key"):
        if not getattr(args, req):
            ap.error(f"--{req.replace('_', '-')} is required when propagating")
    out = propagate(sys.stdin.buffer.read(), args.forwarder_domain,
                    args.key, args.selector, args.domain)
    sys.stderr.write(f"upstream: {out['upstream_mailfrom']}\n")
    sys.stdout.buffer.write(out["raw"])


if __name__ == "__main__":
    main()
