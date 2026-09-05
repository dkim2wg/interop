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
    """Remove the Forwarder's hop from raw: the highest-sequence
    DKIM2-Signature, and then any nd= signature left on top, since a §9.3
    bridge belongs to the hop it was made for and an nd= signature is never
    valid as the top of a chain."""
    headers, body = dkim2sign.parse_message(raw)
    sig_idx = [i for i, h in enumerate(headers)
               if dkim2sign._header_name(h) == b"dkim2-signature"]
    if not sig_idx:
        return raw
    ordered = sorted(sig_idx,
                     key=lambda i: dkim2sign._get_seq_from_sig(
                         headers[i].decode("utf-8", "surrogateescape")))
    drop = {ordered.pop()}
    while ordered:
        val = _hval(headers[ordered[-1]].decode("utf-8", "surrogateescape"))
        if not dkim2sign._extract_tag(val, "nd"):
            break
        drop.add(ordered.pop())
    kept = [h for j, h in enumerate(headers) if j not in drop]
    # parse_message() returns each field WITHOUT its trailing CRLF, so the
    # fields have to be rejoined with one and the header block terminated with
    # the blank line. (Reachable for the first time via a §9.3 bridge: until
    # then every message that got here had two Message-Instances and was
    # rebuilt by undo_message_instance instead.)
    return b"\r\n".join(kept) + b"\r\n\r\n" + body


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


def _origin_sig_tags(raw: bytes) -> dict | None:
    """Like _top_sig_tags but for the LOWEST-i DKIM2-Signature.

    For a DSN that is the signature of the system that generated it: §12.1.1
    makes a DSN a new message with exactly one signature, and if that DSN is
    itself forwarded onwards, i=1 is still its originator.
    """
    headers, _ = dkim2sign.parse_message(raw)
    sigs = [h.decode("utf-8", errors="surrogateescape") for h in headers
            if dkim2sign._header_name(h) == b"dkim2-signature"]
    if not sigs:
        return None
    bottom = _hval(min(sigs, key=dkim2sign._get_seq_from_sig))
    return {
        "i": int(dkim2sign._extract_tag(bottom, "i") or 0),
        "d": dkim2sign._extract_tag(bottom, "d") or "",
    }


def _check_alignment(dsn_sig: dict | None, orig_top: dict | None):
    """spec-06 §12.1.2 point 1: "The DSN's DKIM2-Signature will have a signing
    domain that is aligned with the recipient of the message that is being
    returned. The recipient's address is located in the rt= tag of the last
    (highest i= tag) DKIM2-Signature in the returned message."

    This is the check that says the bounce came from the place we handed the
    message to, and it is worth nothing unless the DSN's own signature has
    been verified -- anyone can write d=. authenticate() therefore verifies
    the DSN as well, and only compares the d= it has proved.

    Alignment is tested in BOTH directions: the spec's §9.4 relaxed match
    strips labels from the envelope-address domain (so d= may be a parent of
    it, e.g. a DSN signed by the org domain for mail delivered to a
    subdomain), while a receiving system that bounces from a dedicated
    subdomain has the opposite shape (d=bounces.example.com for
    rt=<user@example.com>). Both are the same organization by the only test
    DKIM2 has, and rejecting either would reject conformant mail; an
    unrelated domain still fails.

    Returns (state, detail) with state 'pass', 'fail' or 'none'.
    """
    if not dsn_sig:
        return "none", "DSN carries no DKIM2-Signature of its own"
    d = dsn_sig["d"]
    if not d:
        return "none", "DSN signature has no d="
    rts = [r for r in ((orig_top or {}).get("rt") or []) if r]
    if not rts:
        return "none", "returned message's top signature has no rt= to align with"
    for r in rts:
        rd = dkim2verify._domain_from_addr(r)
        if not rd:
            continue
        if (dkim2verify._relaxed_domain_match(rd, d)
                or dkim2verify._relaxed_domain_match(d, rd)):
            return "pass", f"DSN d={d} is aligned with rt= {r}"
    return "fail", (f"DSN d={d} is not aligned with the returned message's rt= "
                    f"({', '.join(rts)})")


def authenticate(raw: bytes, dns_data: dict,
                 skip_timestamp_check: bool = False) -> dict:
    """Authenticate an inbound DSN before propagating it (spec-06 §12.1.2).

      * the returned original's DKIM2 chain must verify, from its headers
        alone when the DSN carries only headers (point 3);
      * the DSN's own signature must verify, and its d= must be aligned with
        the rt= of the returned original's top signature -- i.e. the bounce
        came from the system the message was handed to (point 1);
      * deciding whether that top signature is one the CALLER made (d= and
        mf=) is left to the caller (point 2), since only it knows its own
        domains; `top` is reported for exactly that.

    A DSN that carries no DKIM2-Signature at all is not what §12.1.2 is about
    ("When a system receives a DKIM2 signed DSN"), so it is reported as
    dsn_status 'none' with alignment 'none' rather than failed.

    Returns {ok, status, message, errors, top, dsn_status, dsn_message,
    dsn_sig, alignment, alignment_detail, headers_only, embedded}.
    Raises ValueError, as propagate does, when this is not an RFC 6522 DSN.
    """
    _, parts, orig_idx = _parse_report(raw)
    headers_only = parts[orig_idx].get_content_type() == "text/rfc822-headers"
    embedded = _embedded_bytes(parts[orig_idx])

    res = dkim2verify.verify_message(
        embedded, dns_data, headers_only=headers_only,
        skip_timestamp_check=skip_timestamp_check)

    # The DSN itself, from the bytes as they arrived: re-serializing the
    # message we parsed could move a byte the body hash covers.
    dsn_res = dkim2verify.verify_message(
        raw, dns_data, skip_timestamp_check=skip_timestamp_check)
    dsn_sig = _origin_sig_tags(raw if isinstance(raw, bytes)
                               else raw.encode("utf-8", "surrogateescape"))
    top = _top_sig_tags(embedded)

    if dsn_res.status == "pass":
        alignment, alignment_detail = _check_alignment(dsn_sig, top)
    elif dsn_res.status == "none":
        alignment = "none"
        alignment_detail = "DSN carries no DKIM2-Signature of its own"
    else:
        alignment = "none"
        alignment_detail = "DSN's own signature did not verify"

    ok = (res.ok and dsn_res.status in ("pass", "none") and alignment != "fail")

    return {
        "ok": ok,
        "status": res.status,
        "message": res.message,
        "errors": res.errors,
        "top": top,
        "dsn_status": dsn_res.status,
        "dsn_message": dsn_res.message,
        "dsn_sig": dsn_sig,
        "alignment": alignment,
        "alignment_detail": alignment_detail,
        "headers_only": headers_only,
        "embedded": embedded,
    }


def propagate(raw: bytes, forwarder_domain: str, keyfile: str,
              selector: str, domain: str, timestamp: int = None,
              dns_data: dict = None, skip_authentication: bool = False,
              skip_timestamp_check: bool = False) -> dict:
    """Propagate a received DSN upstream. Returns {raw, upstream_mailfrom}.

    §12.1.2 is not optional here: "If the verification fails then the DSN MUST
    NOT be propagated any further", so the DSN is authenticated first and a
    ValueError raised rather than re-signing one that could not be
    authenticated. That needs dns_data; a caller that has authenticated
    already (or is exercising the rebuild machinery on a fixture, as
    tests/test_dsn.py does) passes skip_authentication=True to say so.
    """
    if not skip_authentication:
        if dns_data is None:
            raise ValueError(
                "propagate: need dns_data to authenticate the DSN (§12.1.2), or "
                "skip_authentication if it has been authenticated already")
        auth = authenticate(raw, dns_data,
                            skip_timestamp_check=skip_timestamp_check)
        if not auth["ok"]:
            why = (auth["alignment_detail"] if auth["alignment"] == "fail"
                   else auth["message"])
            raise ValueError(
                f"propagate: DSN did not authenticate (§12.1.2), not propagating: {why}")

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

    # 5/6. Re-sign the whole DSN as a NEW message: MAIL FROM <>, one MI, one
    #      sig. So the inbound DSN's OWN instance and signature go: they belong
    #      to the DSN we received, which has already been authenticated
    #      (§12.1.2) and is not being continued. Leaving them makes the new
    #      instance m=2 on a chain whose i=1 is somebody else's.
    del dsn["Message-Instance"]
    del dsn["DKIM2-Signature"]

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
    ap.add_argument("--dns", help="path to dns.json key file (required to authenticate)")
    ap.add_argument("--skip-authentication", action="store_true",
                    help="propagate without the §12.1.2 check (already done by the caller)")
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
        sys.stderr.write("DSN's own signature: {}{}\n".format(
            auth["dsn_status"],
            f" (i={auth['dsn_sig']['i']} d={auth['dsn_sig']['d']})" if auth["dsn_sig"] else ""))
        sys.stderr.write(f"alignment: {auth['alignment']} - {auth['alignment_detail']}\n")
        if not auth["ok"]:
            sys.stderr.write("FAIL: {}\n".format(
                auth["alignment_detail"] if auth["alignment"] == "fail" else auth["message"]))
            sys.exit(1)
        print("PASS: returned original verified")
        return

    for req in ("forwarder_domain", "domain", "selector", "key"):
        if not getattr(args, req):
            ap.error(f"--{req.replace('_', '-')} is required when propagating")
    if not args.dns and not args.skip_authentication:
        ap.error("propagating requires --dns to authenticate the DSN (§12.1.2), "
                 "or --skip-authentication")
    out = propagate(sys.stdin.buffer.read(), args.forwarder_domain,
                    args.key, args.selector, args.domain,
                    dns_data=dkim2verify.load_dns_json(args.dns) if args.dns else None,
                    skip_authentication=args.skip_authentication,
                    skip_timestamp_check=args.ignore_timestamps)
    sys.stderr.write(f"upstream: {out['upstream_mailfrom']}\n")
    sys.stdout.buffer.write(out["raw"])


if __name__ == "__main__":
    main()
