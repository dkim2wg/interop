#!/usr/bin/env python3
"""DKIM2 DSN propagation (draft-ietf-dkim-dkim2-spec-05 §12.1.1, RFC 3462).

When a Forwarder receives a DKIM2-signed Delivery Status Notification for a
message it forwarded, it may propagate that DSN back towards the original
sender. The propagated DSN is a *new* message: the Forwarder rebuilds the
enclosed original to the state it was in when forwarded outward (undoing its
own Message-Instance modification and removing the DKIM2-Signature and
Message-Instance it added), then re-signs the whole DSN with MAIL FROM <> so
that it carries exactly one Message-Instance and one DKIM2-Signature.
"""

import base64
import email
import sys
from email import policy

import dkim2sign
import dkim2undo


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


def propagate(raw: bytes, forwarder_domain: str, keyfile: str,
              selector: str, domain: str, timestamp: int = None) -> dict:
    """Propagate a received DSN upstream. Returns {raw, upstream_mailfrom}."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    dsn = email.message_from_bytes(raw, policy=policy.compat32)
    ct = dsn.get_content_type()
    if ct != "multipart/report":
        raise ValueError(f"not a multipart/report DSN (got {ct})")

    parts = dsn.get_payload()
    if not isinstance(parts, list) or len(parts) < 3:
        raise ValueError("DSN must have at least three parts")

    # RFC 3462 defines the multipart/report structure as exactly three parts:
    # (1) a human-readable text part, (2) a message/delivery-status part, and
    # (3) the returned message or its headers. Validate all three are present
    # rather than just counting parts.
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
    ap.add_argument("--forwarder-domain", required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--selector", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    out = propagate(sys.stdin.buffer.read(), args.forwarder_domain,
                    args.key, args.selector, args.domain)
    sys.stderr.write(f"upstream: {out['upstream_mailfrom']}\n")
    sys.stdout.buffer.write(out["raw"])


if __name__ == "__main__":
    main()
