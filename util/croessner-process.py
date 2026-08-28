#!/usr/bin/env python3
"""POST one message to croessner/dkim2's dkim2d /v1/process and report its verdict.

Used by util/croessner-verify.sh. Kept separate from the shell runner because
his daemon speaks JSON over HTTP rather than taking a filename, so a peer
"verifier cell" needs base64, JSON and a capability header rather than a CLI
invocation like every other implementation in this repo.

Exit status: 0 when the daemon's disposition is `accept`, 1 for any other
disposition (including the 204 not-applicable case), 2 for a transport,
protocol or usage failure. That mirrors the other verifiers' shell contract,
where zero means the message verified.
"""

import argparse
import base64
import json
import re
import sys
import urllib.error
import urllib.request

# Both pinned rather than negotiated: the daemon rejects an api_version or
# draft it does not implement, and a silent downgrade would make this runner
# report agreement about a different protocol than the one under test.
API_VERSION = "v1"
DRAFT = "draft-ietf-dkim-dkim2-spec-06"

# The capability is 32 opaque bytes on disk, presented as unpadded base64url.
# Encoding it any other way earns a bare 403 with no diagnostic (his daemon is
# deliberately content-free on errors), so this is spelled out here to save
# the next person the same hour: cmd/dkim2ctl/internal/testclient/capability.go
# uses base64.RawURLEncoding.
CAPABILITY_HEADER = "X-DKIM2-Capability"
CAPABILITY_BYTES = 32


def unfold(raw):
    """Undo RFC 5322 folding so tag values can be read with one regex."""
    return re.sub(r"\r?\n[ \t]+", " ", raw.decode("utf-8", "replace"))


def derive_envelope(raw):
    """Recover the current hop's envelope from the top Message-Instance.

    §7.5/§7.6 put the hop's MAIL FROM in mf= and its RCPT TO in rt=, both
    base64 of the bracketed address. The highest i= is the most recent hop, so
    its pair is the envelope the message is travelling under right now -- which
    is what /v1/process wants. A single-hop message therefore yields exactly
    the envelope its signer was handed, and a forwarded chain yields the
    forwarder's, not the originator's.
    """
    best = None
    for line in re.findall(r"^DKIM2-Signature:(.*)$", unfold(raw), re.M):
        instance = re.search(r"\bi=(\d+)", line)
        mail_from = re.search(r"\bmf=([A-Za-z0-9+/=]+)", line)
        rcpt_to = re.search(r"\brt=([A-Za-z0-9+/=]+)", line)
        if not (instance and mail_from and rcpt_to):
            continue
        index = int(instance.group(1))
        if best is None or index > best[0]:
            best = (
                index,
                base64.b64decode(mail_from.group(1)).decode("utf-8", "replace"),
                base64.b64decode(rcpt_to.group(1)).decode("utf-8", "replace"),
            )
    if best is None:
        raise SystemExit("cannot derive envelope: no complete DKIM2-Signature mf=/rt= pair")
    return best[1], best[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", help="RFC 5322 message file (CRLF)")
    parser.add_argument("--url", required=True, help="daemon base URL, e.g. http://127.0.0.1:18080")
    parser.add_argument("--capability", required=True, help="path to the 32-byte capability file")
    parser.add_argument("--mail-from", help="envelope MAIL FROM; derived from the top instance if omitted")
    parser.add_argument("--rcpt-to", action="append", help="envelope RCPT TO, repeatable; derived if omitted")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    with open(args.message, "rb") as handle:
        raw = handle.read()
    with open(args.capability, "rb") as handle:
        capability = handle.read()
    if len(capability) != CAPABILITY_BYTES:
        print(f"capability file is {len(capability)} bytes, want {CAPABILITY_BYTES}", file=sys.stderr)
        return 2

    if args.mail_from is not None and args.rcpt_to:
        mail_from, rcpt_to = args.mail_from, args.rcpt_to
    else:
        derived_from, derived_to = derive_envelope(raw)
        mail_from = args.mail_from if args.mail_from is not None else derived_from
        rcpt_to = args.rcpt_to if args.rcpt_to else [derived_to]

    body = {
        "api_version": API_VERSION,
        "draft": DRAFT,
        "message": {
            "raw_rfc5322_base64": base64.b64encode(raw).decode("ascii"),
            "fidelity": "raw_rfc5322",
        },
        "smtp": {"mail_from": mail_from, "rcpt_to": rcpt_to},
    }
    request = urllib.request.Request(
        args.url.rstrip("/") + "/v1/process",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            CAPABILITY_HEADER: base64.urlsafe_b64encode(capability).decode("ascii").rstrip("="),
        },
    )
    # The daemon binds loopback only and refuses proxied requests; an inherited
    # http_proxy would turn every cell into an unexplained transport failure.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = response.status
            payload = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:200]
        print(f"HTTP {error.code} {detail}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"transport failure: {error}", file=sys.stderr)
        return 2

    if status == 204:
        # Both DKIM2 field families absent: the daemon declined to verify at
        # all. For this runner that is a failure, not a pass -- every message
        # we feed it is signed.
        print("disposition=not_applicable state=- reason=no-dkim2-fields")
        return 1

    result = json.loads(payload or b"{}")
    verification = result.get("verification", {})
    disposition = result.get("disposition", "-")
    print(
        f"disposition={disposition} "
        f"state={verification.get('state', '-')} "
        f"reason={verification.get('primary_reason', '-')}"
    )
    return 0 if disposition == "accept" else 1


if __name__ == "__main__":
    sys.exit(main())
