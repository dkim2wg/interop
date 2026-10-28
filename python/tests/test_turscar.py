#!/usr/bin/env python3
"""Conformance runner for the Turscar dkim2tests vectors (Steve Atkins).

Runs each vector in the git submodule at <repo>/dkim2tests directly (no import
into our tree) through our verifier and compares the resulting status to the
vector's ExpectedState.

The vectors are written against draft-02; the tag rules (case-insensitive
identifiers, any order, single occurrence, FWS) and the >=1024-bit key
requirement were unchanged up to draft-07; -08's strict-lowercase tags and
AND/OR groups are the KNOWN_DIVERGENCE entries below.

Run:  python3 tests/test_turscar.py     (exit 0 = all match)
Skips cleanly if the submodule is not checked out.
"""
import os
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dkim2verify as V  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS_DIR = os.path.join(REPO_ROOT, "dkim2tests", "tests")

# Upstream vectors we knowingly diverge from, with the reason.  These are not
# counted as failures.
# dkim2tests a382236 fixed tags_whitespace (it had an empty s= value at 9c48edf).
# The draft-02 vectors take tag names in any case and skip an unknown
# algorithm beside a good one; -08 (contract D10, D3) does neither.
_D10 = ("-08 contract D10: an uppercase tag name is an unknown tag, so it is "
        "not a twin of the lowercase one")
KNOWN_DIVERGENCE: dict[str, str] = {
    **{f"d2_duplicate_{t}_tag": _D10
       for t in ("d", "f", "i", "m", "mf", "n", "rt", "t")},
    "tags_mixed_case": "-08 contract D10: I=, M=, D=... are unknown tags, so "
                       "i= is missing",
    "algorithm_with_future": "-08 §14.6 step 4, contract D3: an unimplemented "
                             "algorithm in a \",\" group makes it PERMERROR",
}


def dns_from_toml(d):
    """Convert the toml [DNS] table (host -> pubkey) to our nested dns.json."""
    out = {}
    for host, key in (d.get("DNS") or {}).items():
        marker = "._domainkey."
        i = host.find(marker)
        sel, dom = host[:i], host[i + len(marker):]
        out.setdefault(dom, {})[f"{sel}._domainkey"] = [["txt", key]]
    return out


def run_vector(toml_path):
    d = tomllib.loads(open(toml_path).read())
    exp = d.get("ExpectedState", "?")
    sf = d.get("SignedFile")
    path = os.path.join(TESTS_DIR, sf) if sf else None
    if path and os.path.exists(path):
        raw = open(path, "rb").read()
    else:
        raw = d.get("SignedMessage", "").encode()
        if b"\r\n" not in raw:
            raw = raw.replace(b"\n", b"\r\n")
    r = V.verify_message(raw, dns_from_toml(d), full_chain=True,
                         skip_timestamp_check=True,
                         mail_from=d.get("MailFrom"),
                         rcpt_to=d.get("RcptTo") or [])
    err = (r.errors[0] if getattr(r, "errors", None) else (r.message or "")) if r.status != exp else ""
    return d.get("Name", os.path.basename(toml_path)), exp, r.status, err


def main():
    if not os.path.isdir(TESTS_DIR):
        print(f"SKIP: submodule not checked out at {TESTS_DIR}")
        print("      run: git submodule update --init")
        return 0
    tomls = sorted(f for f in os.listdir(TESTS_DIR) if f.endswith(".toml"))
    # Gate on the accept/reject decision (the security-critical invariant):
    # 'pass' == accept, anything else == reject.  Exact status-code differences
    # (e.g. we say 'fail' where a vector says 'permerror') are surfaced but do
    # not fail the gate.
    def accept(s):
        return s == "pass"
    mismatches, notes, known = [], [], []
    for t in tomls:
        name, exp, got, err = run_vector(os.path.join(TESTS_DIR, t))
        if name in KNOWN_DIVERGENCE:
            known.append((name, exp, got))
            tag = "skip"
        elif accept(exp) != accept(got):
            mismatches.append((name, exp, got, err))
            tag = "FAIL"
        elif exp != got:
            notes.append((name, exp, got))
            tag = "note"
        else:
            tag = "ok  "
        print(f"{tag} {name:30} expect={exp:10} got={got:10} {err[:55]}")
    gated = len(tomls) - len(known)
    print(f"\n{gated - len(mismatches)}/{gated} gated vectors agree on accept/reject; "
          f"{len(notes)} exact-status notes; {len(known)} known-divergence skips")
    for name, _, _ in known:
        print(f"  skip: {name} -- {KNOWN_DIVERGENCE[name]}")
    for name, exp, got in notes:
        print(f"  note: {name} rejects as {got}, vector labels it {exp}")
    if mismatches:
        print(f"{len(mismatches)} ACCEPT/REJECT disagreements:")
        for name, exp, got, err in mismatches:
            print(f"  {name}: expected {exp}, got {got} -- {err[:70]}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
