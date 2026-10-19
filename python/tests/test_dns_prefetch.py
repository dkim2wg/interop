"""Public-key prefetch (dkim2dns): every key the signatures name is asked
for as soon as the header fields are known, and the verdicts are exactly the
ones the ordinary synchronous lookup gives.

A fake resolver stands in for DNS, answering from the repo dns.json.
"""
import json
import os
import struct
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
from dkim2dns import LiveDNS, parse_txt_response  # noqa: E402
from dkim2verify import MessageVerifier, verify_message  # noqa: E402

with open(os.path.join(ROOT, "dns.json")) as fh:
    DNS = json.load(fh)
with open(os.path.join(ROOT, "perl", "tests", "expected",
                       "chain-hop6-unchanged-re-sign.eml"), "rb") as fh:
    RAW = fh.read()
KW = dict(full_chain=True, skip_timestamp_check=True)


class FakeResolver:
    """Answers from dns.json.  first/later: per-name ("*" for any) overrides
    for the prefetch (a call from a worker thread) and for the ordinary
    lookup (from the verifying thread) -- "SERVFAIL", "NXDOMAIN", "NODATA",
    "raise", or "block" (wait until released)."""

    def __init__(self, first=None, later=None):
        self.first, self.later = first or {}, later or {}
        self.calls = []
        self.sync_calls = []    # the ordinary lookups
        self.lock = threading.Lock()
        self.release = threading.Event()

    def query_txt(self, name):
        main = threading.current_thread() is threading.main_thread()
        with self.lock:
            self.calls.append(name)
            if main:
                self.sync_calls.append(name)
        rules = self.later if main else self.first
        how = rules.get(name, rules.get("*"))
        if how == "block":
            self.release.wait(10)
            how = None
        if how == "raise":
            raise OSError("network unreachable")
        if how in ("SERVFAIL", "NXDOMAIN"):
            return how, []
        if how == "NODATA":
            return "NOERROR", []
        sel, _, domain = name.partition("._domainkey.")
        recs = DNS.get(domain, {}).get(f"{sel}._domainkey")
        if not recs:
            return "NXDOMAIN", []
        return "NOERROR", [[v.encode() if isinstance(v, str) else b"".join(
            p.encode() for p in v)] for t, v in recs if t.lower() == "txt"]


def _names():
    import dkim2verify
    from dkim2sign import parse_message
    headers, _ = parse_message(RAW)
    return dkim2verify._key_names(dkim2verify.extract_sig_headers(headers))


NAMES = _names()


def _outcome(r):
    return (r.ok, r.status, r.message, r.errors)


def _verify(resolver, **live):
    return _outcome(verify_message(RAW, LiveDNS(resolver, **live), **KW))


def _sync(resolver):
    return _verify(resolver, prefetch=False)   # every call is "later"


def test_fixture_names_five_keys():
    assert len(NAMES) == 5, NAMES
    assert _outcome(verify_message(RAW, DNS, **KW))[0] is True


def test_all_keys_requested_by_end_of_headers_once_each():
    fake = FakeResolver()
    v = MessageVerifier(LiveDNS(fake), **KW)
    sep = RAW.index(b"\r\n\r\n") + 4 if b"\r\n\r\n" in RAW else RAW.index(b"\n\n") + 2
    v.feed(RAW[:sep])
    for _, fut in list(v._ctx.keys._pending.values()):
        fut.result(5)
    assert sorted(fake.calls) == sorted(NAMES)
    v.feed(RAW[sep:])
    r = v.close()
    assert r.ok, r.errors
    assert sorted(fake.calls) == sorted(NAMES)   # no second lookup


def test_good_answers_match_dns_json_and_sync():
    assert _verify(FakeResolver()) == _outcome(verify_message(RAW, DNS, **KW))
    assert _verify(FakeResolver()) == _sync(FakeResolver())


def test_no_prefetch_without_live_source_or_when_off():
    fake = FakeResolver()
    v = MessageVerifier(LiveDNS(fake, prefetch=False), **KW)
    v.feed(RAW[:RAW.index(b"\n\n") + 2] if b"\r\n\r\n" not in RAW
           else RAW[:RAW.index(b"\r\n\r\n") + 4])
    assert fake.calls == []
    v = MessageVerifier(DNS, **KW)
    v.feed(RAW)
    assert v._ctx.keys is DNS
    assert v.close().ok


def test_still_pending_falls_back_to_ordinary_lookup():
    fake = FakeResolver(first={"*": "block"})
    try:
        got = _verify(fake, prefetch_wait=0)
    finally:
        fake.release.set()
    assert got == _sync(FakeResolver()) and got[0] is True
    assert sorted(fake.sync_calls) == sorted(NAMES)


def test_servfail_and_transport_error_fall_back():
    for how in ("SERVFAIL", "raise"):
        fake = FakeResolver(first={"*": how})
        got = _verify(fake)
        assert got == _sync(FakeResolver()) and got[0] is True, how
        assert sorted(fake.sync_calls) == sorted(NAMES), how
        assert sorted(fake.calls) == sorted(NAMES * 2), how


def test_temperror_is_the_ordinary_lookups_temperror():
    for how in ("SERVFAIL", "raise"):
        got = _verify(FakeResolver(first={"*": how}, later={"*": how}))
        assert got == _sync(FakeResolver(first={"*": how}, later={"*": how}))
        assert got[1] == "temperror", got
        assert "TEMPERROR DKIM2-Signature i=" in got[2]
        assert got[2].endswith("could not be fetched"), got[2]
    # Timed out on the prefetch, then SERVFAIL on the ordinary lookup.
    fake = FakeResolver(first={"*": "block"}, later={"*": "SERVFAIL"})
    try:
        got = _verify(fake, prefetch_wait=0)
    finally:
        fake.release.set()
    assert got == _sync(FakeResolver(later={"*": "SERVFAIL"}))


def test_definitive_answers_used_directly():
    for how in ("NXDOMAIN", "NODATA"):
        name = NAMES[0]
        fake = FakeResolver(first={name: how})   # a second ask would succeed
        got = _verify(fake)
        assert fake.calls.count(name) == 1, how
        assert got == _sync(FakeResolver(later={name: how}))
        assert not got[0] and any("does not exist" in e or "i=" in e
                                  for e in got[3]), got


def test_parse_txt_response():
    q = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0)
    q += b"\x03sel\x0a_domainkey\x07example\x03com\x00" + struct.pack("!HH", 16, 1)
    rdata = b"\x05v=DKI" + b"\x02M1"
    q += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
    assert parse_txt_response(q, 7) == ("NOERROR", [[b"v=DKI", b"M1"]], False)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok:", name)
