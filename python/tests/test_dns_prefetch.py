"""Public-key prefetch (dkim2dns): every key the signatures name is asked
for as soon as the header fields are known (and used only once the chain
walk has passed, contract C9), and the verdicts are exactly the ones the ordinary
synchronous lookup gives.

A fake resolver stands in for DNS, answering from the repo dns.json.
"""
import json
import os
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
from dkim2dns import DNSTempError, LiveDNS  # noqa: E402
from dkim2verify import MessageVerifier, verify_message  # noqa: E402

with open(os.path.join(ROOT, "dns.json")) as fh:
    DNS = json.load(fh)


def _five_key_chain() -> bytes:
    """A five-hop chain, each hop signed with a different key (test1..test5),
    built here so its From is Authentic for i=1 (-07 §11)."""
    import gate_env  # noqa: F401  (old timestamps are fine for the gate)
    from dkim2sign import sign_message
    msg = (b"From: Sender <sender@test1.dkim2.com>\r\nTo: a@test2.dkim2.com\r\n"
           b"Subject: five keys\r\n\r\nbody\r\n")
    hops = [("test1", "sel1"), ("test2", "sel2"), ("test3", "ed25519"),
            ("test4", "sel3"), ("test5", "sel1")]
    mailfrom = "sender@test1.dkim2.com"
    for n, (dom, sel) in enumerate(hops):
        nxt = hops[n + 1][0] if n + 1 < len(hops) else "test1"
        msg = sign_message(
            msg, sel, f"{dom}.dkim2.com",
            os.path.join(ROOT, "keys", f"{sel}._domainkey.{dom}.dkim2.com.pem"),
            mailfrom=mailfrom, rcptto=[f"r@{nxt}.dkim2.com"],
            timestamp=1740000000 + n, dns_data=DNS)
        mailfrom = f"r@{nxt}.dkim2.com"
    return msg


RAW = _five_key_chain()
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


def test_failed_walk_is_the_result_whatever_the_keys_say():
    # Contract C9: the keys are prefetched, but none is used (no ordinary
    # lookup, no key error) when the chain walk fails.
    fake = FakeResolver(first={"*": "NXDOMAIN"})
    r = verify_message(RAW + b"tampered\r\n", LiveDNS(fake), **KW)
    assert r.status == "fail", r.errors
    # Five signatures, one instance: no hop changed the content.
    assert r.errors == ["FAIL: Message-Instance m=1 body hash sha256 mismatch"]
    assert fake.sync_calls == []


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
        assert "TEMPERROR: DKIM2-Signature i=" in got[2]
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


def test_dnspython_answers_mapped():
    try:
        import dns.resolver
    except ImportError:
        print("skip: no dnspython")
        return
    from dkim2dns import DnspythonResolver

    class RR:
        strings = (b"v=DKIM1; k=ed25519; ", b"p=abc")

    r = DnspythonResolver()
    live = LiveDNS(r, prefetch=False)
    outcomes = {}
    for what in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(),
                 dns.resolver.LifetimeTimeout(timeout=5.0, errors=[]),
                 dns.resolver.NoNameservers(), OSError("unreachable"), [RR()]):
        def resolve(*a, **kw):
            if isinstance(what, Exception):
                raise what
            return what
        r.resolver.resolve = resolve
        try:
            outcomes[type(what).__name__] = live.txt_records("s._domainkey.example.com")
        except (KeyError, DNSTempError) as e:
            outcomes[type(what).__name__] = type(e).__name__
    assert outcomes == {
        "NXDOMAIN": "KeyError", "NoAnswer": "KeyError",
        "LifetimeTimeout": "DNSTempError", "NoNameservers": "DNSTempError",
        "OSError": "DNSTempError",
        "list": ["v=DKIM1; k=ed25519; p=abc"]}, outcomes
    try:
        live.txt_records("a..b._domainkey.example.com")   # not a name
        assert False
    except KeyError:
        pass


def test_dns_json_mode_needs_no_dnspython():
    """The util/*.sh runners call the CLI with --dns-json and a bare
    python3: dnspython must matter only for live DNS."""
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    tmp.write(RAW)
    tmp.close()
    fixture = tmp.name
    code = ("import sys, runpy; sys.modules['dns'] = None; "
            "sys.argv = ['dkim2verify.py'] + sys.argv[1:]; "
            "runpy.run_path(%r, run_name='__main__')"
            % os.path.join(os.path.dirname(HERE), "dkim2verify.py"))
    ok = subprocess.run([sys.executable, "-c", code, fixture, "--dns-json",
                         os.path.join(ROOT, "dns.json"), "--ignore-timestamps"],
                        capture_output=True, text=True)
    assert ok.returncode == 0 and "PASS" in ok.stdout, ok.stdout + ok.stderr
    live = subprocess.run([sys.executable, "-c", code, fixture,
                           "--ignore-timestamps"], capture_output=True, text=True)
    assert live.returncode == 2 and "needs dnspython" in live.stderr, live.stderr
    os.unlink(fixture)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok:", name)
