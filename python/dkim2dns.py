#!/usr/bin/env python3
"""
DKIM2 public keys from DNS - draft-ietf-dkim-dkim2-spec-07 §14.5

A key source for dkim2verify.verify_message() in place of a dns.json dict:

    verify_message(raw, LiveDNS())

LiveDNS asks a resolver for `selector._domainkey.domain` TXT records.  The
ordinary lookup is synchronous: NXDOMAIN or NOERROR with no TXT record is an
absent key (KeyError); SERVFAIL, any other rcode, a timeout or a transport
error is DNSTempError, reported as "TEMPERROR ... could not be fetched".

Per message, the verifier calls for_message() and, as soon as the header
fields are known, prefetch() with every key name the DKIM2-Signatures need;
those queries run in the background while the body arrives.  When a
signature is checked, a definitive prefetched answer (records, NXDOMAIN,
NOERROR with no TXT) is used as it is; one that does not settle it (no reply
within prefetch_wait seconds of sending, SERVFAIL, any error) is redone the
ordinary synchronous way, so every verdict is what the synchronous lookup
alone would give.  Each name is looked up once per message.

DnspythonResolver asks the system's resolvers through dnspython, which is
imported only when keys are looked up in DNS (dns.json needs nothing
beyond the standard library and cryptography).  Any object with the same
query_txt() can stand in for it -- the tests use a fake.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor

PREFETCH_WAIT = 5.0     # seconds after sending before a prefetch is given up
_executor: ThreadPoolExecutor | None = None


class DNSTempError(Exception):
    """The lookup did not complete: timeout, SERVFAIL, transport error."""


class DnspythonResolver:
    """TXT queries through dnspython's dns.resolver (the system resolvers).

    dnspython is needed only here: a verifier given dns.json never imports
    it.  query_txt() returns ("NOERROR", records) -- records empty for
    NoAnswer -- or ("NXDOMAIN", []); ValueError for a name that cannot be
    looked up; any other failure (Timeout, NoNameservers i.e. SERVFAIL,
    network errors) propagates and is a temporary error."""

    def __init__(self, lifetime: float = PREFETCH_WAIT):
        try:
            import dns.resolver
        except ImportError:
            raise RuntimeError(
                "looking keys up in DNS needs dnspython (pip install "
                "dnspython); or pass --dns-json")
        self._dns = dns
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = lifetime

    def query_txt(self, name: str) -> tuple[str, list[list[bytes]]]:
        dns = self._dns
        try:
            qname = dns.name.from_text(name)
        except dns.exception.DNSException as e:
            raise ValueError(f"not a domain name: {name!r}: {e}")
        try:
            answer = self.resolver.resolve(qname, "TXT", search=False,
                                           raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN", []
        except dns.resolver.NoAnswer:
            return "NOERROR", []
        return "NOERROR", [list(rr.strings) for rr in answer]


def _answer(rcode: str, records: list[list[bytes]]) -> list[str]:
    """TXT values (each RR's strings concatenated, dkim2-dns-00 §3.4.2.2);
    KeyError if the key is absent, DNSTempError if the answer is not one."""
    if rcode == "NXDOMAIN":
        raise KeyError("NXDOMAIN")
    if rcode != "NOERROR":
        raise DNSTempError(rcode)
    if not records:
        raise KeyError("no TXT record")
    return [b"".join(rr).decode("utf-8", errors="surrogateescape")
            for rr in records]


class LiveDNS:
    """Key source: TXT lookups through `resolver` (a DnspythonResolver by
    default), prefetched per message unless prefetch is False."""

    def __init__(self, resolver=None, prefetch: bool = True,
                 prefetch_wait: float = PREFETCH_WAIT):
        self.resolver = (resolver if resolver is not None
                         else DnspythonResolver(lifetime=prefetch_wait))
        self.prefetch = prefetch
        self.prefetch_wait = prefetch_wait

    def txt_records(self, name: str) -> list[str]:
        """The ordinary synchronous lookup."""
        try:
            rcode, records = self.resolver.query_txt(name)
        except ValueError:
            raise KeyError(name)
        except Exception as e:
            raise DNSTempError(str(e) or type(e).__name__)
        return _answer(rcode, records)

    def for_message(self) -> "MessageKeys":
        return MessageKeys(self)


class MessageKeys:
    """One message's key lookups: prefetched, and each name looked up (and
    its outcome kept) once."""

    def __init__(self, live: LiveDNS):
        self.live = live
        self._pending: dict[str, tuple] = {}
        self._outcome: dict[str, tuple] = {}

    def prefetch(self, names) -> None:
        global _executor
        if not self.live.prefetch:
            return
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=min(32, (os.cpu_count() or 1) + 4),
                thread_name_prefix="dkim2-dns")
        for name in names:
            name = name.lower()
            if name in self._pending:
                continue
            self._pending[name] = (time.monotonic(), _executor.submit(
                self.live.resolver.query_txt, name))

    def _settled(self, name: str):
        """The prefetched (rcode, records) if it is definitive, else None."""
        sent, fut = self._pending.pop(name, (None, None))
        if fut is None:
            return None
        wait = max(0.0, sent + self.live.prefetch_wait - time.monotonic())
        try:
            rcode, records = fut.result(timeout=wait)
        except Exception:
            fut.cancel()
            return None
        return (rcode, records) if rcode in ("NOERROR", "NXDOMAIN") else None

    def txt_records(self, name: str) -> list[str]:
        name = name.lower()
        if name not in self._outcome:
            try:
                answer = self._settled(name)
                values = (_answer(*answer) if answer is not None
                          else self.live.txt_records(name))
                self._outcome[name] = (values, None)
            except (KeyError, DNSTempError) as e:
                self._outcome[name] = (None, e)
        values, err = self._outcome[name]
        if err is not None:
            raise err
        return values
