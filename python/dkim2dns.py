#!/usr/bin/env python3
"""
DKIM2 public keys from DNS - draft-ietf-dkim-dkim2-spec-06 §11.5

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

StubResolver is a small UDP (TCP on truncation) stub resolver using the
nameservers in /etc/resolv.conf; any object with the same query_txt() can
stand in for it.
"""

import os
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

PREFETCH_WAIT = 5.0     # seconds after sending before a prefetch is given up
_TXT, _IN = 16, 1
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
           4: "NOTIMP", 5: "REFUSED"}
_executor: ThreadPoolExecutor | None = None


class DNSTempError(Exception):
    """The lookup did not complete: timeout, SERVFAIL, transport error."""


def _encode_name(name: str) -> bytes | None:
    """Wire form of a domain name, or None if it cannot be one."""
    out = b""
    for label in name.rstrip(".").split("."):
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            return None
        if not 0 < len(raw) < 64:
            return None
        out += bytes([len(raw)]) + raw
    return out + b"\0" if len(out) < 255 else None


def _skip_name(msg: bytes, pos: int) -> int:
    while True:
        n = msg[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + n


def parse_txt_response(msg: bytes, qid: int) -> tuple[str, list[list[bytes]], bool]:
    """(rcode name, TXT RRs as lists of character-strings, truncated)."""
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise DNSTempError("reply does not match the query")
    rcode = _RCODES.get(flags & 0xF, f"RCODE{flags & 0xF}")
    pos = 12
    for _ in range(qd):
        pos = _skip_name(msg, pos) + 4
    records = []
    for _ in range(an):
        pos = _skip_name(msg, pos)
        rtype, rclass, _, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        rdata, pos = msg[pos:pos + rdlen], pos + rdlen
        if rtype == _TXT and rclass == _IN:
            strings, i = [], 0
            while i < len(rdata):
                strings.append(rdata[i + 1:i + 1 + rdata[i]])
                i += 1 + rdata[i]
            records.append(strings)
    return rcode, records, bool(flags & 0x0200)


class StubResolver:
    """TXT queries to the system's recursive resolvers."""

    def __init__(self, nameservers: list[str] | None = None,
                 timeout: float = 5.0, port: int = 53):
        self.nameservers = nameservers or self._system_nameservers()
        self.timeout = timeout
        self.port = port

    @staticmethod
    def _system_nameservers() -> list[str]:
        servers = []
        try:
            with open("/etc/resolv.conf") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        servers.append(parts[1])
        except OSError:
            pass
        return servers or ["127.0.0.1"]

    def query_txt(self, name: str) -> tuple[str, list[list[bytes]]]:
        wire = _encode_name(name)
        if wire is None:
            raise ValueError(f"not a domain name: {name!r}")
        qid = random.getrandbits(16)
        query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) \
            + wire + struct.pack("!HH", _TXT, _IN)
        last: Exception = DNSTempError("no nameserver")
        for ns in self.nameservers:
            family = socket.AF_INET6 if ":" in ns else socket.AF_INET
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(query, (ns, self.port))
                    rcode, recs, tc = parse_txt_response(s.recv(65535), qid)
                if tc:
                    with socket.create_connection((ns, self.port),
                                                  self.timeout) as s:
                        s.sendall(struct.pack("!H", len(query)) + query)
                        rcode, recs, _ = parse_txt_response(
                            self._recv_tcp(s), qid)
                return rcode, recs
            except (OSError, DNSTempError, struct.error, IndexError) as e:
                last = e
        raise last

    @staticmethod
    def _recv_tcp(s) -> bytes:
        def exactly(n):
            buf = b""
            while len(buf) < n:
                part = s.recv(n - len(buf))
                if not part:
                    raise DNSTempError("connection closed")
                buf += part
            return buf
        return exactly(struct.unpack("!H", exactly(2))[0])


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
    """Key source: TXT lookups through `resolver` (a StubResolver by
    default), prefetched per message unless prefetch is False."""

    def __init__(self, resolver=None, prefetch: bool = True,
                 prefetch_wait: float = PREFETCH_WAIT):
        self.resolver = resolver if resolver is not None else StubResolver()
        self.prefetch = prefetch
        self.prefetch_wait = prefetch_wait

    def txt_records(self, name: str) -> list[str]:
        """The ordinary synchronous lookup."""
        if _encode_name(name) is None:
            raise KeyError(name)
        try:
            rcode, records = self.resolver.query_txt(name)
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
            if name in self._pending or _encode_name(name) is None:
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
