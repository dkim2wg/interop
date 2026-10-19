"""Planned walk against the undo walk on real mail.

Every captured list message in corpus/results/capture (1585 messages from
the Mailman/Sympa/milter runs; not in git, so this skips when it is absent --
set DKIM2_CORPUS_DIR to point elsewhere) and every perl/tests/expected
fixture is verified both ways, whole and fed in chunks, together with a copy
whose body has one byte changed and a copy whose Subject is changed.  The
per-instance hashes and the verdicts must be identical.
"""
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
from dkim2verify import MessageVerifier, verify_message  # noqa: E402


def _corpus_dir():
    cands = [os.environ.get("DKIM2_CORPUS_DIR"),
             os.path.join(ROOT, "corpus", "results", "capture")]
    try:  # a git worktree: the corpus lives beside the main checkout
        common = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--path-format=absolute",
             "--git-common-dir"], capture_output=True, text=True).stdout.strip()
        if common:
            cands.append(os.path.join(os.path.dirname(common),
                                      "corpus", "results", "capture"))
    except OSError:
        pass
    for c in cands:
        if c and os.path.isdir(c):
            return c
    return None


def _keys(corpus):
    with open(os.path.join(ROOT, "dns.json")) as fh:
        dns = json.load(fh)
    live = corpus and os.path.join(os.path.dirname(corpus), "dns-live.json")
    if live and os.path.exists(live):
        with open(live) as fh:
            for domain, recs in json.load(fh).items():
                dns.setdefault(domain, {}).update(recs)
    return dns


def _variants(raw):
    yield raw
    sep = raw.find(b"\r\n\r\n")
    sep = sep + 4 if sep >= 0 else raw.find(b"\n\n") + 2
    if 1 < sep < len(raw):
        i = sep + (len(raw) - sep) // 2
        yield raw[:i] + (b"Y" if raw[i:i + 1] != b"Y" else b"Z") + raw[i + 1:]
    s = raw.find(b"\nSubject:")
    if s >= 0:
        yield raw[:s + 9] + b" changed" + raw[s + 9:]


def _outcome(r):
    return (r.ok, r.status, r.message, r.errors)


def compare(raw, dns, sizes=(997,)):
    kw = dict(full_chain=True, skip_timestamp_check=True)
    ref_trace, got_trace = [], []
    ref = verify_message(raw, dns, walk="undo", walk_trace=ref_trace, **kw)
    got = verify_message(raw, dns, walk="plan", walk_trace=got_trace, **kw)
    assert got_trace == ref_trace
    assert _outcome(got) == _outcome(ref)
    for size in sizes:
        trace = []
        v = MessageVerifier(dns, walk_trace=trace, **kw)
        for i in range(0, len(raw), size):
            v.feed(raw[i:i + size])
        assert _outcome(v.close()) == _outcome(ref), size
        assert trace == ref_trace, size
    return ref


_PRE07 = ("matching From is not authentic", "contains invalid JSON")


def _run(paths, dns, sizes, pre07=False):
    n, statuses = 0, {}
    for path in paths:
        with open(path, "rb") as fh:
            raw = fh.read()
        for k, variant in enumerate(_variants(raw)):
            try:
                r = compare(variant, dns, sizes)
            except AssertionError:
                raise AssertionError(f"{path} variant {k}")
            if pre07 and k == 0:
                assert all(e.endswith(_PRE07) for e in r.errors), (path, r.errors)
            statuses[(k, r.status)] = statuses.get((k, r.status), 0) + 1
            n += 1
    return n, statuses


def test_perl_fixtures():
    paths = sorted(glob.glob(os.path.join(ROOT, "perl", "tests", "expected", "*.eml")))
    assert paths
    n, _ = _run(paths, _keys(_corpus_dir()), (1, 7, 997))
    assert n >= 3 * len(paths) - 3


def test_captured_corpus():
    corpus = _corpus_dir()
    if corpus is None:
        print("skip: no corpus/results/capture")
        return
    paths = sorted(glob.glob(os.path.join(corpus, "*.eml")))
    n, statuses = _run(paths, _keys(corpus), (997,), pre07=True)
    print(f"compared {len(paths)} messages, {n} variants: {statuses}")
    # The capture is -06 list mail: under -07 its From is not Authentic (the
    # lists did not rewrite it) and a Latin-1/EUC-KR literal is a -06 "b"
    # step, now an unknown step key.  So an original may be a PERMERROR for
    # those reasons only -- never a hash or signature FAIL.
    assert statuses.get((0, "fail"), 0) == 0, statuses
    assert statuses.get((0, "temperror"), 0) == 0, statuses


if __name__ == "__main__":
    test_perl_fixtures()
    test_captured_corpus()
    print("ok: planned walk matches the undo walk")
