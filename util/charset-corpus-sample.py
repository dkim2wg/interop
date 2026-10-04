#!/usr/bin/env python3
"""
Fetch public mail archives in assorted charsets and pick a representative
sample of raw messages for the DKIM2 charset corpus run.

    util/charset-corpus-sample.py [-n PER_SOURCE] [--only NAME,...] [--cache DIR]

Writes:

    <cache>/raw/<source>.<ext>          the downloaded archive, as served
    <cache>/sample/<source>-NNN-<charset>-<cte>.eml
                                        one message per file, CRLF line endings,
                                        otherwise byte-for-byte as archived
    <cache>/sample/index.tsv            id, source, charset, cte, flags, subject

Nothing under <cache> is committed; the sample set is a derived artifact and
the upstream archives are the source of truth. util/charset-corpus.sh drives
this and then runs the sign/verify matrix and the list round over the sample.

Why these sources: they are the public archives that still hand out FULL raw
messages (Content-Type, Content-Transfer-Encoding, MIME structure intact).
Pipermail's "Gzip'd Text" downloads are scrubbed -- no Content-Type, bodies
re-encoded -- and cannot exercise anything below the Subject line, so none of
the hundred-odd lists.ubuntu.com locale lists are here despite looking ideal.
"""

import argparse
import bz2
import gzip
import io
import re
import sys
import tarfile
import urllib.request
from collections import defaultdict
from pathlib import Path

# name -> (url, kind). kind is how to turn the download into messages:
#   mbox      a Unix mbox (plain or gzip; detected by magic)
#   tar-eml   a tarball whose regular files are each one message, some with a
#             leading mbox From_ line (the SpamAssassin corpus layout)
def _apache(lst, domain, month):
    return (f"https://lists.apache.org/api/mbox.lua?list={lst}&domain={domain}&d={month}", "mbox")


def _hyperkitty(host, lst, year):
    return (f"https://{host}/archives/list/{lst}/export/{lst}.mbox.gz"
            f"?start={year}-01-01&end={year + 1}-01-01", "mbox")


def _sa(tarball):
    return (f"https://spamassassin.apache.org/old/publiccorpus/{tarball}.tar.bz2", "tar-eml")


# name -> (url, kind). kind is how to turn the download into messages:
#   mbox      a Unix mbox (plain or gzip; detected by magic)
#   tar-eml   a tarball whose regular files are each one message, some with a
#             leading mbox From_ line (the SpamAssassin corpus layout)
#
# Apache's localized lists are ezmlm, so their archives hold the bytes the
# sender sent. The Mailman 3 (HyperKitty) exports have already been through a
# list once -- footer, prefix -- so a second list hop is what they test. The
# SpamAssassin corpus is 2002-2003 mail with every charset sin there is.
# Months were chosen by probing for traffic (2026-10-04); a month that has
# gone empty upstream just yields nothing.
SOURCES = {
    # Japanese: ISO-2022-JP 7bit is the stateful encoding footers break.
    "apache-ja":        _apache("general-ja", "openoffice.apache.org", "2012-10"),
    "apache-ja-2013":   _apache("general-ja", "openoffice.apache.org", "2013-01"),
    "ruby-list":        _hyperkitty("ml.ruby-lang.org", "ruby-list@ml.ruby-lang.org", 2024),
    "ruby-list-2023":   _hyperkitty("ml.ruby-lang.org", "ruby-list@ml.ruby-lang.org", 2023),
    "ruby-dev-2023":    _hyperkitty("ml.ruby-lang.org", "ruby-dev@ml.ruby-lang.org", 2023),
    "fedora-ja-2008":   _hyperkitty("lists.fedoraproject.org", "trans-ja@lists.fedoraproject.org", 2008),
    # Chinese: gb2312 / gbk / gb18030 / big5 / utf-8; 8bit, base64 and QP.
    "apache-zh":        _apache("user-zh", "flink.apache.org", "2019-09"),
    "apache-zh-2020":   _apache("user-zh", "flink.apache.org", "2020-06"),
    "apache-zh-2023":   _apache("user-zh", "flink.apache.org", "2023-03"),
    "apache-cn-2013":   _apache("users-cn", "cloudstack.apache.org", "2013-06"),
    # German, French, Spanish, Italian, Czech: Latin-1/-2/-15, windows-125x.
    "apache-de":        _apache("users-de", "openoffice.apache.org", "2013-05"),
    "apache-de-2015":   _apache("users-de", "openoffice.apache.org", "2015-06"),
    "httpd-de-2004":    _apache("users-de", "httpd.apache.org", "2004-06"),
    "cocoon-fr-2005":   _apache("users-fr", "cocoon.apache.org", "2005-03"),
    "apache-fr-2014":   _apache("users-fr", "openoffice.apache.org", "2014-01"),
    "apache-es-2012":   _apache("general-es", "openoffice.apache.org", "2012-11"),
    "apache-it-2016":   _apache("utenti-it", "openoffice.apache.org", "2016-03"),
    "ibatis-cs-2007":   _apache("user-cs", "ibatis.apache.org", "2007-04"),
    # Adversarial: big5, gb2312, iso-8859-2, koi8-r, euc-kr, broken charset=
    # values, 8-bit bytes in headers, HTML-only bodies.
    "sa-spam2":         _sa("20030228_spam_2"),
    "sa-spam-2002":     _sa("20021010_spam"),
    "sa-hardham":       _sa("20030228_hard_ham"),
    "sa-easyham2":      _sa("20030228_easy_ham_2"),
}

CHARSET_RE = re.compile(rb'charset\s*=\s*"?\s*([A-Za-z0-9_.:+-]+)', re.I)
CTE_RE = re.compile(rb'^Content-Transfer-Encoding:\s*([A-Za-z0-9-]+)', re.I | re.M)
SUBJECT_RE = re.compile(rb'^Subject:[ \t]*(.*(?:\r?\n[ \t].*)*)', re.I | re.M)


def fetch(name, url, raw_dir):
    ext = {"mbox": "mbox", "tar-eml": "tar.bz2"}[SOURCES[name][1]]
    out = raw_dir / f"{name}.{ext}"
    if out.exists() and out.stat().st_size > 0:
        return out
    print(f"fetching {name} <- {url}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "dkim2-interop-corpus/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    out.write_bytes(data)
    return out


def split_mbox(data):
    """Yield messages from an mbox, From_ line removed. mboxo '>From ' escapes
    are left alone: undoing them is ambiguous and the message is valid either way."""
    parts = re.split(rb'(?:^|\n)From [^\n]*\n', b"\n" + data)
    for p in parts:
        if p.strip():
            yield p


def messages(path, kind):
    if kind == "mbox":
        yield from split_mbox(path.read_bytes())
    elif kind == "tar-eml":
        with tarfile.open(path, "r:bz2") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                data = tf.extractfile(m).read()
                if data.startswith(b"From "):
                    data = data.split(b"\n", 1)[1]
                yield data


def to_crlf(data):
    return re.sub(rb'\r?\n', b"\r\n", data)


def classify(msg):
    """Return (charset, cte, flags, subject). charset/cte are the first seen
    in the message, which for single-part mail is the one that matters and for
    multipart is the outer or first part -- good enough to spread the sample."""
    sep = msg.find(b"\r\n\r\n")
    hdrs, body = (msg[:sep], msg[sep + 4:]) if sep != -1 else (msg, b"")
    # Prefer the header block: a QP-encoded HTML body is full of
    # `charset=3Dbig5` strings that say nothing about the message's own charset.
    multipart = re.search(rb'^Content-Type:\s*multipart/', hdrs, re.I | re.M) is not None
    m = CHARSET_RE.search(msg if multipart else hdrs)
    charset = m.group(1).decode("ascii", "replace").lower() if m else "none"
    charset = re.sub(r'[^a-z0-9]+', '-', charset).strip('-') or "none"
    m = CTE_RE.search(hdrs) or CTE_RE.search(msg)
    cte = m.group(1).decode("ascii", "replace").lower() if m else "none"
    flags = []
    if any(b > 0x7f for b in hdrs):
        flags.append("8bit-hdr")
    if any(b > 0x7f for b in body):
        flags.append("8bit-body")
    if b"=?" in hdrs:
        flags.append("encword")
    if multipart:
        flags.append("multipart")
    longest = max((len(l) for l in msg.split(b"\r\n")), default=0)
    if longest > 998:
        flags.append("longline")
    m = SUBJECT_RE.search(hdrs)
    subject = m.group(1) if m else b""
    subject = re.sub(rb'\r?\n[ \t]+', b" ", subject).decode("utf-8", "replace")[:60]
    return charset, cte, flags, subject


def pick(classified, per_source):
    """Round-robin over (charset, cte) keys so the sample covers every
    combination present before it takes a second message of any one."""
    buckets = defaultdict(list)
    for item in classified:
        buckets[(item[0], item[1])].append(item)
    chosen = []
    while len(chosen) < per_source and any(buckets.values()):
        for key in sorted(buckets):
            if buckets[key] and len(chosen) < per_source:
                chosen.append(buckets[key].pop(0))
    return chosen


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-n", "--per-source", type=int, default=15,
                    help="messages to keep per source (default 15)")
    ap.add_argument("--only", help="comma-separated source names (default: all)")
    ap.add_argument("--cache", default="corpus", help="cache directory (default ./corpus)")
    ap.add_argument("--list-sources", action="store_true")
    args = ap.parse_args()

    if args.list_sources:
        for n, (u, k) in SOURCES.items():
            print(f"{n}\t{k}\t{u}")
        return 0

    names = args.only.split(",") if args.only else list(SOURCES)
    unknown = [n for n in names if n not in SOURCES]
    if unknown:
        sys.exit(f"unknown source(s): {', '.join(unknown)}")

    cache = Path(args.cache)
    raw_dir, sample_dir = cache / "raw", cache / "sample"
    raw_dir.mkdir(parents=True, exist_ok=True)
    sample_dir.mkdir(parents=True, exist_ok=True)
    for old in sample_dir.glob("*.eml"):
        old.unlink()

    index = []
    for name in names:
        url, kind = SOURCES[name]
        try:
            path = fetch(name, url, raw_dir)
        except Exception as e:  # keep going; a dead mirror shouldn't sink the run
            print(f"{name}: fetch failed: {e}", file=sys.stderr)
            continue
        classified = []
        total = 0
        for msg in messages(path, kind):
            total += 1
            msg = to_crlf(msg)
            charset, cte, flags, subject = classify(msg)
            classified.append((charset, cte, flags, subject, msg))
        chosen = pick(classified, args.per_source)
        keys = sorted({(c[0], c[1]) for c in classified})
        print(f"{name}: {total} messages, {len(keys)} charset/cte combos, kept {len(chosen)}",
              file=sys.stderr)
        for i, (charset, cte, flags, subject, msg) in enumerate(chosen, 1):
            sid = f"{name}-{i:03d}-{charset}-{cte}"
            (sample_dir / f"{sid}.eml").write_bytes(msg)
            index.append((sid, name, charset, cte, ",".join(flags) or "-", subject))

    with open(sample_dir / "index.tsv", "w", encoding="utf-8") as fh:
        fh.write("id\tsource\tcharset\tcte\tflags\tsubject\n")
        for row in index:
            fh.write("\t".join(row).replace("\n", " ") + "\n")
    print(f"sample: {len(index)} messages in {sample_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
