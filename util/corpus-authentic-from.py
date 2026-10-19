#!/usr/bin/env python3
"""Copy a charset-corpus sample with each From address moved into DOMAIN.

    util/corpus-authentic-from.py DOMAIN SRC_DIR DST_DIR

Draft -07 (sections 11 and 12.4) has a signer refuse a message whose From is
not Authentic for its signing domain, and every corpus sample carries its
real author's From. The corpus runner signs each sample as one of our test
domains, so before signing it moves the From address into that domain, the
way a list host rewrites From. Only the address changes: the display name
(often RFC 2047 or raw 8-bit in a corpus charset), every other header field
and the body are copied byte for byte, so the charset content under test is
untouched.

A From with an angle-addr keeps everything outside the brackets; one without
becomes the bare address; a message with no From gets one at the top. Files
other than *.eml (index.tsv) are copied unchanged.
"""
import os
import re
import shutil
import sys


def rewrite(raw: bytes, addr: bytes) -> bytes:
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    eol = b"\r\n" if b"\r\n" in head else b"\n"
    lines = head.split(eol)
    out, i, seen = [], 0, False
    while i < len(lines):
        line = lines[i]
        j = i + 1
        while j < len(lines) and lines[j][:1] in (b" ", b"\t"):
            j += 1
        if re.match(rb"(?i)from\s*:", line):
            seen = True
            field = eol.join(lines[i:j])
            name, _, value = field.partition(b":")
            m = list(re.finditer(rb"<[^<>]*>", value))
            if m:
                last = m[-1]
                value = value[:last.start()] + b"<" + addr + b">" + value[last.end():]
            else:
                value = b" " + addr
            out.extend((name + b":" + value).split(eol))
        else:
            out.extend(lines[i:j])
        i = j
    if not seen:
        out.insert(0, b"From: " + addr)
    return eol.join(out) + sep + body


def main() -> None:
    domain, src, dst = sys.argv[1:4]
    addr = b"corpus@" + domain.encode("ascii")
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(src):
        s, d = os.path.join(src, name), os.path.join(dst, name)
        if not os.path.isfile(s):
            continue
        if name.endswith(".eml"):
            with open(s, "rb") as f:
                raw = f.read()
            with open(d, "wb") as f:
                f.write(rewrite(raw, addr))
        else:
            shutil.copyfile(s, d)


if __name__ == "__main__":
    main()
