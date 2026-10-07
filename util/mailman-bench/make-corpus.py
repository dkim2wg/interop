#!/usr/bin/env python3
"""Build the Mailman benchmark corpus: the charset-corpus samples plus
synthetic messages, each unsigned and DKIM2-signed (perl/bin/dkim2sign)."""
import random, subprocess, sys
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'bench' / 'corpus'
KEY = ROOT / 'perl/t/data/keys/sel1._domainkey.test1.dkim2.com.pem'
rng = random.Random(20261007)

def base(subject):
    m = EmailMessage(policy=SMTP)
    m['From'] = 'bench@test1.dkim2.com'
    m['To'] = 'bench@lists.example.com'
    m['Subject'] = subject
    m['Message-ID'] = '<{}@bench.dkim2.com>'.format(subject.replace(' ', '-'))
    m['Date'] = 'Wed, 07 Oct 2026 00:00:00 +0000'
    return m

def text(n):
    words = 'the list adds a footer and the message is wrapped once more'.split()
    lines, line, total = [], [], 0
    while total < n:
        line.append(rng.choice(words))
        if len(' '.join(line)) > 66:
            s = ' '.join(line)
            lines.append(s); total += len(s) + 1; line = []
    return '\n'.join(lines) + '\n'

def synthetic():
    m = base('plain 2k'); m.set_content(text(2_000)); yield 'syn-plain-2k', m, 0
    m = base('outlook'); m.set_content(text(4_000))
    m.add_alternative('<html><body>' + '<p>' * 4000 + text(4_000) + '</body></html>', subtype='html')
    yield 'syn-outlook', m, 0
    for mb in (1, 10, 50):
        m = base(f'attach {mb}MB'); m.set_content(text(1_000))
        m.add_attachment(rng.randbytes(mb * 1_000_000), maintype='application',
                         subtype='octet-stream', filename=f'blob{mb}.bin')
        yield f'syn-attach-{mb}mb', m, 0
    m = base('qp 5MB'); m.set_content(text(5_000_000).replace('the', 'thé'), cte='quoted-printable')
    yield 'syn-qp-5mb', m, 0
    m = base('filtered 10MB'); m.set_content(text(1_000))
    m.add_attachment(rng.randbytes(10_000_000), maintype='application',
                     subtype='zip', filename='kitten.zip')
    yield 'syn-filter-10mb', m, 1

def size_class(n):
    return 'small' if n < 20_000 else 'medium' if n < 1_000_000 else 'large' if n < 20_000_000 else 'huge'

def sign(raw):
    # dkim2sign emits the whole signed message (headers + body) on stdout.
    return subprocess.run(
        ['perl', '-I', str(ROOT / 'perl/lib'), str(ROOT / 'perl/bin/dkim2sign'),
         '-d', 'test1.dkim2.com', '-s', 'sel1', '-k', str(KEY),
         '--mailfrom', 'bench@test1.dkim2.com', '--rcptto', 'bench@lists.example.com'],
        input=raw, capture_output=True, check=True).stdout

def main():
    for sub in ('unsigned', 'signed'):
        (OUT / sub).mkdir(parents=True, exist_ok=True)
    rows, skipped = [], []
    items = [(p.stem, p.read_bytes(), 0) for p in sorted((ROOT / 'corpus/sample').glob('*.eml'))]
    items += [(i, m.as_bytes(policy=SMTP), f) for i, m, f in synthetic()]
    for ident, raw, filt in items:
        raw = raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        try:
            signed = sign(raw)
            assert b'Message-Instance:' in signed and b'DKIM2-Signature:' in signed
        except (subprocess.CalledProcessError, AssertionError) as e:
            skipped.append(ident)
            print(f'skip {ident}: signing failed ({type(e).__name__})', file=sys.stderr)
            continue
        (OUT / 'unsigned' / f'{ident}.eml').write_bytes(raw)
        (OUT / 'signed' / f'{ident}.eml').write_bytes(signed)
        rows.append(f'{ident}\t{len(raw)}\t{size_class(len(raw))}\t{filt}')
    (OUT / 'index.tsv').write_text('id\tsize\tclass\tfilter\n' + '\n'.join(rows) + '\n')
    print(f'{len(rows)} messages -> {OUT} ({len(skipped)} skipped)')

if __name__ == '__main__':
    sys.exit(main())
