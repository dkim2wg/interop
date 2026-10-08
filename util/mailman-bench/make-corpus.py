#!/usr/bin/env python3
"""Build the Mailman benchmark corpus: the charset-corpus samples plus
synthetic messages, each unsigned and DKIM2-signed (perl/bin/dkim2sign).

With --sympa, build only the extra synthetics the Sympa benchmark needs
(util/sympa-bench) into bench/corpus-sympa; the charset samples are
reused from the Mailman corpus on the box."""
import argparse, base64, random, subprocess, sys
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
    # Zero bytes base64 to ~137k identical lines: the worst case for a line
    # diff (last, so the rng-driven items above stay byte-identical).
    m = base('zeros 10MB'); m.set_content(text(1_000))
    m.add_attachment(bytes(10_000_000), maintype='application',
                     subtype='octet-stream', filename='zeros.bin')
    yield 'syn-zeros-10mb', m, 0

def b64_attachment(m, data, width, filename):
    """Attach data base64-encoded at `width` columns (the email package
    always uses 76)."""
    enc = base64.b64encode(data).decode('ascii')
    m.make_mixed()
    part = EmailMessage(policy=SMTP)
    part['Content-Type'] = 'application/octet-stream'
    part['Content-Disposition'] = f'attachment; filename="{filename}"'
    part['Content-Transfer-Encoding'] = 'base64'
    part.set_payload('\n'.join(enc[i:i + width]
                               for i in range(0, len(enc), width)) + '\n')
    m.attach(part)

def sympa_synthetic():
    """The Sympa-only cases (docs/superpowers/specs/2026-10-08-sympa-always-
    wrap-design.md, "Corpus").  Sizes are of the decoded content."""
    rng.seed(20261008)
    sizes = (('10k', 10_000), ('30k', 30_000), ('100k', 100_000),
             ('1mb', 1_000_000), ('5mb', 5_000_000))
    for label, n in sizes:
        m = base(f'b64 text {label}')
        m.set_content(text(n).replace('the', 'thé'), cte='base64')
        yield f'syn-b64-text-{label}', m, 0
        m = base(f'b64 html {label}')
        m.set_content('<html><body><p>' + text(n).replace('\n', '</p>\n<p>')
                      + '</p></body></html>\n', subtype='html', cte='base64')
        yield f'syn-b64-html-{label}', m, 0
    m = base('qp 100k')
    m.set_content(text(100_000).replace('the', 'thé'), cte='quoted-printable')
    yield 'syn-qp-100k', m, 0
    m = base('alternative qp')
    m.set_content(text(4_000))
    m.add_alternative('<html><body><p style="font-family: Arial, sans-serif">'
                      + text(8_000).replace('the', 'thé').replace('\n', ' ')
                      + '</p></body></html>\n', subtype='html',
                      cte='quoted-printable')
    yield 'syn-alt-qp', m, 0
    for mb in (1, 10, 25, 50):
        data = rng.randbytes(mb * 1_000_000)
        for width in (76, 72):
            m = base(f'attach {mb}MB b{width}')
            m.set_content(text(1_000))
            b64_attachment(m, data, width, f'blob{mb}.bin')
            yield f'syn-attach-{mb}mb-b{width}', m, 0
    m = base('latin1')
    m.set_content(text(4_000).replace('the', 'thé').replace('a ', 'à '),
                  charset='iso-8859-1', cte='8bit')
    yield 'syn-latin1', m, 0
    jp = 'メーリングリストはフッターを追加します。本文はもう一度折り返されます。'
    m = base('iso-2022-jp')
    m.set_content('\n'.join([jp] * 100) + '\n', charset='iso-2022-jp', cte='7bit')
    yield 'syn-iso2022jp', m, 0
    # Personalisation ("merge") "all" rewrites the body through the template
    # engine: a tag near the top and one in the middle.
    m = base('merge')
    body = text(4_000)
    mid = len(body) // 2
    mid = body.index('\n', mid) + 1
    m.set_content('Hello [% user.email %],\n\n' + body[:mid]
                  + 'You are subscribed as [% user.email %].\n' + body[mid:])
    yield 'syn-merge', m, 0

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
    ap = argparse.ArgumentParser()
    ap.add_argument('--sympa', action='store_true',
                    help='build only the Sympa extras, into bench/corpus-sympa')
    args = ap.parse_args()
    out = ROOT / 'bench' / 'corpus-sympa' if args.sympa else OUT
    for sub in ('unsigned', 'signed'):
        (out / sub).mkdir(parents=True, exist_ok=True)
    rows, skipped = [], []
    if args.sympa:
        items = [(i, m.as_bytes(policy=SMTP), f) for i, m, f in sympa_synthetic()]
    else:
        items = [(p.stem, p.read_bytes(), 0) for p in sorted((ROOT / 'corpus/sample').glob('*.eml'))]
        items += [(i, m.as_bytes(policy=SMTP), f) for i, m, f in synthetic()]
    for ident, raw, filt in items:
        raw = raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        try:
            signed = sign(raw)
        except subprocess.CalledProcessError as e:
            why = e.stderr.decode('utf-8', 'replace').strip() or f'exit {e.returncode}'
            signed = None
        else:
            why = None if (b'Message-Instance:' in signed and b'DKIM2-Signature:' in signed) \
                else 'no Message-Instance/DKIM2-Signature in the output'
        if why:
            skipped.append(ident)
            print(f'skip {ident}: signing failed: {why}', file=sys.stderr)
            continue
        (out / 'unsigned' / f'{ident}.eml').write_bytes(raw)
        (out / 'signed' / f'{ident}.eml').write_bytes(signed)
        rows.append(f'{ident}\t{len(raw)}\t{size_class(len(raw))}\t{filt}')
    (out / 'index.tsv').write_text('id\tsize\tclass\tfilter\n' + '\n'.join(rows) + '\n')
    print(f'{len(rows)} messages -> {out} ({len(skipped)} skipped)')
    # A partial corpus would make the benchmark silently incomparable.
    if not rows or skipped:
        print('error: ' + ('no messages' if not rows else
                           'skipped: ' + ', '.join(skipped)), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
