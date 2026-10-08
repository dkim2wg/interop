# Sympa DKIM2 support: CPU, memory, wire and Message-Instance cost

Measurements made 2026-10-08 of Sympa 6.2.78 with and without DKIM2
Message-Instance support. The comparison is between stock Sympa, the old
CTE-preserving series, and the always-wrap rebuild. This is a quick profile
(about 10 minutes of benchmarking), not a soak: it answers "what does one
message cost in each build", not "how does a busy list server behave over a
day".

## What was measured

Three builds, all libraries of Sympa 6.2.78 with the `Constants.pm` of the
production build, run in-process (no daemon, no database):

| id | Sympa ref | what it is |
|---|---|---|
| `up` | `6.2.78` | stock |
| `cte` | `dkim2-cte-preserve-6.2.78` (`bc6d4413b`) | the old series: keeps the body's Content-Transfer-Encoding, line-diffs the body at egress |
| `wrap` | `dkim2` (`254bae3fa`) | the always-wrap rebuild, switch on, with Mail::DKIM2 0.15 |

Eight messages, each arriving DKIM2-signed (so the list adds `m=2`):
`syn-plain-2k`, `syn-outlook` (about 21 KB, text and HTML), `syn-latin1`,
`syn-b64-text-100k`, `syn-qp-100k`, a 1 MB attachment base64-wrapped at 76
and at 72 columns (same bytes), and a 10 MB attachment at 76. Three list
configurations, one factor at a time from a MIME-appended footer, 25 members:
`f-mime`, `pers-footer` (personalised footer, one decorate per recipient)
and `m1000` (1000 members, 40 packets; under 2 MB only). Each case is the
median of 3 runs. CPU is process CPU time. RSS is the case's own cost, peak
RSS less the baseline of the forked child. Every build runs in a 700 MB
cgroup, and the `cte` build is cut off at 60 s per case. The box is the
`dkim2` host: 2 vCPU, 2 GB (a small cloud VM). The wire copy of each case is
checked afterwards with Mail::DKIM2's verifier.

Raw rows for the run are in `inproc-*.jsonl`; `util/sympa-bench/bench_report.py`
turns them into the full 69-row table.

## Headline

CPU total for one message, `pers-footer` (the heaviest per-recipient
configuration), then the cost of the DKIM2 header and of memory.

| message | up | cte | wrap | MI header cte / wrap | RSS delta up / cte / wrap |
|---|---:|---:|---:|---:|---:|
| plain 2 KB | 195 ms | 425 ms (2.2x) | 172 ms (0.9x) | 424 / 425 B | +7 / +7 / +7 MB |
| outlook 21 KB | 226 ms | 3.3 s (14.6x) | 202 ms (0.9x) | 18195 / 468 B | +7 / +9 / +8 MB |
| latin1 | 168 ms | 434 ms (2.6x) | 141 ms (0.8x) | 428 / 366 B | +7 / +7 / +7 MB |
| base64 text 100 KB | 182 ms | 1.1 s (6.2x) | 238 ms (1.3x) | 436 / 437 B | +10 / +16 / +10 MB |
| QP text 100 KB | 645 ms | 26.7 s (41x) | 210 ms (0.3x) | 133869 / 445 B | +9 / +15 / +10 MB |
| 1 MB attachment, 76 col | 575 ms | 6.0 s (10x) | 758 ms (1.3x) | 322 / 472 B | +34 / +90 / +31 MB |
| 1 MB attachment, 72 col | 571 ms | timeout (>60 s) | 703 ms (1.2x) | - / 472 B | +34 / - / +32 MB |
| 10 MB attachment, 76 col | 3.3 s | OOM at 700 MB | 5.1 s (1.5x) | - / 476 B | +274 / - / +214 MB |

With the default `f-mime` configuration the pattern is the same and the
wrap build is 0.6x to 1.8x of stock (10 MB attachment: 818 ms against
556 ms). `m1000` on messages under 2 MB: wrap is 0.6x to 1.7x of stock
(plain 2 KB: 333 ms against 346 ms; 1 MB attachment: 2.9 s against 1.7 s),
the old series up to 38x (QP 100 KB: 46.5 s against 1.2 s).

Wire bytes per recipient: wrap adds the `Message-Instance` header (about
0.45 KB) and the MIME wrap, so a 2 KB message grows from 3545 to 4215
bytes and larger messages by well under 1%. The old series on the 100 KB QP
message sent 257 KB per recipient against 123 KB stock, because of its
134 KB header.

Every `wrap` output verifies and undoes. Every `cte` output that was
produced verifies too, but not every case was produced (see below). The
`up` rows say "NO" in the full report: stock Sympa changes the message and
adds no instance, so the inbound chain breaks, which is what DKIM2 is for.

## Findings

- **The old series had quadratic cases.** Its line diff at egress is
  fine on short lines and bad on others. Outlook-style HTML costs 14.6x
  stock with personalisation, 100 KB of QP 41x (26.7 s), and the 1 MB
  attachment at 72 columns timed out at 60 s in every configuration: a
  body whose lines are all different between original and wrapped is the
  worst case for a diff. The 10 MB attachment was OOM-killed at 700 MB.
  The QP message produced a 134 KB `Message-Instance` header, because the
  Recipe listed the changed lines.
- **The rebuild is within 1.1x to 1.7x of stock CPU** for the cases that
  carry real work (1.2-1.3x for 100 KB base64 and 1 MB attachments with
  personalisation, 1.5x for 10 MB, 1.7x for 1 MB with 1000 members), and at
  stock for small messages. It is faster than stock where stock re-encodes
  the body (QP 100 KB: 0.3x with personalisation), because the wrap copies
  the original lines instead.
- **Its Message-Instance header is 370 to 480 bytes,** for every message,
  because the body Recipe is one copy range or a null.
- **Memory is at or below stock** for every message of 100 KB and over
  (10 MB attachment: +214 MB against +274 MB for stock) and the same for
  small ones. The `cte` build used 2.6x stock RSS for the 1 MB attachment (+90 MB against +34 MB).
- **Task 12 (one body hash per copy, no MIME parse at egress)** was
  measured on the 10 MB attachment with a personalised footer. Before (an earlier run of the same quick profile): 27.5 s
  CPU and +600 MB RSS. After, in this run: 5.1 s and +214 MB. Stock: 3.3 s
  and +274 MB. (Stock was 3.0 s in the earlier run; the box varies by
  about 10% between runs.)

## Limits of this measurement

- One factor at a time. `pers-footer` with VERP, `append` with
  personalisation `all` and similar combinations were not measured.
- A quick profile: 8 messages, 3 configurations, 3 runs, signed copies
  only, on one 2-vCPU host. The charset corpus (about 300 messages) and the
  other 9 configurations are in the harness but were not run.
- Process CPU time for the in-process pipeline. No daemon start-up, no
  database, no SMTP; spool disk is measured but not shown here. There was no
  soak, so queue behaviour under load, drain time and the cost of the real
  mailer are not covered.
- The benchmark verifier is Mail::DKIM2, which is also what the builds
  use to sign.
- The `cte` build is stopped at 60 s per case, so its worst cases are
  lower bounds. Near the 700 MB cap the 3-5 MB higher baseline of builds that
  load Mail::DKIM2 can matter.

## Re-running

The harness is `util/sympa-bench/` in this repository; see its README for
the build set-up and the stages. In short, from `~/src/interop`:

    # ship the sources (the box cannot fetch from GitHub)
    git -C ~/src/sympa bundle create /tmp/sympa-bench.bundle \
        6.2.78 dkim2-cte-preserve-6.2.78 dkim2
    scp /tmp/sympa-bench.bundle dkim2:/opt/sympa-bench/sympa.bundle
    rsync -a --delete perl/lib/ dkim2:/opt/sympa-bench/dkim2lib/
    rsync -a --delete bench/corpus-sympa/ dkim2:/opt/sympa-bench/corpus-sympa/
    scp util/sympa-bench/*.{sh,pl} dkim2:/opt/sympa-bench/
    ssh dkim2 bash /opt/sympa-bench/setup-builds.sh

    # about 10 minutes, memory-capped
    ssh dkim2 'cd /opt/sympa-bench && OUT=results/final bash run-inproc.sh --quick'

    rsync -a dkim2:/opt/sympa-bench/results/final/ results/
    util/sympa-bench/bench_report.py results
