# Mailman DKIM2 support: CPU, memory, queue and bandwidth cost

Measurements made 2026-10-07/08 for the mailman-developers discussion of
the DKIM2 Message-Instance series, which asked what DKIM2 support costs on a
small host (1 vCPU, 2 GB RAM, small `/var`). This note says what was measured
and how, gives the numbers, and lists what they do and do not show.

## Summary

- **CPU, typical post** (< 20 KB, 300 real-world messages, 25 members,
  header and footer): median 112 ms per post with DKIM2 (always-wrap series)
  against 104 ms for upstream 3.3.10, 1.08x. Delivery (decorate + egress) is
  most of the difference: 43 ms against 37 ms. The same build with DKIM2 off
  measured 96 ms, 0.93x. So upstream and an identical code path differ by
  about 7% between runs, which is about the same size as the DKIM2 cost.
- **CPU, large posts:** the wrap does not re-encode the original body, so
  it costs less than upstream decoration. 5 MB quoted-printable: 0.96 s
  against 1.88 s. 10 MB base64 attachment: 2.1 s against 3.6 s.
- **Memory per message** (tracemalloc peak): +3% for small posts. +34% for
  20 KB-1 MB posts (295 KiB against 220 KiB). For a 10 MB attachment,
  104.5 MiB against 99.6 MiB; the LMTP parse sets that peak, and it is the
  same in every build. Every build, upstream included, was OOM-killed at
  700 MB on a 50 MB attachment.
- **Queue disk:** in/pipeline/out queue pickles are 1.8-2.0x upstream,
  because they also carry the received octets. Archive queue copies are
  1.02-1.09x. In the soak, peak queue disk was 47.7 MiB against 26.2 MiB.
- **Bandwidth:** each delivered copy of a typical post gains about 1.5-2 KiB
  (+27-38%): roughly 0.85-1 KB of `Message-Instance` header plus the MIME
  wrap. Large posts are unchanged, or smaller where upstream re-encodes
  (5.8 MiB against 6.8 MiB for the 5 MB QP post).
- **Soak** (7 runners, 100 members, 3 passes, 1914 posts, 191,400
  deliveries per build, 700 MB cap): every build delivered every message,
  with no OOM kills and nothing shunted. Drain time, runner CPU and runner
  RSS varied between builds by no more than upstream varies against the
  DKIM2-off build.
- **With DKIM2 off** (site option or list flag), the always-wrap build
  measured the same as upstream on every queue and wire metric (1.00x).
- **Stock Mailman 3.3.10 did not hold up**, without any DKIM2 code, on the
  first soak attempt, which included the multi-megabyte posts: runners were
  OOM-killed at 700 MB and mail was shunted (see Findings).

## What was compared

Five configurations of Mailman 3.3.10, all on Python 3.13:

| id | Mailman commit | what it is |
|---|---|---|
| `up` | `a63d71e55` | v3.3.10 plus the two upstream Python 3.13 fixes (3.3.10 does not run on 3.13 without them) |
| `cte` | `b4c9c5a35` | the earlier DKIM2 series, which kept the body's Content-Transfer-Encoding when adding a header or footer (branch `dkim2-cte-preserve-3.3.10`), DKIM2 on |
| `cte-off` | `b4c9c5a35` | the same build with the list's DKIM2 flag off |
| `wrap` | `86bd7bee8` | the always-wrap series (branch `dkim2-3.3.10`), DKIM2 on |
| `wrap-off` | `86bd7bee8` | the same build with DKIM2 off |

The published `dkim2-3.3.10` head is `f86931bfc`. It differs from the
measured `86bd7bee8` in two ways. Verify/undo code that only tests use was
moved out of `message_instance.py` into test support. And the ingress
fallback for posts that arrive without received octets (`mailman inject`,
REST) became a single rule. The benchmark does not run that fallback: every
post comes in over LMTP. Nothing on the measured path changed.

In the always-wrap series, decoration on a DKIM2 list MIME-wraps the
original: a `multipart/mixed` whose parts are a short preamble, the list
header, the original `Content-*` fields and body spliced verbatim from the
received octets, and the footer. The body Recipe is then "literal lines,
one copy range, literal lines". If the body was changed before decoration
(content filtering, DMARC wrap), the message is decorated as upstream does
it, and egress records a null body Recipe instead of a diff. To make the
splice possible, the LMTP runner keeps the received octets on the message
(`msg.original_bytes`). It does so only when `[mta] message_instance` is on,
and ingress drops them for a list that has DKIM2 off.

## Method

### Host

The host has 2 vCPU and 2 GB RAM. It also runs a low-traffic production
Mailman/Postfix instance, so it is shared. Every benchmark process ran in
its own transient systemd unit with `MemoryMax=700M` and
`MemorySwapMax=0`. Only one build ran at a time, and the soaks ran
overnight (03:57-05:06 UTC). Each build is its own venv, installed from
production's `pip freeze` (web UI packages left out).

### Corpus

The corpus is 325 messages, each in an unsigned and a DKIM2-signed copy
(signed with the interop Perl signer, so a signed copy carries the sender's
`m=1` Message-Instance):

- 317 real-world messages from public archives, chosen for charset and
  encoding variety: Apache project lists in several languages, ruby-list
  and ruby-dev, Fedora Japanese, and the SpamAssassin public corpus.
- 8 synthetic messages: 2 KB plain text; Outlook-style text+HTML; 1, 10
  and 50 MB random base64 attachments; 5 MB of quoted-printable text; a
  10 MB `.zip` attachment that the list's content filter removes; and a
  10 MB attachment of zero bytes, whose base64 is about 137k identical
  lines (the worst case for a line diff).

Size classes, by the unsigned size: small < 20 KB (300 messages), medium
< 1 MB (19), large < 20 MB (5), huge (1, the 50 MB attachment).

### In-process benchmark

`bench_inproc.py` runs each build's own code the way the runners do, but
in one process and without an MTA. For each message: the LMTP runner's
parse and enqueue, the incoming runner's hand-off to the pipeline queue, the
posting pipeline, then the out queue and delivery. SMTP is replaced by
`smtplib.SMTP.send_message` writing into a buffer, so the bytes measured are
the bytes Mailman would hand to the MTA. The list has 25 members, a list
header and a footer, regular (bulk) delivery, and the prototype archiver on.

- **CPU** (`time.process_time`) per stage: the median of 5 runs without
  tracemalloc. Messages over 1 MB were run once.
- **Peak memory:** one separate run per message with tracemalloc. The
  number is the peak of Python allocations per stage, and the table shows
  the largest stage. It is not process RSS, which is higher.
- **Queue:** the sizes of the `.pck` files the message produces in the in,
  pipeline, out and archive queues.
- **Wire:** the size of the first delivered copy, and the total size of its
  `Message-Instance` header fields. The `DKIM2-Signature`, which the MTA
  adds, is not included.
- **Limits:** a message gets 120 s per run, then it is recorded as a
  timeout. A message killed by the cgroup is recorded as OOM. Both are
  excluded from medians.
- **Medians and ratios are like-for-like:** each one is computed over the
  messages that succeeded in every build being compared. So when `cte`
  timed out on two large synthetics, those two were also dropped from the
  other builds' large-class medians (n=3 instead of 5).

### Soak

`soak.sh` runs a real Mailman instance for one build: its own var
directory, ports and systemd units, LMTP in, and delivery to a local
discard SMTP sink. The setup:

- 100 members, a list header and footer, the prototype archiver on, and
  `max_message_size` 0.
- Only the 7 runners a post goes through: lmtp, in, pipeline, out,
  archive, retry, virgin. The default set of 12 idles at about 860 MB RSS
  on this host (about 72 MB each), which is over the 700 MB cap before any
  mail arrives.
- Corpus: every message under 2 MB (320 ids, signed and unsigned), posted
  3 times, for 1920 attempts per build. Mailman's LMTP runner refused 6 of
  them with "501 Message has defects", in every build including upstream:
  one SpamAssassin message, signed and unsigned, in each pass. That left
  1914 accepted posts and 191,400 expected deliveries.
- Once a second: the RSS and CPU ticks of each runner, and the disk used
  by the queue and archive directories. The run ends when the queues drain.

### Caveats

- The host is shared, and some differences are smaller than the noise. The
  clearest measure of noise is `up` against `wrap-off`, whose code paths
  are close to identical: they differ by up to 7% on in-process CPU
  medians, and by 10% on soak CPU and drain time.
- Peak memory is from tracemalloc: Python allocations only, per stage.
  The soak's RSS samples are summed over processes, so shared pages are
  counted more than once, and 1 s sampling can miss short peaks. The
  cgroup `memory.peak` includes page cache.
- The large-class medians rest on n=3. The per-message table below is more
  useful for large posts.
- The host has 2 vCPU. Each runner is a single process, so per-message CPU
  applies to a 1 vCPU host as it is. Soak drain times would not carry over
  directly.

## Results

### In-process, unsigned posts

Median per post (ratio against `up`). Values are rounded. `cte-off` is
left out of this table: it matches `up` on CPU and wire, and `cte` on
queue sizes, since the old series kept the received octets even with
DKIM2 off.

| class | metric | up | cte | wrap | wrap-off |
|---|---|---|---|---|---|
| small (n=300) | CPU total | 104 ms | 116 ms (1.12) | 112 ms (1.08) | 96 ms (0.93) |
| | CPU, out stage | 36.5 ms | 47.7 ms (1.31) | 43.3 ms (1.19) | 34.1 ms (0.93) |
| | peak memory | 197 KiB | 203 KiB (1.03) | 203 KiB (1.03) | 197 KiB (1.00) |
| | in-queue pickle | 5.2 KiB | 9.8 KiB (1.89) | 9.8 KiB (1.89) | 5.2 KiB (1.00) |
| | out-queue pickle | 6.4 KiB | 11.7 KiB (1.83) | 11.6 KiB (1.81) | 6.4 KiB (1.00) |
| | archive-queue pickle | 6.4 KiB | 11.7 KiB (1.83) | 7.0 KiB (1.09) | 6.4 KiB (1.00) |
| | wire, per copy | 5.2 KiB | 6.9 KiB (1.33) | 7.2 KiB (1.38) | 5.2 KiB (1.00) |
| medium (n=19) | CPU total | 114 ms | 130 ms (1.14) | 116 ms (1.02) | 104 ms (0.91) |
| | peak memory | 220 KiB | 309 KiB (1.40) | 295 KiB (1.34) | 220 KiB (1.00) |
| | out-queue pickle | 27.7 KiB | 53.9 KiB (1.95) | 53.8 KiB (1.94) | 27.7 KiB (1.00) |
| | archive-queue pickle | 27.7 KiB | 54.0 KiB (1.95) | 28.2 KiB (1.02) | 27.7 KiB (1.00) |
| | wire, per copy | 26.5 KiB | 28.2 KiB (1.06) | 28.1 KiB (1.06) | 26.5 KiB (1.00) |
| large (n=3) | CPU total | 1.83 s | 6.66 s (3.63) | 1.00 s (0.54) | 1.70 s (0.93) |
| | CPU, out stage | 1.23 s | 4.21 s (3.43) | 0.24 s (0.20) | 1.12 s (0.91) |
| | peak memory, pipeline stage | 23.4 MiB | 46.1 MiB (1.97) | 46.1 MiB (1.97) | 23.4 MiB (1.00) |
| | peak memory, largest stage | 47.6 MiB | 46.1 MiB (0.97) | 46.1 MiB (0.97) | 47.6 MiB (1.00) |
| | out-queue pickle | 5.8 MiB | 11.5 MiB (2.00) | 11.5 MiB (2.00) | 5.8 MiB (1.00) |
| | archive-queue pickle | 5.8 MiB | 11.5 MiB (2.00) | 5.8 MiB (1.00) | 5.8 MiB (1.00) |
| | wire, per copy | 6.8 MiB | 5.8 MiB (0.84) | 5.8 MiB (0.84) | 6.8 MiB (1.00) |

The `Message-Instance` fields total 983 B on a small post (Mailman adds
both `m=1` and `m=2`), 774 B on a medium one and 668 B on a large one.

### In-process, signed posts

These arrive with the sender's `m=1` (127 B). The "MI added" row is the
paired increase in `Message-Instance` bytes over `up`.

| class | metric | up | cte | wrap | wrap-off |
|---|---|---|---|---|---|
| small (n=300) | CPU total | 101 ms | 121 ms (1.21) | 109 ms (1.09) | 104 ms (1.03) |
| | CPU, out stage | 35.7 ms | 48.8 ms (1.37) | 42.3 ms (1.19) | 36.5 ms (1.02) |
| | peak memory | 198 KiB | 205 KiB (1.04) | 204 KiB (1.03) | 199 KiB (1.01) |
| | out-queue pickle | 7.1 KiB | 12.5 KiB (1.77) | 12.4 KiB (1.76) | 7.1 KiB (1.00) |
| | archive-queue pickle | 7.1 KiB | 12.5 KiB (1.77) | 7.2 KiB (1.02) | 7.1 KiB (1.00) |
| | wire, per copy | 5.9 KiB | 7.1 KiB (1.21) | 7.4 KiB (1.27) | 5.9 KiB (1.00) |
| | MI added | - | 811 B | 858 B | 0 B |
| medium (n=19) | CPU total | 113 ms | 147 ms (1.30) | 106 ms (0.94) | 113 ms (0.99) |
| | peak memory | 223 KiB | 312 KiB (1.40) | 299 KiB (1.34) | 223 KiB (1.00) |
| | out-queue pickle | 28.3 KiB | 54.9 KiB (1.94) | 54.8 KiB (1.93) | 28.3 KiB (1.00) |
| | wire, per copy | 27.2 KiB | 28.4 KiB (1.04) | 28.5 KiB (1.05) | 27.2 KiB (1.00) |
| | MI added | - | 677 B | 649 B | 0 B |
| large (n=3) | CPU total | 1.88 s | 5.63 s (2.99) | 0.96 s (0.51) | 1.62 s (0.86) |
| | CPU, out stage | 1.20 s | 3.03 s (2.52) | 0.25 s (0.21) | 0.96 s (0.79) |
| | peak memory, pipeline stage | 23.4 MiB | 46.1 MiB (1.97) | 46.1 MiB (1.97) | 23.4 MiB (1.00) |
| | out-queue pickle | 5.8 MiB | 11.5 MiB (2.00) | 11.5 MiB (2.00) | 5.8 MiB (1.00) |
| | wire, per copy | 6.8 MiB | 5.8 MiB (0.84) | 5.8 MiB (0.84) | 6.8 MiB (1.00) |
| | MI added | - | 444 B | 543 B | 0 B |

### Large and huge synthetic posts, one at a time (signed copies)

CPU total per post. The unsigned copies show the same pattern.

| post (size as received) | up | cte | cte-off | wrap | wrap-off |
|---|---|---|---|---|---|
| 1 MB attachment (1.3 MiB) | 0.42 s | 0.76 s | 0.41 s | 0.33 s | 0.38 s |
| 5 MB quoted-printable (5.8 MiB) | 1.88 s | 8.02 s | 1.79 s | 0.96 s | 1.62 s |
| 10 MB attachment (13.1 MiB) | 3.64 s | 5.63 s | 3.49 s | 2.08 s | 3.19 s |
| 10 MB zero-filled attachment (13.1 MiB) | 3.30 s | > 120 s | 3.80 s | 2.14 s | 3.47 s |
| 10 MB zip, removed by the content filter (13.1 MiB) | 0.73 s | > 120 s | 1.13 s | 1.16 s | 0.55 s |
| 50 MB attachment | OOM | OOM | OOM | OOM | OOM |

Memory, queue and wire for `up` and `wrap` (`wrap-off` equals `up`):

| post | peak memory, up / wrap | out-queue pickle, up / wrap | wire per copy, up / wrap | MI fields, wrap |
|---|---|---|---|---|
| 1 MB attachment | 10.0 / 10.6 MiB | 1.3 / 2.6 MiB | 1.3 / 1.3 MiB | 670 B |
| 5 MB quoted-printable | 47.6 / 46.1 MiB | 5.8 / 11.5 MiB | 6.8 / 5.8 MiB | 693 B |
| 10 MB attachment | 99.6 / 104.5 MiB | 13.1 / 26.1 MiB | 13.1 / 13.1 MiB | 670 B |
| 10 MB zero-filled | 99.6 / 104.5 MiB | 13.1 / 26.1 MiB | 13.1 / 13.1 MiB | 670 B |
| 10 MB zip, filtered | 99.6 / 99.6 MiB | 4.4 KiB / 13.1 MiB | 2.6 / 3.5 KiB | 697 B |

For the 10 MB posts, the peak is in the LMTP parse stage, which is the same
code in every build. Even with that stage counted, every build was
OOM-killed at 700 MB on the 50 MB post.

### Soak

All five builds drained with 191,400 of 191,400 deliveries, 0 OOM kills,
0 held, 0 shunted and 0 in the bad queue.

| build | drain | runner CPU | cgroup peak | queue disk peak | archives |
|---|---|---|---|---|---|
| up | 845 s | 1014 s | 628 MiB | 26.2 MiB | 27.4 MiB |
| cte | 911 s | 1128 s | 635 MiB | 47.9 MiB (+2.6 MiB mi-cache) | 27.9 MiB |
| cte-off | 773 s | 942 s | 637 MiB | 47.8 MiB | 27.4 MiB |
| wrap | 741 s | 901 s | 645 MiB | 47.7 MiB | 27.8 MiB |
| wrap-off | 767 s | 922 s | 627 MiB | 26.3 MiB | 27.4 MiB |

Runner CPU is the sum over Mailman's runners; the harness's sink is
excluded. Peak RSS of the runners that handle the message body:

| build | in | pipeline | out | archive |
|---|---|---|---|---|
| up | 86.6 MiB | 92.1 MiB | 91.6 MiB | 86.0 MiB |
| cte | 94.7 MiB | 101.6 MiB | 102.3 MiB | 94.3 MiB |
| cte-off | 92.9 MiB | 100.8 MiB | 97.5 MiB | 91.2 MiB |
| wrap | 92.0 MiB | 97.0 MiB | 96.6 MiB | 91.3 MiB |
| wrap-off | 91.1 MiB | 93.6 MiB | 97.9 MiB | 95.6 MiB |

The other runners (master, lmtp, retry, virgin) were at 84-103 MiB in every
build.

## Findings

1. **CPU.** On typical posts, always-wrap adds about 6-9 ms per post
   (median, 25 members, bulk delivery), mostly in decorate and egress
   (serialising once and SHA-256). That is about the size of the run-to-run
   noise on this host. On posts over 1 MB it costs less than upstream,
   since upstream decoration re-encodes the original body and the wrap
   copies it. The old CTE-preserving series cost 1.1-1.4x on typical posts
   and 3x on large ones, and exceeded 120 s on two 10 MB posts.
2. **Memory.** Per-message Python allocation grows 3% on small posts,
   about a third on 20 KB-1 MB posts, and doubles in the pipeline stage on
   large posts (one more copy of the received octets). The largest stage
   for a large post is still the LMTP parse, which DKIM2 does not touch. In
   the soak, the body-handling runners peaked about 5 MiB higher than upstream,
   but `wrap-off` (code close to upstream) also differs from upstream by up
   to 10 MiB, so this run does not resolve the difference.
3. **Queue disk** is the clearest cost. The in, pipeline and out queue
   pickles carry the received octets next to the parsed message: 1.8x on
   small posts, 2.0x on large ones. The soak's peak queue disk went from
   26 to 48 MiB. On a host where several out-queue entries for multi-MB
   posts can sit in retry, that is double the space.
4. **Bandwidth.** About 1.5-2 KiB more per delivered copy of a typical
   post: under 1 KB of `Message-Instance`, plus the wrap's preamble and
   part headers. On a 100-member list that is about 150-200 KiB per post.
   Large posts are the same size, or smaller where upstream re-encodes.
5. **Content filtering.** When the filter deletes an attachment, the wrap
   build emits a null body Recipe. The deleted content does not go into a
   header to every subscriber: the `Message-Instance` fields came to 697 B
   for the filtered 10 MB zip. The old series built a multi-megabyte
   `Message-Instance` value in that case and spent more than 120 s on it.
6. **Off means off.** With the site option or the list flag off, the wrap
   build's queue pickles, archive copies and wire bytes are the same as
   upstream's (1.00x), because the received octets are not kept. The old
   series kept them even when off (`cte-off` pickles 1.7-2.0x).
7. **Stock Mailman on 700 MB.** The first soak attempt used the full
   corpus, multi-megabyte synthetics included (100 members, 3 passes). On
   `up`, with no DKIM2 code, it produced 5 runner OOM kills at the 700 MB
   cap, 1292 shunted messages, and about 64,000 of about 193,000 expected
   deliveries, and the LMTP runner then refused further posts. That run
   was stopped to protect the production instance on the same host. The
   soak above was then limited to posts under 2 MB, and large posts are
   covered only by the in-process numbers. Within a 700 MB budget, stock
   Mailman with 7 runners could not carry 10 MB posts to 100 members
   before any DKIM2 code was involved.

### Changes made because of these measurements

The benchmark was built while the always-wrap series was being written,
and these changes went into the series because of it:

- The body Recipe diff was quadratic on repeated lines, and the wrap's
  preamble defeated the append-only fast path. The 10 MB zero-filled post
  is in the corpus to catch this. It is now a contiguous-run scan: 175,467
  lines take 0.012 s.
- `Message-Instance` header folding was quadratic on a multi-megabyte
  value. Fixed in the wrap series; the old series still has it.
- The received octets are kept only when `[mta] message_instance` is on,
  and are dropped at ingress for a list with DKIM2 off. Before this
  change, every site paid the 2x pickle size.
- Archive and NNTP queue copies no longer carry the received octets (2x
  down to 1.0-1.09x).
- The wrap's body Recipe now comes from the layout the wrap is built from,
  not from a diff, and the original part is held as one bytes object, not
  one string per line. For a 10 MB attachment (13.7 MiB as received), a
  separate tracemalloc harness (`mi_10mb.py`) measured:
  - decorate + egress peak: 93.7 MiB down to 29.1 MiB
  - ingress peak: 50.8 MiB down to under 1 MiB
  - ingress time: 0.61 s down to 0.11 s

## Remaining costs and options

What is left is one copy of the received octets:

- in the in, pipeline and out queue pickles, about 1.8-2.0x upstream's
  size;
- in the pipeline runner's memory, while that runner holds the message.

The splice needs the octets at decoration time, in the out runner. A
filtered post, which gets a null body Recipe, still carries all of them
(13.1 MiB in the out queue for the filtered 10 MB zip, against 4.4 KiB
upstream), although egress then needs only their header block.

Options for discussion (none implemented):

- **Drop the body octets once the body is modified.** After
  `mime-delete` or the DMARC wrap marks the body modified, keep only the
  header block of the received octets. This removes the filtered-post
  case above.
- **Queue only the bytes.** A `Message.__getstate__` that pickles the
  headers plus the original octets, not the parsed body as well, and
  re-parses when the message is loaded. Queue files would then be close to
  upstream size. It costs a parse per dequeue and touches every runner's
  path through the switchboard, so it is a larger change and needs its
  own measurement.

## How to reproduce

The harness is in `util/mailman-bench/` in this repository; see its
README. Results and the generated report (`bench/`) are not committed.

    # locally: build the corpus (needs the interop Perl signer)
    util/mailman-bench/make-corpus.py            # -> bench/corpus, 325 messages
    rsync -a bench/corpus util/mailman-bench/ BOX:/opt/mailman/bench/

    # on the box: one venv per build (up, cte, wrap), from the refs above
    /opt/mailman/bench/setup-builds.sh

    # in-process, every build in turn, each attempt capped at 700M
    /opt/mailman/bench/run-inproc.sh

    # soak, one build at a time, on the < 2 MB subset of the corpus
    # (run-soaks.sh builds corpus-soak/ and runs soak.sh for every build)
    WAIT=0 bash /opt/mailman/bench/run-soaks.sh

    # locally: pull results/ into bench/results and build bench/report.{md,json}
    util/mailman-bench/bench_report.py

    # 10 MB decorate/egress allocation check: util/mailman-bench/mi_10mb.py is a
    # nose2 test module, copied into a Mailman checkout; see its docstring

`setup-builds.sh` builds `wrap` from the current head of
`dkim2-3.3.10`. To reproduce these numbers exactly, pin it to `86bd7bee8`.
