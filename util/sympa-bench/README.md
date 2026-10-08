# sympa-bench

Benchmark harness comparing Sympa 6.2.78 builds with and without DKIM2: the
old CTE-preserving series and the always-wrap rebuild. It measures the
per-message cost in-process: CPU per stage, peak RSS, spool, wire and
Message-Instance size, and whether the output verifies. It runs on the
`dkim2` box under `/opt/sympa-bench/` and never touches production.
`/opt/sympa-dkim2`, `/usr/share/sympa`, `/root/interop`, the running
services and the live lists are only read, never modified. The Mailman
equivalent is `util/mailman-bench/`. The design is in
`docs/superpowers/specs/2026-10-08-sympa-always-wrap-design.md`, section
"Benchmark".

## The five builds

| id          | Sympa ref                                | lib            | DKIM2 |
|-------------|------------------------------------------|----------------|-------|
| `up`        | `6.2.78`                                 | `up/lib`       | n/a   |
| `cte`       | `dkim2-cte-preserve-6.2.78` (bc6d4413b)  | `cte/lib`      | on (no switch exists) |
| `cte-nomod` | same as `cte`                            | `cte/lib`      | Mail::DKIM2 not on `@INC` |
| `wrap`      | `dkim2` (the always-wrap series)         | `wrap/lib`     | list switch on |
| `wrap-off`  | same as `wrap`                           | `wrap/lib`     | list switch off |

A build is the ref's `src/lib` plus the `Sympa/Constants.pm` that the
production build generated. That file comes from
`/usr/share/sympa/lib`: the same 6.2.78 configure, and `Constants.pm.in` is
identical in all three refs. There is no `make install`. Mail::DKIM2 is
interop `perl/lib` at 0.15, in `/opt/sympa-bench/dkim2lib`. The box also has
0.14 installed system-wide, so `bench_inproc.pl` hides every Mail::DKIM2
from `@INC` when it isn't given `--dkim2lib`; that is what makes
`cte-nomod`.

## Scripts

Run locally:

- `../mailman-bench/make-corpus.py --sympa` builds the Sympa-only
  synthetics, unsigned and DKIM2-signed, into `bench/corpus-sympa`
  (`bench/` is gitignored). The synthetics are:
  - single-part base64 text and HTML at 10 KB, 30 KB, 100 KB, 1 MB and
    5 MB;
  - single-part QP;
  - multipart/alternative with a QP HTML part;
  - 1, 10, 25 and 50 MB attachments, base64-wrapped at 76 and at 72
    columns, with the same bytes at both widths;
  - latin1 and ISO-2022-JP bodies;
  - a body with `[% user.email %]` tags, for personalisation.

Run on the box:

- `setup-builds.sh` installs `/opt/sympa-bench/{up,cte,wrap}/lib` from
  `sympa.bundle`, checks `dkim2lib` is 0.15, and assembles
  `/opt/sympa-bench/corpus`. The corpus is the 317 charset samples
  symlinked from the Mailman corpus (`/opt/mailman/bench/corpus`), plus
  `corpus-sympa`, with a merged `index.tsv`. The script is idempotent: a
  build is redone only when its ref now resolves to a different commit.
- `bench_inproc.pl BUILD LIBDIR [--dkim2lib DIR] [--switch on|off]` runs one
  build over the corpus. The header comment documents the stages and
  options.
- `run-inproc.sh` runs every build in turn, never two at once. Each build
  runs in `systemd-run --scope -p MemoryMax=700M -p MemorySwapMax=0
  -p OOMPolicy=continue`. Before each build it waits for no Sympa or Mailman
  test suite to be running.

Shipping the sources (the box cannot fetch from GitHub):

    git -C ~/src/sympa bundle create /tmp/sympa-bench.bundle \
        6.2.78 dkim2-cte-preserve-6.2.78 dkim2
    scp /tmp/sympa-bench.bundle dkim2:/opt/sympa-bench/sympa.bundle
    rsync -a --delete ~/src/interop/perl/lib/ dkim2:/opt/sympa-bench/dkim2lib/
    rsync -a --delete ~/src/interop/bench/corpus-sympa/ dkim2:/opt/sympa-bench/corpus-sympa/
    scp util/sympa-bench/*.{sh,pl} dkim2:/opt/sympa-bench/
    ssh dkim2 bash /opt/sympa-bench/setup-builds.sh

## What the in-process driver measures

`bench_inproc.pl` loads the build's libraries with a throwaway `%Conf::Conf`
(ConfDef defaults) and a stub `Sympa::List`, the same bootstrap as
`t/DKIM2.t`. There is no database. `get_list_member` and `search_fullpath`
are stubbed, and `Sympa::Mailer::store` is replaced by a capture. Which
pipeline runs is read off the libraries:

- **`wrap`:** `Sympa::DKIM2::ingress`, then per packet `egress_context`,
  and `egress_add` inside the real `ProcessOutgoing::__twist_one`.
- **`cte`:** the old ProcessIncoming hook (`add_message_instance_ingress`,
  or `mi_original` when an instance is already there), a `.mi_orig` file
  beside the spool file, and the egress call inside `__twist_one`.
- **`up`:** neither hook.

Per message (unsigned and signed), and per list configuration, a forked
child runs the case:

| stage      | what is timed |
|------------|---------------|
| `ingress`  | `Sympa::Message->new` of the received text (LF line ends, as Postfix hands it over) and the ingress hook |
| `tolist`   | a TransformIncoming stand-in (subject tag, `List-Id`, `List-Unsubscribe`, `Precedence`), `dup`, `prepare_message_according_to_mode`, ToList's shelving |
| `spool`    | `to_string` to a file (plus `.mi_orig` for `cte`), then `new_from_file` once per packet, as bulk does |
| `decorate` | time inside `Message::decorate` and `Message::personalize` |
| `egress`   | `egress_context` + `egress_add` (`wrap`); `add_message_instance_*` during distribution (`cte`) |
| `total`    | all of the above and the rest of `__twist_one` (`dup` per packet or recipient), less the capture |

CPU is `CLOCK_PROCESS_CPUTIME_ID`. Each stage value is the median of up to
5 runs; fewer runs are made when the next one would pass a 240 s budget.
`peak_rss_kb` is the child's `VmHWM`. It includes the parent's inherited
pages, which `rss_base_kb` gives. The child runs under `alarm 300`. A
timeout, a death (`error`) or a cgroup OOM kill (`oom`) is recorded, and
the run moves on. The first wire copy of the first run is checked
afterwards by a separate verifier process that loads Mail::DKIM2 0.15
whatever the build loads. It runs `chain_verifies` on the CRLF wire text:

- `verifies`: the chain checks, or null when the output has no
  Message-Instance;
- `undo_ok`: it also undoes this hop's instance (m ≥ 2) with no null body
  Recipe on the way, so the body as received is recoverable;
- also `mi_count`, `top_m`, `null_body` and `verify_err`.

Recipients are `memberN@dN%50.example.net`. Packets come from
`Sympa::Spool::Outgoing::_get_recipient_tabs_by_domain`, with the default
`nrcpt` of 25. VERP, merge and tracking run one `__twist_one` per
recipient. The footer is UTF-8 with non-ASCII text, and under
personalisation it carries `[% user.email %]`.

List configurations are one factor at a time from `f-mime`:

| config          | change from `f-mime` (footer only, `footer_type` mime, personalisation off, VERP 0%, reception mail, 25 members) |
|-----------------|------|
| `f-mime`        | — |
| `hf-mime`       | `message_header` plus footer |
| `f-append`      | `footer_type` append |
| `hf-append`     | header plus footer, append |
| `pers-footer`   | personalisation, `mail_apply_on` footer |
| `pers-all`      | personalisation, `mail_apply_on` all |
| `verp100`       | VERP 100% (one `__twist_one` per recipient) |
| `txt`           | reception mode txt |
| `notice`        | reception mode notice |
| `m1000`         | 1000 members (40 packets) |
| `m1000-verp100` | 1000 members, VERP 100% (1000 `__twist_one`) |

The two 1000-member configurations run only on the synthetics and on every
10th charset sample, and `m1000-verp100` only below 2 MB. Otherwise one
build would take days.

Output is `/opt/sympa-bench/results/inproc-BUILD.jsonl`, one record per
message × configuration × signed/unsigned:

    {build, variant, switch, dkim2_version, msg_id, size, class, signed,
     config, members, stage_cpu:{ingress,tolist,spool,decorate,egress,total},
     runs, wall_s, peak_rss_kb, rss_base_kb, spool_bytes,
     wire_bytes_per_rcpt, mi_len_max, n_wire, packets, twists,
     verifies, undo_ok, mi_count, top_m, null_body, verify_err,
     timeout, oom, stage (where a timeout/OOM hit), error, log}

`log` is the first `err` or `notice` Sympa logged in the case. The wire copy
of each message under `f-mime` is kept in `results/eml/`. Results stay on
the box.

## Running

    ssh dkim2 'cd /opt/sympa-bench && nohup bash run-inproc.sh \
        > results/run-inproc.out 2>&1 &'

A smoke run on a few messages:

    WAIT=0 OUT=/opt/sympa-bench/results/smoke \
      BENCH_ARGS='--ids a,b,c --configs f-mime,m1000' bash run-inproc.sh
