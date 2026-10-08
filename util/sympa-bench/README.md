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
  `corpus-sympa` (plus Mailman's `syn-plain-2k` and `syn-outlook`), with a merged `index.tsv`. The script is idempotent: a
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

The DKIM2 work does not land in the same stage in every build:

- In `wrap`, building the MIME wrap happens inside `decorate`.
- In `cte`, the line diff happens in `egress`.

A comparison of DKIM2 cost therefore has to use `decorate + egress`, or
`total`, never `egress` alone.

CPU is `CLOCK_PROCESS_CPUTIME_ID`. Each stage value is the median of up to
5 runs; fewer runs are made when the next one would pass a 240 s budget.
`peak_rss_kb` is the child's `VmHWM`. It includes the parent's
inherited pages, which `rss_base_kb` gives. That baseline differs by
build. Builds that load Mail::DKIM2 (`cte`, `wrap`, `wrap-off`) start
3–5 MB higher than `up` and `cte-nomod` (smoke run). The report must therefore
compare the per-case cost `peak_rss_kb - rss_base_kb`, not
`peak_rss_kb`.

The 700M cap covers the whole scope: parent, child and verifier. A
higher baseline leaves less headroom, so near the cap a build with
Mail::DKIM2 loaded can be OOM-killed on a message that `up` just
survives. Read an OOM on the 25 and 50 MB cases with that in mind. The child runs under `alarm 300`. A
timeout, a death (`error`) or a cgroup OOM kill (`oom`) is recorded, and
the run moves on. The first wire copy of the first run is checked
afterwards by a separate verifier process that loads Mail::DKIM2 0.15
whatever the build loads. It runs `chain_verifies` on the CRLF wire text:

- `verifies`: the chain checks, or null when the output has no
  Message-Instance;
- `undo_ok`: it also undoes this hop's instance (m ≥ 2) with no null body
  Recipe on the way, so the body as received is recoverable;
- also `mi_count`, `top_m`, `null_body` and `verify_err`;
- `expect_mi`: true when DKIM2 is on for the build (`wrap` with the switch
  on, or `cte` with Mail::DKIM2 loadable). If such a build's wire copy
  has no Message-Instance, the record says `verifies: false` with
  `verify_err: "no instance"`. For the other builds, no instance means
  `verifies: null`;
- `pseudo_leak`: the spool pseudo-header `X-Sympa-DKIM2-Headers` reached
  the wire. This must always be false.

Packets come from `Sympa::Spool::Outgoing::_get_recipient_tabs_by_domain`,
with the defaults `nrcpt` 25 and `avg` 10. That function starts a new
packet when either of these is true:

- the packet already holds 25 recipients;
- it holds more than 10, and the next recipient's last two domain labels
  differ.

Recipients are set up for two cases:

- **Few domains** (every config except `m1000-manydom`): recipients are
  `memberN@d(N%50).example.net`. The last two labels are always
  `example.net`, so the domain rule never fires and packets fill to 25.
  1000 members make 40 packets.
- **Many domains** (`m1000-manydom`): recipients are
  `memberN@d(N%200).example`, which is 200 registrable domains. After
  sorting by domain, a packet ends at the first domain change after 10
  recipients, so there are more, smaller packets. VERP, merge and tracking run one `__twist_one` per
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
| `m1000`         | 1000 members, few domains (40 packets) |
| `m1000-manydom` | 1000 members over 200 domains (67 packets of 15) |
| `m1000-verp100` | 1000 members, VERP 100% (1000 `__twist_one`) |

The 1000-member configurations run only on the synthetics and on every
10th charset sample, and `m1000-verp100` only below 2 MB. Otherwise one
build would take days.

What is left out, and why:

- **Interactions.** The configurations change one factor at a time. They
  show what each factor costs on its own, not how factors combine: for
  example, append + personalisation all + VERP is not measured. The full
  cross product would be 144 configurations, days per build.
- **Digest mode.** A digest is a new message that Sympa composes, and
  Sympa never adds an instance to its own messages (no m=1 for digests).
  The always-wrap change has nothing to measure there. `nomail` and
  `summary` send nothing.
- **OOM kills.** A cgroup OOM kill is a recorded result, not the end of the
  run. That needs `-p OOMPolicy=continue`: systemd's default
  (`OOMPolicy=stop`) stops the whole scope at the first kill. A trial run
  ended that way, with SIGTERM to every process.

Output is `/opt/sympa-bench/results/inproc-BUILD.jsonl`, one record per
message × configuration × signed/unsigned:

    {build, variant, switch, dkim2_version, msg_id, size, class, signed,
     config, members, stage_cpu:{ingress,tolist,spool,decorate,egress,total},
     runs, wall_s, peak_rss_kb, rss_base_kb, spool_bytes,
     wire_bytes_per_rcpt, mi_len_max, n_wire, packets, twists,
     verifies, undo_ok, expect_mi, pseudo_leak, mi_count, top_m,
     null_body, verify_err,
     timeout, oom, stage (where a timeout/OOM hit), error, log}

`log` is the first `err` or `notice` Sympa logged in the case. The wire copy
of each message under `f-mime` is kept in `results/eml/`. Results stay on
the box.

## Running

The usual run is the quick profile, which takes about 10 minutes:

    ssh dkim2 'cd /opt/sympa-bench && bash run-inproc.sh --quick'

It covers:

- **Builds:** `up`, `cte` and `wrap`. The two switch-off builds are left
  out because Sympa's `util/off-identical.sh` already shows that `wrap`
  with the switch off is byte-identical to stock 6.2.78. The old series
  has no switch.
- **Messages:** 8, signed copies only:
  - `syn-plain-2k`: plain text, about 2 KB;
  - `syn-outlook`: Outlook-style text and HTML, about 21 KB, the closest
    in the corpus to the 40 KB case;
  - `syn-b64-text-100k`: single-part base64 text;
  - `syn-attach-1mb-b76` and `syn-attach-1mb-b72`: a 1 MB attachment,
    base64-wrapped at 76 and at 72 columns;
  - `syn-attach-10mb-b76`: a 10 MB attachment;
  - `syn-qp-100k`: a QP text body;
  - `syn-latin1`: a latin1 body. The footer is always UTF-8.

  `syn-plain-2k` and `syn-outlook` are the Mailman corpus's synthetics,
  linked in by `setup-builds.sh`.
- **Configurations:** `f-mime`, `pers-footer` and `m1000` (few
  domains). `m1000` skips messages of 2 MB and over
  (`--heavy-max-size 2000000`).
- **Runs:** each case is the median of 3 runs. `cte` cases time out at
  60 s (`--timeout 60 --budget 50`), recorded as `timeout`.
- **Waiting:** the profile checks once that no test suite is running
  before each build, and waits only while one is.

Results go to `results/quick/`. The script runs with `--resume`, so
delete that directory before running it again.

The full profile is every build, both signed and unsigned copies, all
342 messages, the 12 configurations and 5 runs per case. It takes a day
or more:

    ssh dkim2 'cd /opt/sympa-bench && nohup bash run-inproc.sh \
        > results/run-inproc.out 2>&1 &'

A smoke run on a few messages:

    WAIT=0 OUT=/opt/sympa-bench/results/smoke \
      BENCH_ARGS='--ids a,b,c --configs f-mime,m1000' bash run-inproc.sh
