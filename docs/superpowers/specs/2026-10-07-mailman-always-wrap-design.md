# Mailman DKIM2: always MIME-wrap, null body Recipe, and a performance harness

Date: 2026-10-07

## Why

Stephen Turnbull (Mailman developer) reviewed the DKIM2 series on
mailman-developers (2026-10-05/06). His points:

- The CTE-preserving decoration (7bit/8bit, QP and base64 paths in
  `decorate.py`) is overengineered. MIME-wrapping the original verbatim and
  describing "add N lines, copy L..M, add K lines" is good enough; most posts
  are already wrapped today because most mail is HTML.
- Resource use matters: Mailman runs on 1 vCPU / 2 GB / small `/var` boxes
  with several out queues holding dozens of pickled messages. Extra copies of
  a message in RAM and in queue files can get runners OOM-killed or fill the
  disk. The archive is not a concern (decoration happens at delivery, after
  archiving).
- Lists that delete parts (content filtering) must not have to ship the
  deleted attachment in a change description, times every subscriber.
- Everything stays behind options, off by default.

Agreed in the thread: MIME-wrap, with a preamble note for readers without
MIME support.

## Decisions

- On a DKIM2-enabled list, **every** decorated message is wrapped (not only
  DKIM2-signed ones): one code path.
- Wrapping is a **raw splice** of the received octets, not a regeneration of
  the parsed message.
- A body changed before decoration gets a **null body Recipe**; the outbound
  milter gains an option to sign such messages.
- Performance is measured both in-process (per message) and with a soak run
  on real runners.

## §1 Mailman change

### Decorate on a DKIM2 list

Applies when the site option and the list's `dkim2_message_instance` flag are
both on. If both header and footer are empty, nothing changes (the existing
escape hatch).

**Body unchanged since ingress** (`msgdata['body-modified']` not set):

- The outer message gets `Content-Type: multipart/mixed; boundary=<fresh>`;
  its `Content-Transfer-Encoding` and `Content-Disposition` are removed.
- Its payload is set to a single string (the email generator writes a string
  multipart payload verbatim):
  1. a preamble: "This message was MIME-wrapped because the list adds DKIM2
     change records; a MIME-capable mail reader shows it as the sender
     intended." It is added to every wrapped message.
  2. if there is a header: `--b`, a `text/plain` part in the list charset with
     `Content-Disposition: inline`.
  3. `--b`, then the original top-level `Content-*` header fields exactly as
     received (folding intact) taken from `msg.original_bytes`, a blank line,
     then the original body octets verbatim. A message with no
     `Content-Type` gets none (the default `text/plain; charset=us-ascii`
     applies inside the part too).
  4. if there is a footer: `--b`, a footer part built as in step 2.
  5. `--b--`.
- The boundary is chosen so that it does not occur in the original body.
- The resulting body Recipe is literal lines, one copy range covering the
  original body, literal lines. The header Recipe records the outer
  `Content-*` changes.

**Body modified** (`msgdata['body-modified']` is true): decorate exactly as
upstream does. Egress then emits m=N+1 with `"b": null` (no body diff is
computed) and a normal header Recipe (draft-06 §5.1 forbids a null header
Recipe).

`body-modified` is set by:

- `mime-delete` whenever it changes the message (part removal, collapsing
  alternatives, HTML conversion, pass-through filtering).
- `dmarc` when the `wrap_message` mitigation wraps the message.

### Non-DKIM2 lists

`decorate.py` behaves byte-for-byte like upstream. The CTE-preserving patch
("Preserve the original Content-Transfer-Encoding when decorating") is
deleted, and `handlers/docs/decorate.rst` reverts to upstream.

### Snapshot simplification

- Ingress makes sure `msg.original_bytes` holds the snapshot: the received
  octets, or the serialized message when no octets were kept (older queue
  entries, internal paths), or the unstamped baseline in the existing
  Message-ID-Hash case.
- Egress diffs against `msg.original_bytes` instead of `mi-cache/*.orig`.
- `save_mi_original`, `load_mi_original`, `_cleanup_mi_original`,
  `_mi_cache_dir`, the `mi_file` msgdata key and the `snaps=` X-DKIM2-Info
  field are removed. There is then one copy of the original per queue entry
  instead of a pickled copy plus a file.

### Series

On each of `dkim2-3.3.10`, `dkim2-3.3.8` and `dkim2` (master):

1. Keep the bytes a message arrived with (unchanged).
2. Add DKIM2 Message-Instance headers at ingress and egress (now containing
   the DKIM2 wrap in `decorate.py`, the `body-modified` flags in
   `mime_delete.py` and `dmarc.py`, the null body Recipe and the snapshot
   simplification).
3. Add a per-list `dkim2_message_instance` flag (unchanged).

On 3.3.10 these follow the two py3.13 upstream fixes. Before rewriting, the
current heads are kept as historical branches `dkim2-cte-preserve-3.3.10`,
`dkim2-cte-preserve-3.3.8` and `dkim2-cte-preserve` (pushed to the `brong`
remote, never deleted), in case the CTE-preserving style is revived.
`mailman/README.md` names them. Re-export
with `util/export-list-patches.sh`, and `--check` must pass.
`mailman/README.md`, `DKIM2-MESSAGE-INSTANCE.md` and the list-host guide are
updated.

### Tests (Mailman)

- Splice: text/plain 7bit, 8bit, QP and base64; multipart/alternative;
  multipart/mixed; broken MIME (missing final boundary); header only; footer
  only; no Content-Type. Each output must undo to the m=N state
  byte-for-byte and verify (hashes + Recipe).
- Boundary collision: an original body containing the first candidate
  boundary.
- Null Recipe: `mime-delete` stripping a part, and `dmarc` wrap, both give
  `"b": null` with a header Recipe.
- Non-DKIM2 list: upstream `decorate.rst` doctest passes unchanged.
- The `mi-cache` directory is never created.

## §1b Mail::DKIM2 and dkim2-milter change

Probe (2026-10-07): today the milter already signs a top unsigned instance
with a null body Recipe. `chain_verifies` and the Verifier's
`_verify_mi_chain` both stop at an unrecoverable instance (`last if
unrecoverable`) and pass, so nothing below it is checked at all.

A null body Recipe loses only the body. The header Recipes still describe the
whole header history, so it is checked:

- **Mail::DKIM2** (`MessageInstance` and `Verifier`): when the walk reaches an
  instance with a null body Recipe, it continues **header-only**: undo applies
  header Recipes and leaves the body alone, and each lower instance's header
  hashes are checked down to m=1. Body hashes below the null instance are not
  checked; a body Recipe below it is not applied. A header hash mismatch, or a
  header Recipe that does not apply, anywhere in the history is a failure,
  exactly as without the null. `MessageInstance->verify` and `->undo` take
  `HeadersOnly => 1` for this. This changes what a receiver checks, so it is
  a Mail::DKIM2 release (0.14, or folded into 0.13 if that is not yet on
  CPAN).
- **dkim2-milter** gets `--allow-null-body-recipe`, default off:
  - off: a message whose top instance has a null body Recipe is not signed
    (`X-DKIM2-Info: not-signed=null-body-recipe`). This is a behaviour change
    from today's silent signing; nothing emits null body Recipes yet.
  - on: it is signed when the upstream DKIM2-Signatures verify and the
    header history checks out as above; the milter adds
    `X-DKIM2-Info: null-body-recipe`.
- One outbound milter process serves every signing listener on a host, so
  the option is per host. The list-host example unit
  (`deploy/examples/dkim2-milter-outbound.service`, which the box runs) turns
  it on with a comment, because that unit is for list hosts; the POD
  documents the default as off.

Tests in `perl/t/`: header-history walk (null at m=2 over m=1; null at m=3
over a normal m=2; tampered header below the null; bad header Recipe below
the null) in both `chain_verifies` and the Verifier; milter on and off in
`t/milter-script.t`.

Sympa needs no change: it does not modify bodies before its Message-Instance
step.

## §2 Performance harness

Location: `util/mailman-bench/` in interop. Raw results go to `bench/`
(gitignored). The committed summary is `docs/mailman-dkim2-performance.md`,
plus an HTML report page for sharing with the Mailman developers.

### Builds

Each build is installed from a git ref into its own venv under
`/opt/mailman/bench/<variant>/` on dkim2-dev:

| id | build | list DKIM2 flag |
|---|---|---|
| `up` | v3.3.10 + the two py3.13 fixes | n/a |
| `cte` | `dkim2-cte-preserve-3.3.10` | on |
| `cte-off` | same | off |
| `wrap` | new `dkim2-3.3.10` | on |
| `wrap-off` | same | off |

### Corpus

- The 317 charset-corpus samples (`corpus/`).
- Synthetic: plain 2 KB text; Outlook-style text + HTML (4 KB + 40 KB);
  1 MB, 10 MB and 50 MB base64 attachments; a 5 MB QP text body; a 10 MB
  attachment posted to a list with `filter_content` on (null Recipe path).
  The 50 MB case is the largest: the box has 2 GB RAM and runs production.
- Each message is run both unsigned and DKIM2-signed by the interop signer.

### In-process driver (`bench_inproc.py`)

Runs inside each venv with a temporary `var/` and Mailman's config, under
`systemd-run --scope -p MemoryMax=700M` so an oversized case can only kill
the benchmark, never production (an OOM is itself a recorded result). It
creates a list with a header and a footer, 25 members (configurable),
personalization off. Per message:

1. Parse as the LMTP handler does (setting `original_bytes` where the build
   does).
2. Enqueue to `in`, dequeue, and run the posting pipeline.
3. Enqueue to `out`, dequeue, and run delivery against a fake SMTP connection
   that captures the bytes sent.

Recorded per stage: CPU (`time.process_time`), tracemalloc peak, size of each
queue pickle (in / pipeline / out / archive), mi-cache bytes, wire bytes per
recipient, Message-Instance header length, and whether the output verifies
(Mail::DKIM2 undo). Each message is run 5 times and the median is kept.
Output is JSON lines.

### Soak (`bench_soak.sh`)

Each build runs, one at a time and under the same memory cap, as a real
Mailman instance on its own ports: LMTP in, an
aiosmtpd sink that discards everything out, prototype archiver on, 100
members. The full corpus is injected 3× as fast as LMTP accepts. Every second
it samples each runner's VmRSS/VmHWM and utime+stime from `/proc`, plus `du`
of `var/queue/*`, `var/archives` and mi-cache. Reported: peak and mean RSS
per runner, total CPU, peak queue disk, drain time. Production Mailman and
Postfix are not touched.

### Report (`bench_report.py`)

Compares each build with `up`: median, p95 and max per metric, broken out by
size class and by signed vs unsigned. Writes the markdown summary and the
HTML page.

### Success criteria

- Defensible numbers for queue RAM and disk, CPU, and wire bandwidth.
- `wrap-off` matches `up` within noise.
- A clear answer on whether `original_bytes` alongside the parsed message is
  acceptable at 50 MB.

## Acceptance (definition of done)

- Mailman's tests pass on the box for all three branches (3.3.10 py3.13,
  3.3.8 py3.12, master).
- Perl tests pass; the outbound milter on the box runs with
  `--allow-null-body-recipe`.
- Deployed to dkim2-dev: Mailman from `dkim2-3.3.10` (force-reinstall,
  migrations), milter via `deploy/deploy.sh`.
- Charset corpus replay: 317/317 through dkim2corpus@mailman.dkim2.com, all
  five verifiers; the smoke list round-trips.
- A filtered post on a `filter_content` test list arrives signed with
  `"b": null`.
- Benchmark run complete and the report published.

## Next stage (TODO, not this change)

- Sympa: apply the same always-wrap / null body Recipe policy to its
  decoration, and measure it with the same harness.
- The interop libraries (Perl Mail::DKIM2, Python, C, Go, JS): confirm each
  verifier accepts an unsigned top instance with a null body Recipe, and add
  the equivalent of `--allow-null-body-recipe` wherever a signer gates on
  the chain undoing; port the header-only history walk past a null body
  Recipe to the Python, C, Go and JS verifiers (and the browser verifier).

## Out of scope

- Upstreaming anything to the Python email package.
- An IN-queue size check before parsing (Steve's suggestion; a separate
  change).
- Sympa and the interop libraries: the next stage, above.
