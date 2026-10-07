# mailman-bench

Benchmark harness comparing Mailman builds with and without DKIM2 and the
always-wrap change: per-message cost (CPU time, wall time) in-process, and
memory/throughput under a sustained soak. It runs on the `dkim2` box in
separate venvs under `/opt/mailman/bench/` and never touches production
(`/opt/mailman/venv`, the running services and the live lists are only read,
never modified).

## The five builds

| id        | Mailman ref                                   | venv         | DKIM2 |
|-----------|-----------------------------------------------|--------------|-------|
| `up`      | `a63d71e55` (v3.3.10 + the two py3.13 fixes)  | `up`         | n/a   |
| `cte`     | `dkim2-cte-preserve-3.3.10`                   | `cte`        | on    |
| `cte-off` | same as `cte`                                 | `cte` (reused) | off |
| `wrap`    | `dkim2-3.3.10` (always-wrap series)           | `wrap`       | on    |
| `wrap-off`| same as `wrap`                                | `wrap` (reused) | off |

`cte-off` and `wrap-off` are not separate builds: they reuse the `cte` and
`wrap` venvs with the DKIM2 list flag turned off, so the difference from the
`on` run is the cost of DKIM2 alone.

## Scripts

Run locally:

- `make-corpus.py` builds the benchmark corpus (charset samples plus
  synthetics, unsigned and signed).
- `bench_report.py` turns the results gathered from the box into the
  comparison report.

Run on the box:

- `soak.sh BUILD VENV on|off|na` (+ `sink.py`) runs one real Mailman instance
  (own ports 18024/18025/18001, own units `mmsoak-*`, master capped at 700M in
  its own cgroup) over the corpus 3x and writes `results/soak-BUILD*.{tsv,json}`.
  Only the delivery-path runners are started (the full set idles above the cap).
  TSV notes: runner labels look like `in:0:1` (group on the part before the
  first colon; the sink is `sink`); `cpu_ticks` are raw clock ticks (CLK_TCK,
  normally 100/s); the cgroup `memory.peak` in the summary includes page cache,
  so compare builds on the per-runner RSS columns.
- `setup-builds.sh` builds the venvs `/opt/mailman/bench/{up,cte,wrap}/venv`
  from the refs above, installing the production `pip freeze` minus the web UI
  packages. Idempotent: a build is redone only when its ref now resolves to a
  different commit than the one recorded in `<id>/ref`. **`wrap` tracks the
  remote branch `dkim2-3.3.10`, so re-run the script after that branch is
  force-pushed.**
- `run-inproc.sh` runs the in-process benchmark of one build over the corpus.
- `soak.sh` runs the sustained-load soak of one build.
- `mi_10mb.py` (a nose2 test module copied into a Mailman checkout) times one
  10 MB post through ingress, decorate and egress and reports tracemalloc peaks.

## Running safely

The box is production (2 vCPU, 2 GB RAM). Run one build at a time, and wrap
each benchmark or soak in a memory cap so a runaway cannot push production
into the OOM killer:

    systemd-run --scope -p MemoryMax=700M <command>

`setup-builds.sh` applies the same cap to its `pip install` steps.
