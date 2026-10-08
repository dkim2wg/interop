#!/usr/bin/env python3
"""Compare Sympa benchmark builds with `up`, as markdown on stdout.

Usage: bench_report.py [RESULTS_DIR]     (default: results/quick on the box)

Reads RESULTS_DIR/inproc-<build>.jsonl (see bench_inproc.pl) and prints one
table per message x configuration.  Each build is shown beside `up`:

  CPU       total process CPU for the case, and decorate+egress (where the
            DKIM2 work lands in both pipelines), median of the runs
  RSS       peak_rss_kb - rss_base_kb, the cost of the case itself
  wire/rcpt bytes on the wire per recipient
  MI        longest Message-Instance header, in bytes
  verifies  the output chain verifies (- when the build adds no instance)
  fail      timeout or oom (such a row has no CPU or RSS to compare)

Stdlib only.
"""
import json, sys
from collections import defaultdict
from pathlib import Path

BUILDS = ['up', 'cte', 'cte-nomod', 'wrap', 'wrap-off']


def load(res):
    rows = defaultdict(dict)  # (msg, config) -> build -> row
    for f in sorted(Path(res).glob('inproc-*.jsonl')):
        for line in f.open():
            try:
                r = json.loads(line)
            except ValueError:
                continue  # half-written last line of a running benchmark
            rows[(r['msg_id'], r['config'])][r['build']] = r
    return rows


def failed(r):
    return r.get('timeout') or r.get('oom') or r.get('error') or 'stage_cpu' not in r


def cpu(r):
    s = r['stage_cpu']
    return s['total'], s['decorate'] + s['egress']


def rss_mb(r):
    return (r['peak_rss_kb'] - r['rss_base_kb']) / 1024


def secs(x):
    return f'{x * 1000:.0f} ms' if x < 1 else f'{x:.1f} s'


def vs(x, base):
    return f' ({x / base:.1f}x)' if base and base >= 0.01 else ''


def main():
    res = sys.argv[1] if len(sys.argv) > 1 else 'results/quick'
    rows = load(res)
    print('| message | config | build | CPU total | decorate+egress | RSS delta | '
          'wire/rcpt | MI header | verifies | fail |')
    print('|---|---|---|---:|---:|---:|---:|---:|:-:|---|')
    for (msg, cfg), by in sorted(rows.items(), key=lambda kv: (kv[1].get('up', next(iter(kv[1].values())))['size'], kv[0])):
        up = by.get('up')
        for b in BUILDS:
            r = by.get(b)
            if not r:
                continue
            ver = {True: 'yes', False: 'NO', None: '-'}[r.get('verifies')]
            if failed(r):
                kind = 'timeout' if r.get('timeout') else 'oom' if r.get('oom') else 'error'
                print(f'| {msg} | {cfg} | {b} | | | | | | {ver} | {kind} |')
                continue
            t, de = cpu(r)
            upok = up and not failed(up)
            ut, ude = cpu(up) if upok else (0, 0)
            tt = secs(t) + (vs(t, ut) if b != 'up' else '')
            dd = secs(de) + (vs(de, ude) if b != 'up' else '')
            rd = f'{rss_mb(r):+.0f} MB'
            mi = r.get('mi_len_max')
            print(f'| {msg} | {cfg} | {b} | {tt} | {dd} | {rd} | '
                  f'{r["wire_bytes_per_rcpt"]} | {mi if mi else "-"} | {ver} | |')


if __name__ == '__main__':
    main()
