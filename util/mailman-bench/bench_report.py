#!/usr/bin/env python3
"""Aggregate Mailman benchmark results into bench/report.{md,json}.

Usage: bench_report.py [--results DIR]   (default: <repo>/bench/results)

Reads results/inproc-<build>-<signed>.jsonl (harness rows) and
results/soak-<build>{.tsv,-du.tsv,-summary.json} (see soak.sh for formats).
Failure rows (oom/timeout/crash/undelivered) carry no metrics: they are
reported as censored counts, never averaged in.  Stdlib only.
"""
import argparse, json, statistics
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
METRICS = ['cpu_in', 'cpu_pipeline', 'cpu_out', 'peak_in', 'peak_pipeline', 'peak_out',
           'pck_in', 'pck_pipeline', 'pck_out', 'pck_archive', 'mi_cache', 'wire_bytes',
           'mi_header_len']
BUILDS = ['up', 'cte', 'cte-off', 'wrap', 'wrap-off']
SIGNED = ('unsigned', 'signed')
CLASSES = ('all', 'small', 'medium', 'large', 'huge')
CLK_TCK = 100


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(0.95 * len(xs)))]


def stats(xs):
    return {'median': statistics.median(xs), 'p95': p95(xs), 'max': max(xs)}


def load_rows(res):
    """Rows keyed (build, signed, id); a re-run of a message replaces the earlier row."""
    rows = {}
    for f in sorted(res.glob('inproc-*.jsonl')):
        for line in f.open():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue  # half-written last line of a running benchmark
            if 'build' in r and 'signed' in r and 'id' in r:
                rows[(r['build'], r['signed'], r['id'])] = r
    return list(rows.values())


def is_failure(r):
    return bool(r.get('oom') or r.get('timeout') or r.get('crash') or r.get('undelivered')) \
        or 'cpu_in' not in r


def fail_kind(r):
    if r.get('oom'):
        return 'oom'
    if r.get('timeout'):
        return 'timeout'
    if r.get('crash'):
        return 'crash'
    if r.get('undelivered'):
        return 'undelivered'
    return 'incomplete'


def fail_label(r):
    k = fail_kind(r)
    if k == 'timeout':
        s = r.get('timeout_s')
        lab = f'>{s:g} s' if isinstance(s, (int, float)) else 'timeout'
        return lab + (f" ({r['stage']})" if r.get('stage') else '')
    if k == 'crash':
        return f"crash rc={r.get('rc')}"
    return k


def total_cpu(r):
    return r['cpu_in'] + r['cpu_pipeline'] + r['cpu_out']


def peak_max(r):
    return max(r['peak_in'], r['peak_pipeline'], r['peak_out'])


def _stat_block(sel):
    a = {m: stats([r[m] for r in sel if m in r]) for m in METRICS if any(m in r for r in sel)}
    a['cpu_total'] = stats([total_cpu(r) for r in sel])
    a['peak_max'] = stats([peak_max(r) for r in sel])
    a['n'] = len(sel)
    return a


def intersections(rows):
    """(signed, cls) -> (builds compared, ids that succeeded in EVERY one of them).

    A build is compared if it has at least one successful row in that cell;
    a message censored in any compared build drops out of all builds' headline."""
    inter = {}
    for signed in SIGNED:
        for cls in CLASSES:
            per = {}
            for b in BUILDS:
                ids = {r['id'] for r in rows if r['build'] == b and r['signed'] == signed
                       and (cls == 'all' or r['cls'] == cls) and not is_failure(r)}
                if ids:
                    per[b] = ids
            if per:
                inter[(signed, cls)] = (list(per), set.intersection(*per.values()))
    return inter


def aggregate(rows, inter):
    """agg: like-for-like (intersection ids); own: each build's own successful rows."""
    agg, own, censored = {}, {}, {}
    for b in BUILDS:
        for signed in SIGNED:
            brows = [r for r in rows if r['build'] == b and r['signed'] == signed]
            if not brows:
                continue
            c = defaultdict(int)
            kinds = defaultdict(list)
            for r in brows:
                if is_failure(r):
                    k = fail_kind(r)
                    c[k] += 1
                    kinds[k].append(r['id'] + ' ' + fail_label(r))
            censored[f'{b}/{signed}'] = {'counts': dict(c), 'rows': kinds, 'n_rows': len(brows)}
            for cls in CLASSES:
                sel = [r for r in brows if (cls == 'all' or r['cls'] == cls) and not is_failure(r)]
                if not sel:
                    continue
                own[f'{b}/{signed}/{cls}'] = _stat_block(sel)
                ids = inter[(signed, cls)][1]
                lf = [r for r in sel if r['id'] in ids]
                if lf:
                    a = _stat_block(lf)
                    a['n_own'] = len(sel)
                    agg[f'{b}/{signed}/{cls}'] = a
    return agg, own, censored


def added_by_mailman(rows, inter):
    """mi_header_len minus the same message's `up` value (paired by id)."""
    up = {(r['signed'], r['id']): r for r in rows if r['build'] == 'up' and not is_failure(r)}
    out = {}
    for b in BUILDS:
        if b == 'up':
            continue
        for signed in SIGNED:
            for cls in CLASSES:
                d = []
                for r in rows:
                    if r['build'] != b or r['signed'] != signed or is_failure(r):
                        continue
                    if cls != 'all' and r['cls'] != cls:
                        continue
                    if r['id'] not in inter.get((signed, cls), (0, ()))[1]:
                        continue
                    u = up.get((signed, r['id']))
                    if u is not None and 'mi_header_len' in r and 'mi_header_len' in u:
                        d.append(r['mi_header_len'] - u['mi_header_len'])
                if d:
                    out[f'{b}/{signed}/{cls}'] = {**stats(d), 'n': len(d)}
    return out


def synthetic(rows):
    """Per-message pairing for large/huge syn-* messages: build -> row summary."""
    ids = sorted({(r['signed'], r['id']) for r in rows
                  if r['id'].startswith('syn-') and r['cls'] in ('large', 'huge')})
    by = {(r['build'], r['signed'], r['id']): r for r in rows}
    table = []
    for signed, mid in ids:
        ent = {'signed': signed, 'id': mid, 'builds': {}}
        for b in BUILDS:
            r = by.get((b, signed, mid))
            if r is None:
                continue
            if is_failure(r):
                ent['builds'][b] = {'state': fail_label(r)}
            else:
                ent['builds'][b] = {k: v for k, v in {
                    'cpu_total': total_cpu(r), 'peak_max': peak_max(r),
                    'pck_out': r.get('pck_out'), 'wire_bytes': r.get('wire_bytes'),
                    'mi_header_len': r.get('mi_header_len')}.items()}
                if r.get('size'):
                    ent['size'] = r['size']
        table.append(ent)
    return table


def read_tsv(path):
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    return [l.split('\t') for l in lines[1:] if l.strip()]


def soak_one(res, build, summary):
    s = dict(summary)
    clk = s.get('clk_tck') or CLK_TCK
    groups = defaultdict(lambda: defaultdict(int))     # group -> t -> summed rss kb
    hwm = defaultdict(int)
    ticks = {}                                         # (runner, pid) -> [first, last] ticks
    for row in read_tsv(res / f'soak-{build}.tsv'):
        try:
            t, runner, pid, rss, h, cpu = row[:6]
            rss, h, cpu = int(rss), int(h), int(cpu)
        except ValueError:
            continue
        g = runner.split(':')[0]
        groups[g][t] += rss
        hwm[g] = max(hwm[g], h)
        ticks.setdefault((runner, pid), [cpu, cpu])[1] = cpu
    # ticks are cumulative since process start: CPU over the sampled window is
    # last minus first (startup before the first sample, and anything after the
    # last, is not counted); a restarted runner's new pid starts its own baseline.
    cpu_g = defaultdict(float)
    for (runner, _pid), (first, last) in ticks.items():
        cpu_g[runner.split(':')[0]] += (last - first) / clk
    allg = {g: {'peak_rss_kb': max(v.values()), 'hwm_kb': hwm[g], 'cpu_s': cpu_g[g]}
            for g, v in groups.items()}
    # `sink` is the harness's discard SMTP sink, not Mailman: reported apart.
    s['harness_sink'] = allg.pop('sink', None)
    s['groups'] = allg
    total_t = defaultdict(int)
    for g, v in groups.items():
        if g != 'sink':
            for t, kb in v.items():
                total_t[t] += kb
    s['sum_group_peak_rss_kb'] = sum(g['peak_rss_kb'] for g in s['groups'].values())
    s['peak_total_rss_kb'] = max(total_t.values()) if total_t else None
    du = read_tsv(res / f'soak-{build}-du.tsv')
    try:
        s['peak_queue_kb'] = max(int(x[1]) for x in du) if du else None
        s['peak_archives_kb'] = max(int(x[2]) for x in du) if du else None
        s['peak_micache_kb'] = max(int(x[3]) for x in du) if du else None
    except (ValueError, IndexError):
        pass
    return s


def load_soak(res):
    soak = {}
    for f in sorted(res.glob('soak-*-summary.json')):
        try:
            summ = json.loads(f.read_text())
        except ValueError:
            continue
        b = summ.get('build') or f.name[len('soak-'):-len('-summary.json')]
        soak[b] = soak_one(res, b, summ)
    return soak


# ---- markdown -------------------------------------------------------------

def fb(v):
    if v is None:
        return '-'
    for unit, d in (('GiB', 1 << 30), ('MiB', 1 << 20), ('KiB', 1 << 10)):
        if abs(v) >= d:
            return f'{v / d:.1f} {unit}'
    return f'{v:.0f} B'


def fcpu(v):
    return f'{v * 1000:.1f} ms' if v < 1 else f'{v:.2f} s'


def fmt(m, v):
    if m.startswith('cpu'):
        return fcpu(v)
    if m.startswith('pck') or m.startswith('peak') or m in ('wire_bytes', 'mi_header_len'):
        return fb(v)
    return f'{v:.0f}'


def ratio(v, base):
    if base is None or not base:
        return ''
    return f' ({v / base:.2f}x)'


def md_report(agg, own, inter, censored, added, syn, soak, rows):
    ALLM = ['cpu_total', 'peak_max'] + METRICS
    out = ['# Mailman DKIM2 benchmark', '']
    if not rows:
        out += ['No in-process results found.', '']
    for signed in SIGNED:
        for cls in CLASSES:
            keys = [f'{b}/{signed}/{cls}' for b in BUILDS if f'{b}/{signed}/{cls}' in agg]
            if not keys:
                continue
            base = agg.get(f'up/{signed}/{cls}')
            n_i = inter[(signed, cls)][1]
            out += [f'## {signed}, {cls}: median (ratio vs up), like-for-like n={len(n_i)}', '',
                    'Computed on the messages that succeeded in every build compared.', '']
            odd = [f"{k.split('/')[0]} own n={own[k]['n']}" for k in keys if own[k]['n'] != len(n_i)]
            if odd:
                out += [f"**WARNING: n differs from the like-for-like n={len(n_i)} for: " + ', '.join(odd)
                        + ' (censored or missing messages dropped from every build; see secondary table).**', '']
            out += ['| metric | ' + ' | '.join(f"{k.split('/')[0]} (n={agg[k]['n']})" for k in keys) + ' |',
                    '|---|' + '---|' * len(keys)]
            for m in ALLM:
                if not all(m in agg[k] for k in keys):
                    continue
                cells = []
                for k in keys:
                    v = agg[k][m]['median']
                    bv = base[m]['median'] if base and m in base and not k.startswith('up/') else None
                    cells.append(fmt(m, v) + ratio(v, bv))
                out.append(f'| {m} | ' + ' | '.join(cells) + ' |')
            ak = [added.get(k) for k in keys]
            if signed == 'signed' and any(ak):
                out.append('| mi added by Mailman (vs up, paired) | ' + ' | '.join(
                    '-' if not a else f"{fb(a['median'])} (n={a['n']})" for a in ak) + ' |')
            out.append('')
            out += [f'p95 / max, {signed} {cls} (p95 is index-based, noisy for small n)', '',
                    '| metric | ' + ' | '.join(k.split('/')[0] for k in keys) + ' |',
                    '|---|' + '---|' * len(keys)]
            for m in ['cpu_total', 'peak_max', 'pck_out', 'wire_bytes']:
                if all(m in agg[k] for k in keys):
                    out.append(f'| {m} | ' + ' | '.join(
                        f"{fmt(m, agg[k][m]['p95'])} / {fmt(m, agg[k][m]['max'])} (n={agg[k]['n']})" for k in keys) + ' |')
            out.append('')
    out += ['## Per-build own numbers (NOT like-for-like: each build\'s own successful rows, median, own n)', '']
    for signed in SIGNED:
        for cls in CLASSES:
            keys = [f'{b}/{signed}/{cls}' for b in BUILDS if f'{b}/{signed}/{cls}' in own]
            if not keys:
                continue
            out += [f'{signed}, {cls}', '',
                    '| metric | ' + ' | '.join(f"{k.split('/')[0]} (n={own[k]['n']})" for k in keys) + ' |',
                    '|---|' + '---|' * len(keys)]
            for m in ['cpu_total', 'peak_max', 'pck_out', 'wire_bytes']:
                out.append(f'| {m} | ' + ' | '.join(fmt(m, own[k][m]['median']) for k in keys) + ' |')
            out.append('')
    # censored
    out += ['## Censored rows (excluded from every aggregate above)', '']
    if censored:
        out += ['| build/signed | rows | ok | oom | timeout | crash | undelivered | incomplete |', '|---|---|---|---|---|---|---|---|']
        for k, c in censored.items():
            n = c['counts']
            bad = sum(n.values())
            out.append(f"| {k} | {c['n_rows']} | {c['n_rows'] - bad} | {n.get('oom', 0)} | "
                       f"{n.get('timeout', 0)} | {n.get('crash', 0)} | {n.get('undelivered', 0)} | {n.get('incomplete', 0)} |")
        out.append('')
        lines = [f'- {k}: {x}' for k, c in censored.items() for kind in c['rows'] for x in c['rows'][kind]]
        if lines:
            out += lines + ['']
    else:
        out += ['None.', '']
    # synthetic
    out += ['## Large/huge synthetic messages, per build', '']
    if syn:
        out += ['| message | build | cpu total | peak max | pck_out | wire | mi hdr |', '|---|---|---|---|---|---|---|']
        for e in syn:
            for b, v in e['builds'].items():
                name = f"{e['id']} ({e['signed']}{', ' + fb(e['size']) if e.get('size') else ''})"
                if 'state' in v:
                    out.append(f"| {name} | {b} | {v['state']} | | | | |")
                else:
                    out.append(f"| {name} | {b} | {fcpu(v['cpu_total'])} | {fb(v['peak_max'])} | "
                               f"{fb(v['pck_out'])} | {fb(v['wire_bytes'])} | {fb(v['mi_header_len'])} |")
        out.append('')
    else:
        out += ['No syn-* large/huge rows yet.', '']
    # soak
    out += ['## Soak (real runners)', '']
    if soak:
        out += ['| build | drained | drain s | injected | delivered/expected | cgroup peak | oom | held | shunt | bad | runners | memmax | passes |',
                '|---|---|---|---|---|---|---|---|---|---|---|---|---|']
        for b in BUILDS + sorted(set(soak) - set(BUILDS)):
            if b not in soak:
                continue
            s = soak[b]
            out.append(f"| {b} | {s.get('drained')} | {s.get('drain_seconds', '-')} | {s.get('injected', '-')} | "
                       f"{s.get('delivered', '-')}/{s.get('expected_recipients', '-')} | "
                       f"{fb(s.get('cgroup_mem_peak_bytes'))} | {s.get('oom_kills', '-')} | "
                       f"{s.get('held_requests', '-')} | {s.get('shunt_files', '-')} | {s.get('bad_files', '-')} | "
                       f"{s.get('runners', '-')} | {s.get('memmax', '-')} | {s.get('passes', '-')} |")
        out.append('')
        out += ['Problems: ' + ('; '.join(f"{b}: {soak[b].get('failures')}" for b in soak
                                          if soak[b].get('failures') or soak[b].get('sink_failed')
                                          or soak[b].get('injection_aborted') or soak[b].get('unit_result') not in (None, 'success')) or 'none'), '']
        gs = sorted({g for s in soak.values() for g in s['groups']})
        out += ['Peak RSS per Mailman runner group (harness sink excluded; max over time of the group sum; "sum" = sum of group peaks; "conc" = peak of concurrent total). RSS is summed across processes, so shared pages are double-counted, and 1 s sampling can miss short peaks: the cgroup memory peak above is authoritative.', '',
                '| build | ' + ' | '.join(gs) + ' | sum | conc |', '|---|' + '---|' * (len(gs) + 2)]
        for b in soak:
            s = soak[b]
            out.append(f'| {b} | ' + ' | '.join(
                fb(s['groups'][g]['peak_rss_kb'] * 1024) if g in s['groups'] else '-' for g in gs)
                + f" | {fb(s['sum_group_peak_rss_kb'] * 1024)} | {fb((s['peak_total_rss_kb'] or 0) * 1024)} |")
        out += ['', 'Total CPU seconds per Mailman runner group (last minus first sample per process; startup before the first sample and work after the last are not counted):', '',
                '| build | ' + ' | '.join(gs) + ' |', '|---|' + '---|' * len(gs)]
        for b in soak:
            out.append(f'| {b} | ' + ' | '.join(
                f"{soak[b]['groups'][g]['cpu_s']:.1f}" if g in soak[b]['groups'] else '-' for g in gs) + ' |')
        out += ['', 'Harness discard sink (not Mailman, excluded from all totals above): ' + '; '.join(
            f"{b}: peak RSS {fb(soak[b]['harness_sink']['peak_rss_kb'] * 1024)}, CPU {soak[b]['harness_sink']['cpu_s']:.1f} s"
            for b in soak if soak[b].get('harness_sink')) , '', 'Disk: peak queue / archives / mi-cache', '',
                '| build | queue | archives | mi-cache |', '|---|---|---|---|']
        for b in soak:
            s = soak[b]
            out.append(f"| {b} | " + ' | '.join(fb(s[k] * 1024) if s.get(k) is not None else '-'
                       for k in ('peak_queue_kb', 'peak_archives_kb', 'peak_micache_kb')) + ' |')
        out.append('')
    else:
        out += ['No soak results yet.', '']
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default=str(REPO / 'bench' / 'results'))
    res = Path(ap.parse_args().results)
    outdir = REPO / 'bench'
    outdir.mkdir(exist_ok=True)
    rows = load_rows(res)
    inter = intersections(rows)
    agg, own, censored = aggregate(rows, inter)
    added, syn, soak = added_by_mailman(rows, inter), synthetic(rows), load_soak(res)
    (outdir / 'report.json').write_text(json.dumps(
        {'inproc': agg, 'inproc_own': own,
         'like_for_like_n': {'/'.join(k): len(v[1]) for k, v in inter.items()},
         'censored': censored, 'mi_added': added, 'synthetic': syn, 'soak': soak}, indent=1))
    (outdir / 'report.md').write_text(md_report(agg, own, inter, censored, added, syn, soak, rows))
    print(outdir / 'report.md')


if __name__ == '__main__':
    main()
