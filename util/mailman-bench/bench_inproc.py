"""Drive one Mailman build over the benchmark corpus in-process.

Run with that build's venv python:
  bench_inproc.py --build wrap --dkim2 on --corpus DIR --signed signed --out DIR --members 25
Mirrors what the runners do -- LMTP parse, in queue, posting pipeline,
out queue, delivery -- without runner processes or an MTA, so each
message's CPU, peak memory and queue footprint can be measured alone.

cpu_* are the median of --repeat runs made WITHOUT tracemalloc (it inflates
allocation-heavy code unequally).  peak_* come from one separate traced run
per message.  Each run has a --timeout (all stages of one run); a message
that exceeds it gets a row with "timeout": true and no metrics.
"""
import argparse, email, inspect, json, os, re, shutil, smtplib, statistics
import signal, tempfile, time, tracemalloc
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--build', required=True)
ap.add_argument('--dkim2', choices=['on', 'off', 'na'], required=True)
ap.add_argument('--corpus', required=True)
ap.add_argument('--signed', choices=['signed', 'unsigned'], required=True)
ap.add_argument('--out', required=True)
ap.add_argument('--members', type=int, default=25)
ap.add_argument('--repeat', type=int, default=5)
ap.add_argument('--timeout', type=int, default=120,
                help='seconds allowed for all stages of one run of one message')
ap.add_argument('--resume', action='store_true',
                help='skip ids already in the output file (after an OOM kill)')
args = ap.parse_args()

var = Path(tempfile.mkdtemp(prefix='mmbench-'))
cfg = var / 'mailman.cfg'
# [mta] message_instance exists only in the DKIM2 builds; leave it out of
# the config for upstream, whose schema would reject it.
mi_line = {'on': 'message_instance: yes', 'off': 'message_instance: no',
           'na': ''}[args.dkim2]
cfg.write_text(f"""\
[mailman]
site_owner: bench@example.com
layout: bench
[paths.bench]
var_dir: {var}
template_dir: {var}/templates
[database]
url: sqlite:///{var}/mailman.db
[mta]
smtp_host: 127.0.0.1
smtp_port: 9
{mi_line}
[archiver.prototype]
enable: yes
""")
from mailman.core.initialize import initialize
initialize(str(cfg))
from mailman.config import config
from mailman.app.lifecycle import create_list
from mailman.core.pipelines import process as run_pipeline
from mailman.email.message import Message
from mailman.interfaces.domain import IDomainManager
from mailman.interfaces.usermanager import IUserManager
from mailman.interfaces.template import ITemplateManager
from mailman.mta import connection as mta_connection
from mailman.mta.deliver import deliver
from mailman.runners import lmtp as lmtp_runner
from mailman.utilities.datetime import now
from mailman.utilities.email import add_message_hash
from zope.component import getUtility

# Only builds whose LMTP runner keeps the received octets carry them in
# their queue pickles; setting the attribute on the others would charge
# upstream for our patch.
KEEPS_BYTES = 'original_bytes' in inspect.getsource(lmtp_runner)

WIRE = []


class FakeSMTP(smtplib.SMTP):
    """The real SMTP.send_message (Bcc drop, CRLF flatten), no socket."""
    def __init__(self):
        self.esmtp_features = {}
        self.command_encoding = 'ascii'
        self.local_hostname = 'bench'

    def sendmail(self, from_addr, to_addrs, msg, *a, **kw):
        WIRE.append(msg)
        return {}

    def ehlo_or_helo_if_needed(self):
        pass

    def quit(self):
        return (221, b'bye')


mta_connection.Connection._connect = lambda self: (
    setattr(self, '_connection', FakeSMTP()),
    setattr(self, '_session_count', 0))[0]
mta_connection.Connection._login = lambda self: None


def make_list(name, filt):
    mlist = create_list(f'{name}@lists.example.com')
    if hasattr(mlist, 'dkim2_message_instance'):
        mlist.dkim2_message_instance = (args.dkim2 == 'on')
    mlist.filter_content = bool(filt)
    mlist.filter_types = ['application/zip'] if filt else []
    um = getUtility(IUserManager)
    for i in range(args.members):
        email_ = f'member{i}@example.net'
        addr = um.get_address(email_) or um.create_address(email_)
        addr.verified_on = now()
        mlist.subscribe(addr)
    # A header and a footer, as on a typical list.
    tdir = var / 'templates' / 'site' / 'en'
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / 'bench-footer.txt').write_text(
        '-- \nbench list footer\nhttps://example.com/unsub\n')
    (tdir / 'bench-header.txt').write_text('bench list header\n')
    tm = getUtility(ITemplateManager)
    tm.set('list:member:regular:footer', mlist.list_id,
           'mailman:///bench-footer.txt')
    tm.set('list:member:regular:header', mlist.list_id,
           'mailman:///bench-header.txt')
    config.db.commit()
    return mlist


getUtility(IDomainManager).add('lists.example.com')
config.db.commit()
LISTS = {0: make_list('bench', 0), 1: make_list('benchfilter', 1)}


class BenchTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise BenchTimeout()


signal.signal(signal.SIGALRM, _alarm)
STAGE = 'start'


def measure(fn, stage, traced):
    """Return (result, cpu seconds, tracemalloc peak or None)."""
    global STAGE
    STAGE = stage
    if traced:
        tracemalloc.start()
        tracemalloc.reset_peak()
    try:
        t0 = time.process_time()
        result = fn()
        cpu = time.process_time() - t0
        peak = tracemalloc.get_traced_memory()[1] if traced else None
    finally:
        if traced:
            tracemalloc.stop()
    return result, cpu, peak


def pck_size(sb, filebase):
    return os.path.getsize(os.path.join(sb.queue_directory, filebase + '.pck'))


def mi_cache_bytes():
    d = var / 'mi-cache'
    return sum(p.stat().st_size for p in d.glob('*')) if d.exists() else 0


def clear_state():
    """Empty every queue (subscribing leaves welcome mail in virgin) and the
    mi-cache, before a run and after a timeout."""
    for sb in config.switchboards.values():
        d = sb.queue_directory
        for f in os.listdir(d):
            os.unlink(os.path.join(d, f))
    shutil.rmtree(var / 'mi-cache', ignore_errors=True)


def odd_queues():
    """Files in the queues a held/shunted/bounced post would land in."""
    return sum(len(os.listdir(config.switchboards[n].queue_directory))
               for n in ('hold', 'shunt', 'bad', 'virgin', 'bounces')
               if n in config.switchboards)


def mi_len(wire):
    head = wire.split(b'\r\n\r\n', 1)[0]
    return sum(len(f) for f in re.split(rb'\r\n(?![ \t])', head)
               if f.split(b':', 1)[0].strip().lower() == b'message-instance')


def one(raw, mlist, traced):
    WIRE.clear()
    clear_state()
    sb_in, sb_pipe, sb_out, sb_arch = (
        config.switchboards[n] for n in ('in', 'pipeline', 'out', 'archive'))
    def lmtp():
        # What LMTPHandler._handle_DATA does before it enqueues.
        msg = email.message_from_bytes(raw, Message)
        msg.set_unixfrom('sender@example.org')
        if KEEPS_BYTES:
            msg.original_bytes = raw
        msg.original_size = len(raw)
        add_message_hash(msg)
        msg['X-MailFrom'] = 'sender@example.org'
        return sb_in.enqueue(msg, {}, listid=mlist.list_id,
                             original_size=len(raw), received_time=now(),
                             to_list=True)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        fb, cpu_in, peak_in = measure(lmtp, 'lmtp', traced)
        r = {'pck_in': pck_size(sb_in, fb), 'cpu_in': cpu_in,
             'peak_in': peak_in}
        # The incoming runner's posting chain accepts the post and moves it
        # to the pipeline queue unchanged.
        msg, data = sb_in.dequeue(fb)
        sb_in.finish(fb)
        fb = sb_pipe.enqueue(msg, data, pipeline=mlist.posting_pipeline)
        r['pck_pipeline'] = pck_size(sb_pipe, fb)
        def pipeline():
            msg, data = sb_pipe.dequeue(fb)
            sb_pipe.finish(fb)
            run_pipeline(mlist, msg, data, mlist.posting_pipeline)
        _, r['cpu_pipeline'], r['peak_pipeline'] = measure(
            pipeline, 'pipeline', traced)
        # to-outgoing and to-archive enqueued copies.
        out_files = list(sb_out.files)
        r['n_out_files'] = len(out_files)
        r['pck_out'] = sum(pck_size(sb_out, f) for f in out_files)
        r['pck_archive'] = sum(pck_size(sb_arch, f) for f in sb_arch.files)
        r['mi_cache'] = mi_cache_bytes()
        def outgoing():
            for f in out_files:
                m, d = sb_out.dequeue(f)
                sb_out.finish(f)
                deliver(mlist, m, d)
        _, r['cpu_out'], r['peak_out'] = measure(outgoing, 'outgoing', traced)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    r['delivered'] = len(WIRE)
    r['odd_queue_files'] = odd_queues()
    first = WIRE[0] if WIRE else b''
    r['wire_bytes'] = len(first)
    r['mi_header_len'] = mi_len(first)
    return r, first


index = [l.split('\t')
         for l in Path(args.corpus, 'index.tsv').read_text().splitlines()[1:]]
out_dir = Path(args.out)
(out_dir / 'eml').mkdir(parents=True, exist_ok=True)
out_file = out_dir / f'inproc-{args.build}-{args.signed}.jsonl'
current = out_dir / f'inproc-{args.build}-{args.signed}.current'
done = set()
if args.resume and out_file.exists():
    for l in out_file.open():
        try:
            done.add(json.loads(l)['id'])
        except ValueError:
            pass    # a partial line left by a kill
# Warm-up (imports, template cache, sqlite) so the first message is not
# charged for it; not recorded.
for warm_id, warm_size, _, warm_filt in index:
    if int(warm_size) < 1_000_000:
        try:
            one(Path(args.corpus, args.signed, warm_id + '.eml').read_bytes(),
                LISTS[int(warm_filt)], False)
        except BenchTimeout:
            clear_state()
        break
# A cgroup OOM kill ends this process outright (no MemoryError), so the id
# being worked on is written to .current first; run-inproc.sh records it as
# an OOM row and resumes after it.
with open(out_file, 'a' if args.resume else 'w') as fp:
    for ident, size, cls, filt in index:
        if ident in done:
            continue
        current.write_text(f'{ident}\t{size}\t{cls}\t{filt}\n')
        raw = Path(args.corpus, args.signed, ident + '.eml').read_bytes()
        base = dict(build=args.build, dkim2=args.dkim2, signed=args.signed,
                    id=ident, size=int(size), cls=cls, filter=int(filt))
        mlist = LISTS[int(filt)]
        # Multi-megabyte messages are slow and the medians of their runs
        # barely differ, so time them once.
        n = 1 if int(size) > 1_000_000 else args.repeat
        runs = []
        try:
            for _ in range(n):
                r, first = one(raw, mlist, False)
                runs.append(r)
            traced, _ = one(raw, mlist, True)
        except BenchTimeout:
            clear_state()
            row = dict(base, oom=False, timeout=True,
                       timeout_s=args.timeout, stage=STAGE)
        else:
            row = {k: statistics.median(run[k] for run in runs)
                   for k in runs[0] if not k.startswith('peak_')}
            row.update({k: v for k, v in traced.items()
                        if k.startswith('peak_')})
            row.update(base, oom=False, runs=len(runs))
            if row['delivered'] == 0:
                row['undelivered'] = True
            (out_dir / 'eml' / f'{args.build}-{args.signed}-{ident}.eml'
             ).write_bytes(first)
        fp.write(json.dumps(row) + '\n')
        fp.flush()
current.unlink(missing_ok=True)
shutil.rmtree(var)
