#!/bin/bash
# One real Mailman instance for BUILD: LMTP in on 127.0.0.1:18024, delivery to
# a discard sink on 127.0.0.1:18025, prototype archiver on, 100 members, list
# header and footer.  Injects the whole corpus PASSES times (3), samples runner
# RSS/CPU and disk every second, stops when the queues drain.  Never touches
# production: own ports, own var dir, own transient systemd units.
#
# Usage: soak.sh BUILD VENV DKIM2(on|off|na)
# Overrides: B (bench root), CORPUS, PASSES, DRAIN_CAP and INJECT_CAP (seconds), MEMMAX,
# RUNNERS (space-separated runner names; default is the delivery path).
#
# Output notes: runner labels look like `in:0:1` (group on the part before the
# first colon); cpu_ticks are raw clock ticks (CLK_TCK, normally 100/s);
# the cgroup's memory.peak includes page cache, so compare builds on the
# per-runner RSS columns.  The sink is sampled under the label `sink`.
#
# Only the runners a post goes through are started: the full default set of 12
# idles at ~860 MB RSS here (72 MB each), which alone exceeds the 700 MB cap
# and OOM-killed the master within seconds on an empty queue.
set -euo pipefail
BUILD=$1 VENV=$2 DK=$3
B=${B:-/opt/mailman/bench}; OUT=$B/results; V=$B/soak-$BUILD
CORPUS=${CORPUS:-$B/corpus}; PASSES=${PASSES:-3}
DRAIN_CAP=${DRAIN_CAP:-10800}; INJECT_CAP=${INJECT_CAP:-7200}; MEMMAX=${MEMMAX:-700M}
MEMBERS=100
RUNNERS=${RUNNERS:-lmtp in pipeline out archive retry virgin}
# `master -r` is broken upstream (it passes tuples to a str concat), so the
# others are switched off in the config instead.
RCFG=; for r in bounces command digest nntp rest task; do
  case " $RUNNERS " in *" $r "*) ;; *) RCFG="$RCFG"$'\n'"[runner.$r]"$'\n'"start: no" ;; esac
done
LMTP=18024 SINKP=18025 REST=18001
UNIT=mmsoak-$BUILD-$$; SINKUNIT=mmsoak-sink-$BUILD-$$
mkdir -p $OUT
for p in $LMTP $SINKP $REST; do
  ss -ltn "sport = :$p" | grep -q LISTEN && { echo "port $p busy" >&2; exit 1; }
done
rm -f $OUT/soak-$BUILD.tsv $OUT/soak-$BUILD-du.tsv $OUT/soak-$BUILD-summary.json
rm -rf $V && mkdir -p $V

case $DK in
  on)  MI=$'message_instance: yes' ;;
  off) MI=$'message_instance: no' ;;   # DKIM2 builds only; 'up' has no such option
  *)   MI= ;;
esac
cat > $V/mailman.cfg <<CFG
[mailman]
site_owner: bench@example.com
layout: soak
[paths.soak]
var_dir: $V/var
template_dir: $V/var/templates
[database]
url: sqlite:///$V/var/mailman.db
[mta]
lmtp_host: 127.0.0.1
lmtp_port: $LMTP
smtp_host: 127.0.0.1
smtp_port: $SINKP
$MI
[archiver.prototype]
enable: yes
[webservice]
hostname: 127.0.0.1
port: $REST$RCFG
CFG

SAMPLER=
cleanup() {
  [ -n "$SAMPLER" ] && kill $SAMPLER 2>/dev/null || true
  systemctl stop $UNIT $SINKUNIT 2>/dev/null || true
  systemctl reset-failed $UNIT $SINKUNIT 2>/dev/null || true
}
trap cleanup EXIT

# Domain, list, 100 members, nonmember posts accepted, header and footer.
$VENV/bin/python - $V/mailman.cfg $DK $MEMBERS <<'PY'
import os, sys
from mailman.core.initialize import initialize
initialize(sys.argv[1])
from mailman.config import config
from mailman.app.lifecycle import create_list
from mailman.interfaces.action import Action
from mailman.interfaces.domain import IDomainManager
from mailman.interfaces.template import ITemplateManager
from mailman.interfaces.usermanager import IUserManager
from mailman.utilities.datetime import now
from zope.component import getUtility
getUtility(IDomainManager).add('lists.example.com')
ml = create_list('soak@lists.example.com')
ml.default_nonmember_action = Action.accept
ml.max_message_size = 0             # default 40 KB would hold every big message
ml.max_num_recipients = 0
ml.require_explicit_destination = False
ml.administrivia = False
ml.send_welcome_message = False    # else 100 welcome mails pollute the delivery count
if hasattr(ml, 'dkim2_message_instance'):
    ml.dkim2_message_instance = (sys.argv[2] == 'on')
um = getUtility(IUserManager)
for i in range(int(sys.argv[3])):
    e = f'member{i}@example.net'
    a = um.get_address(e) or um.create_address(e)
    a.verified_on = now()
    ml.subscribe(a)
tdir = os.path.join(config.VAR_DIR, 'templates', 'site', 'en')
os.makedirs(tdir, exist_ok=True)
open(os.path.join(tdir, 'bench-footer.txt'), 'w').write(
    '-- \nbench list footer\nhttps://example.com/unsub\n')
open(os.path.join(tdir, 'bench-header.txt'), 'w').write('bench list header\n')
tm = getUtility(ITemplateManager)
tm.set('list:member:regular:footer', ml.list_id, 'mailman:///bench-footer.txt')
tm.set('list:member:regular:header', ml.list_id, 'mailman:///bench-header.txt')
config.db.commit()
PY

systemd-run -q --unit=$SINKUNIT -p MemoryMax=300M -p MemorySwapMax=0 \
  -p StandardOutput=append:$V/sink.log -p StandardError=append:$V/sink.log \
  $VENV/bin/python $B/sink.py $SINKP $V/delivered.json
# The master in the foreground (Type=simple): every runner is its child inside
# this unit's cgroup, so the cap covers them together and systemd records why
# the unit ended.
systemd-run -q --unit=$UNIT -p MemoryMax=$MEMMAX -p MemorySwapMax=0 -p OOMPolicy=continue \
  -p WorkingDirectory=$V -E PATH=$VENV/bin:/usr/bin:/bin \
  -p StandardOutput=append:$V/master.out -p StandardError=append:$V/master.out \
  $VENV/bin/master -C $V/mailman.cfg --force
sleep 3
systemctl is-active -q $UNIT || { echo "master failed to start" >&2; tail $V/master.out >&2; exit 1; }
CG=/sys/fs/cgroup$(systemctl show -p ControlGroup --value $UNIT)
for i in $(seq 60); do
  ss -ltn "sport = :$LMTP" | grep -q LISTEN && \
    ss -ltn "sport = :$SINKP" | grep -q LISTEN && break
  sleep 1
done
ss -ltn "sport = :$LMTP" | grep -q LISTEN && ss -ltn "sport = :$SINKP" | grep -q LISTEN \
  || { echo "LMTP/sink ports never opened" >&2; tail $V/master.out $V/sink.log >&2; exit 1; }
sleep 5

# Sampler: per-runner RSS/HWM/CPU from the unit's cgroup (plus the sink), disk
# usage, and the cgroup's memory.peak / oom_kill, polled so that the last
# values survive the unit being stopped by its OOM policy.
printf 't\trunner\tpid\trss_kb\thwm_kb\tcpu_ticks\n' > $OUT/soak-$BUILD.tsv
printf 't\tqueue_kb\tarchives_kb\tmicache_kb\n' > $OUT/soak-$BUILD-du.tsv
SINKCG=/sys/fs/cgroup$(systemctl show -p ControlGroup --value $SINKUNIT)
rm -f $V/memlast
du1() { du -sk "$1" 2>/dev/null | cut -f1 || true; }
row() { # t label pid -> one tab row, or nothing unless both reads worked
  local m c
  m=$(awk -v t=$1 -v r="$2" -v p=$3 '/^VmRSS/{rss=$2} /^VmHWM/{hwm=$2} END{if(rss=="")exit 1; printf "%s\t%s\t%s\t%s\t%s", t,r,p,rss,hwm}' /proc/$3/status 2>/dev/null) || return 0
  c=$(sed 's/.*) //' /proc/$3/stat 2>/dev/null | awk '{print $12+$13}') || return 0
  [ -n "$c" ] && printf '%s\t%s\n' "$m" "$c"
}
( while sleep 1; do
    t=$(date +%s)
    for p in $(cat $CG/cgroup.procs 2>/dev/null); do
      r=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | grep -o -- '--runner=[a-z:0-9]*' | cut -d= -f2 || true)
      [ -n "$r" ] || r=master
      row $t $r $p
    done >> $OUT/soak-$BUILD.tsv
    for p in $(cat $SINKCG/cgroup.procs 2>/dev/null); do row $t sink $p; done >> $OUT/soak-$BUILD.tsv
    q=$(du1 $V/var/queue); a=$(du1 $V/var/archives); m=$(du1 $V/var/mi-cache)
    printf "%s\t%s\t%s\t%s\n" $t ${q:-0} ${a:-0} ${m:-0} >> $OUT/soak-$BUILD-du.tsv
    pk=$(cat $CG/memory.peak 2>/dev/null) && ok=$(awk '/^oom_kill /{print $2}' $CG/memory.events 2>/dev/null) \
      && [ -n "$pk" ] && echo "$pk ${ok:-0}" > $V/memlast.tmp && mv $V/memlast.tmp $V/memlast
  done ) & SAMPLER=$!

# Inject: raw LMTP, streamed (no whole-message copies), one connection per
# message, per-message timeout.  Signed then unsigned of each corpus id.
START=$(date +%s)
$VENV/bin/python - $CORPUS $PASSES $LMTP $OUT/soak-$BUILD-inject.json $UNIT $INJECT_CAP <<'PY'
import json, socket, subprocess, sys, time
corpus, passes, port, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
unit, cap = sys.argv[5], int(sys.argv[6])
t0 = time.time()
aborted = None
ids = [l.split('\t')[0] for l in open(corpus + '/index.tsv').read().splitlines()[1:] if l]
acc = rej = 0
fails = []

def reply(f):
    line = f.readline()
    code = line[:3]
    while line[3:4] == b'-':
        line = f.readline()
    return int(code), line.decode('ascii', 'replace').strip()

def send(path):
    s = socket.create_connection(('127.0.0.1', port), timeout=300)
    f = s.makefile('rwb')
    def cmd(c, want):
        f.write(c + b'\r\n'); f.flush()
        code, text = reply(f)
        if code != want:
            raise RuntimeError(text)
    reply(f)
    cmd(b'LHLO soak', 250)
    cmd(b'MAIL FROM:<bench@test1.dkim2.com>', 250)
    cmd(b'RCPT TO:<soak@lists.example.com>', 250)
    cmd(b'DATA', 354)
    with open(path, 'rb') as m:
        for line in m:
            line = line.rstrip(b'\r\n')
            if line.startswith(b'.'):
                line = b'.' + line
            f.write(line + b'\r\n')
    f.write(b'.\r\n'); f.flush()
    code, text = reply(f)
    try:
        cmd(b'QUIT', 221)
    except Exception:
        pass
    s.close()
    if code != 250:
        raise RuntimeError(text)

def master_alive():
    return subprocess.call(['systemctl', 'is-active', '-q', unit]) == 0

for p in range(passes):
    if aborted: break
    for i in ids:
        if aborted: break
        for kind in ('signed', 'unsigned'):
            if not master_alive():
                aborted = 'master unit no longer active'; break
            if time.time() - t0 > cap:
                aborted = f'injection cap {cap}s exceeded'; break
            path = f'{corpus}/{kind}/{i}.eml'
            try:
                send(path); acc += 1
            except Exception as e:
                rej += 1; fails.append(f'{kind}/{i}: {e}')
json.dump({'attempted': acc + rej, 'accepted': acc, 'rejected': rej,
           'aborted': aborted, 'failures': fails[:50]}, open(out, 'w'))
print('injected', acc, 'rejected', rej)
PY
INJ_END=$(date +%s)

# Drain: every queue empty for 10 consecutive seconds and the sink count stable.
# queue/digest, shunt and bad are ignored: digest fills as posts are archived
# and only empties when a digest is sent (digest runner off); nothing consumes
# shunt or bad.  Their file counts go in the summary.
quiet=0; last=; DRAINED=true; SINKFAILED=false
while [ $quiet -lt 10 ]; do
  sleep 1
  cur=$(cat $V/delivered.json 2>/dev/null || echo none)
  if [ -z "$(find $V/var/queue \( -path $V/var/queue/digest -o -path $V/var/queue/shunt -o -path $V/var/queue/bad \) -prune -o -type f -print -quit)" ] && [ "$cur" = "$last" ]; then
    quiet=$((quiet+1)); else quiet=0; fi
  last=$cur
  systemctl is-active -q $UNIT || { DRAINED=false; break; }   # master gone (OOM?)
  systemctl is-active -q $SINKUNIT || { SINKFAILED=true; DRAINED=false; break; }
  [ $(( $(date +%s) - START )) -gt $DRAIN_CAP ] && { DRAINED=false; break; }
done
END=$(date +%s)

# The cgroup's verdict: read it if still there, else the sampler's last poll
# (with OOMPolicy=stop the cgroup vanishes with the unit).
MEMPEAK=$(cat $CG/memory.peak 2>/dev/null || true)
OOMK=$(awk '/^oom_kill /{print $2}' $CG/memory.events 2>/dev/null || true)
if [ -z "$MEMPEAK" ] || [ -z "$OOMK" ]; then
  read -r MEMPEAK OOMK < $V/memlast 2>/dev/null || { MEMPEAK=; OOMK=; }
fi
ACTIVE=$(systemctl is-active $UNIT || true)
kill $SAMPLER 2>/dev/null || true; SAMPLER=
systemctl stop $UNIT 2>/dev/null || true
RESULT=$(systemctl show -p Result --value $UNIT 2>/dev/null || true)
systemctl stop $SINKUNIT 2>/dev/null || true
SHUNT=$(find $V/var/queue/shunt -type f 2>/dev/null | wc -l); BAD=$(find $V/var/queue/bad -type f 2>/dev/null | wc -l)
LOGDIED=$(grep -ciE 'died|signal 9|killed' $V/var/logs/mailman.log 2>/dev/null || true)
systemctl reset-failed $UNIT $SINKUNIT 2>/dev/null || true

python3 - <<PY
import json, sqlite3
inj = json.load(open("$OUT/soak-$BUILD-inject.json"))
try: d = json.load(open("$V/delivered.json"))
except Exception: d = {"messages": 0, "recipients": 0}
try:   # posts held for moderation (hold queue); None if unreadable
    held = sqlite3.connect("$V/var/mailman.db").execute(
        "select count(*) from _request").fetchone()[0]
except Exception: held = None
def num(x):
    return int(x) if x.strip().isdigit() else None
oom = num("$OOMK")
if "$RESULT" == "oom-kill" and not oom: oom = 1
s = {"build": "$BUILD", "dkim2": "$DK", "drained": "$DRAINED" == "true",
     "sink_failed": "$SINKFAILED" == "true", "injection_aborted": inj["aborted"],
     "drain_seconds": $END - $START, "inject_seconds": $INJ_END - $START,
     "injected": inj["accepted"], "rejected": inj["rejected"],
     "members": $MEMBERS, "expected_recipients": inj["accepted"] * $MEMBERS,
     "delivered": d["recipients"], "delivered_messages": d["messages"],
     "held_requests": held, "shunt_files": $SHUNT, "bad_files": $BAD,
     "cgroup_mem_peak_bytes": num("$MEMPEAK"), "oom_kills": oom,
     "unit_active_at_end": "$ACTIVE", "unit_result": "$RESULT",
     "log_died_lines": int("${LOGDIED:-0}"),
     "runners": "$RUNNERS", "memmax": "$MEMMAX", "passes": $PASSES,
     "drain_cap": $DRAIN_CAP, "inject_cap": $INJECT_CAP, "failures": inj["failures"]}
json.dump(s, open("$OUT/soak-$BUILD-summary.json", "w"), indent=1)
print(json.dumps(s))
PY
