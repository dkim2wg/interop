#!/bin/bash
# One real Mailman instance for BUILD: LMTP in on 127.0.0.1:18024, delivery to
# a discard sink on 127.0.0.1:18025, prototype archiver on, 100 members, list
# header and footer.  Injects the whole corpus PASSES times (3), samples runner
# RSS/CPU and disk every second, stops when the queues drain.  Never touches
# production: own ports, own var dir, own transient systemd units.
#
# Usage: soak.sh BUILD VENV DKIM2(on|off|na)
# Overrides: B (bench root), CORPUS, PASSES, DRAIN_CAP (seconds), MEMMAX,
# RUNNERS (space-separated runner names; default is the delivery path).
#
# Only the runners a post goes through are started: the full default set of 12
# idles at ~860 MB RSS here (72 MB each), which alone exceeds the 700 MB cap
# and OOM-killed the master within seconds on an empty queue.
set -euo pipefail
BUILD=$1 VENV=$2 DK=$3
B=${B:-/opt/mailman/bench}; OUT=$B/results; V=$B/soak-$BUILD
CORPUS=${CORPUS:-$B/corpus}; PASSES=${PASSES:-3}
DRAIN_CAP=${DRAIN_CAP:-10800}; MEMMAX=${MEMMAX:-700M}
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
systemd-run -q --unit=$UNIT -p MemoryMax=$MEMMAX -p MemorySwapMax=0 \
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
sleep 5

# Sampler: per-runner RSS/HWM/CPU from the unit's cgroup, and disk usage.
printf 't\trunner\tpid\trss_kb\thwm_kb\tcpu_ticks\n' > $OUT/soak-$BUILD.tsv
printf 't\tqueue_kb\tarchives_kb\tmicache_kb\n' > $OUT/soak-$BUILD-du.tsv
du1() { du -sk "$1" 2>/dev/null | cut -f1 || true; }
( while sleep 1; do
    t=$(date +%s)
    for p in $(cat $CG/cgroup.procs 2>/dev/null); do
      r=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | grep -o -- '--runner=[a-z:0-9]*' | cut -d= -f2 || true)
      [ -n "$r" ] || r=master
      { awk -v t=$t -v r="$r" -v p=$p '/^VmRSS/{rss=$2} /^VmHWM/{hwm=$2} END{printf "%s\t%s\t%s\t%s\t%s\t", t,r,p,rss+0,hwm+0}' /proc/$p/status
        sed 's/.*) //' /proc/$p/stat | awk '{print $12+$13}'; } 2>/dev/null || true
    done >> $OUT/soak-$BUILD.tsv
    q=$(du1 $V/var/queue); a=$(du1 $V/var/archives); m=$(du1 $V/var/mi-cache)
    printf "%s\t%s\t%s\t%s\n" $t ${q:-0} ${a:-0} ${m:-0} >> $OUT/soak-$BUILD-du.tsv
  done ) & SAMPLER=$!

# Inject: raw LMTP, streamed (no whole-message copies), one connection per
# message, per-message timeout.  Signed then unsigned of each corpus id.
START=$(date +%s)
$VENV/bin/python - $CORPUS $PASSES $LMTP $OUT/soak-$BUILD-inject.json <<'PY'
import json, socket, sys
corpus, passes, port, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
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

for p in range(passes):
    for i in ids:
        for kind in ('signed', 'unsigned'):
            path = f'{corpus}/{kind}/{i}.eml'
            try:
                send(path); acc += 1
            except Exception as e:
                rej += 1; fails.append(f'{kind}/{i}: {e}')
json.dump({'attempted': acc + rej, 'accepted': acc, 'rejected': rej,
           'failures': fails[:50]}, open(out, 'w'))
print('injected', acc, 'rejected', rej)
PY
INJ_END=$(date +%s)

# Drain: every queue empty for 10 consecutive seconds and the sink count stable.
# queue/digest is ignored: it fills as posts are archived for the digest and
# is only emptied when a digest is sent (the digest runner is off).
quiet=0; last=; DRAINED=true
while [ $quiet -lt 10 ]; do
  sleep 1
  cur=$(cat $V/delivered.json 2>/dev/null || echo none)
  if [ -z "$(find $V/var/queue -path $V/var/queue/digest -prune -o -type f -print -quit)" ] && [ "$cur" = "$last" ]; then
    quiet=$((quiet+1)); else quiet=0; fi
  last=$cur
  systemctl is-active -q $UNIT || { DRAINED=false; break; }   # master gone (OOM?)
  [ $(( $(date +%s) - START )) -gt $DRAIN_CAP ] && { DRAINED=false; break; }
done
END=$(date +%s)

# Capture the cgroup's verdict before stopping it.
MEMPEAK=$(cat $CG/memory.peak 2>/dev/null || echo 0)
OOMK=$(awk '/^oom_kill /{print $2}' $CG/memory.events 2>/dev/null || echo 0)
ACTIVE=$(systemctl is-active $UNIT || true)
kill $SAMPLER 2>/dev/null || true; SAMPLER=
systemctl stop $UNIT 2>/dev/null || true
RESULT=$(systemctl show -p Result --value $UNIT 2>/dev/null || true)
systemctl stop $SINKUNIT 2>/dev/null || true
LOGDIED=$(grep -ciE 'died|signal 9|killed' $V/var/logs/mailman.log 2>/dev/null || true)
systemctl reset-failed $UNIT $SINKUNIT 2>/dev/null || true

python3 - <<PY
import json
inj = json.load(open("$OUT/soak-$BUILD-inject.json"))
try: d = json.load(open("$V/delivered.json"))
except Exception: d = {"messages": 0, "recipients": 0}
s = {"build": "$BUILD", "dkim2": "$DK", "drained": "$DRAINED" == "true",
     "drain_seconds": $END - $START, "inject_seconds": $INJ_END - $START,
     "injected": inj["accepted"], "rejected": inj["rejected"],
     "members": $MEMBERS, "expected_recipients": inj["accepted"] * $MEMBERS,
     "delivered": d["recipients"], "delivered_messages": d["messages"],
     "cgroup_mem_peak_bytes": int("${MEMPEAK:-0}"), "oom_kills": int("${OOMK:-0}"),
     "unit_active_at_end": "$ACTIVE", "unit_result": "$RESULT",
     "log_died_lines": int("${LOGDIED:-0}"), "failures": inj["failures"]}
json.dump(s, open("$OUT/soak-$BUILD-summary.json", "w"), indent=1)
print(json.dumps(s))
PY
