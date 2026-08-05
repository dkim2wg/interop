#!/usr/bin/env python3
"""One-time migration: repurpose 127.0.0.1:10587 as the DKIM2 split entry.

Run ON the server, from a CURRENT checkout:

    ssh dkim2 'cd /root/interop && git pull && python3 deploy/migrate-10587-to-split.py'
    ssh dkim2 'postfix check && postfix reload'

Rewrites /etc/postfix/master.cf to:
  - drop the old signing definition of 10587 (smtpd_milters, syslog_name=listserv)
  - drop the old split section (the duplicate 10586 entry and its 10589)
  - append deploy/postfix-dkim2-split.master.cf, which defines the new 10587
    (split entry, no milter) and 10589 (signing re-injection)

Already applied to the demo box; kept in the repo because it records exactly what
was done to master.cf, and it is idempotent so re-running is harmless.

Matches by content rather than line number, writes a timestamped backup, and does
NOT reload -- run `postfix check` yourself and reload only if it passes.
"""
import shutil
import subprocess
import sys
import os

MASTER = '/etc/postfix/master.cf'
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAGMENT = os.path.join(REPO, 'deploy', 'postfix-dkim2-split.master.cf')

fragment = open(FRAGMENT).read()

# GUARD: a stale fragment (one still defining 10586 instead of 10587) would
# delete 10587 and put nothing back, silently breaking Mailman and Sympa, which
# both point at 10587. Checked BEFORE anything is written. This exact mistake was
# made once, from a checkout that had not been pulled.
if '\n127.0.0.1:10587 ' not in fragment:
    sys.exit('!! %s does not define 127.0.0.1:10587 -- stale checkout? '
             'git pull and retry; refusing to remove 10587 with nothing to '
             'replace it.' % FRAGMENT)
if '\n127.0.0.1:10589 ' not in fragment:
    sys.exit('!! %s does not define the 10589 signing re-injection; aborting.'
             % FRAGMENT)
# A *definition* of 10586, not a mention: the fragment's comments legitimately
# explain why that entry was retired.
if '\n127.0.0.1:10586 ' in fragment:
    sys.exit('!! %s still defines 127.0.0.1:10586 -- that entry was retired in '
             'favour of 10587; aborting.' % FRAGMENT)

src = open(MASTER).read()
if 'postfix/dkim2-split-in' in src:
    print('   already rewired (10587 is the split entry); nothing to do')
    sys.exit(0)

lines = src.split('\n')
out, removed, i = [], [], 0
while i < len(lines):
    line = lines[i]

    # Old split section: from its header comment to EOF.
    if line.startswith('# DKIM2 Bcc-safe origination:'):
        removed.append('old split section (10586 + 10589), %d lines'
                       % (len(lines) - i))
        break

    # Old signing definition of 10587, plus the comment block introducing it.
    if line.startswith('# Submission port for mailing list software'):
        j = i
        while j < len(lines) and not lines[j].startswith('127.0.0.1:10587'):
            j += 1
        if j < len(lines):
            j += 1
            while j < len(lines) and lines[j].startswith('  -o '):
                j += 1
            removed.append('old signing 10587 block, %d lines' % (j - i))
            i = j
            continue

    out.append(line)
    i += 1

if not removed:
    sys.exit('!! neither the old 10587 block nor the old split section was '
             'found -- master.cf is not in the expected shape; aborting')

new = '\n'.join(out).rstrip('\n') + '\n\n' + fragment

stamp = subprocess.run(['date', '+%Y%m%d%H%M%S'],
                       capture_output=True, text=True).stdout.strip()
backup = '%s.bak-presplit-%s' % (MASTER, stamp)
shutil.copy2(MASTER, backup)
open(MASTER, 'w').write(new)

for r in removed:
    print('   removed:', r)
print('   appended:', FRAGMENT)
print('   backup:  ', backup)
print('   now run: postfix check && postfix reload')
