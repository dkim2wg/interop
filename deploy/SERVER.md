# DKIM2 Demo Server — dkim2.com

## Overview

A Digital Ocean VPS running the DKIM2 demonstration server.

| Item | Value |
|------|-------|
| Hostname | mail.dkim2.com |
| IP | 134.209.211.166 |
| OS | Ubuntu 25.10 (Questing Quokka) |
| SSH alias | `ssh dkim2` (configured in ~/.ssh/config) |

---

## Software Components

### 1. Postfix (system package)

**Role:** Edge MTA — receives inbound mail on port 25, routes outbound mail
from lists via port 10587 (listserv).

**Config files:**
- `/etc/postfix/main.cf` — main configuration
- `/etc/postfix/master.cf` — process table (includes listserv entry)

**Key `main.cf` settings:**
```
myhostname = mail.dkim2.com
mydomain = dkim2.com
myorigin = $mydomain
mydestination = dkim2.com, test1-5.dkim2.com, sympa.dkim2.com,
                mailman.dkim2.com, localhost
smtpd_milters = unix:var/run/dkim2-milter-in.sock
non_smtpd_milters = unix:var/run/dkim2-milter-in.sock,
                    unix:var/run/dkim2-milter-out.sock
```

**`master.cf` listserv entry (port 10587):**
```
127.0.0.1:10587 inet n  -  y  -  -  smtpd
  -o syslog_name=postfix/listserv
  -o smtpd_milters=unix:var/run/dkim2-milter-out.sock
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o local_recipient_maps=
  -o smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination
```
Listserv port receives mail from Mailman/Sympa, runs only the outbound
milter (sign + MI diff).

**Update:** `systemctl restart postfix`

---

### 2. DKIM2 Milter (dkim2-milter.pl)

**Role:** DKIM2 signing and verification + Message-Instance header computation.

**Source:** `/root/interop/` — this git repository (`github.com/dkim2wg/interop`).
The milter code is in `brong/bin/dkim2-milter.pl` and `brong/lib/Mail/DKIM2/`.

**Two instances run:**

| Service | Mode | Socket | Purpose |
|---------|------|--------|---------|
| `dkim2-milter-inbound` | inbound | `dkim2-milter-in.sock` | Verify DKIM2, add Auth-Results, add MI v=1 |
| `dkim2-milter-outbound` | outbound | `dkim2-milter-out.sock` | Compute MI diff, sign with DKIM2 |

**Service files:** `/etc/systemd/system/dkim2-milter-{inbound,outbound}.service`
(also committed to `deploy/` in this repo — but on server `ProtectHome=no`
since repo is under `/root/`)

**Keys:** `/etc/dkim2/keys/{domain}/{selector}.key` (RSA PKCS#8 PEM format)
- `dkim2.com/sel1.key`, `dkim2.com/ed25519.key`
- `test{1-5}.dkim2.com/sel1.key`, etc.

**Snapshots:** `/var/spool/dkim2/snapshots/`

**Update process:**
```bash
ssh dkim2
cd /root/interop
git pull
systemctl restart dkim2-milter-inbound dkim2-milter-outbound
```

---

### 3. Mailman 3

**Role:** Mailing list manager at `mailman.dkim2.com`.

**Source:** Fork at `github.com/brong/mailman` with DKIM2 additions in
`src/mailman/handlers/message_instance.py` and
`src/mailman/mta/message_instance.py`.

**Installation:** Installed as a Python package in a venv at `/opt/mailman/venv/`.
The installed package files live at:
```
/opt/mailman/venv/lib/python3.13/site-packages/mailman/
```
Version: 3.3.11b1 (from brong fork, installed via pip in development mode or
copied directly).

**Config files:**
- `/etc/mailman3/mailman.cfg` — main mailman config
- `/etc/mailman3/web/settings.py` — Django settings for Postorius + HyperKitty
- `/etc/mailman3/postfix-mailman.cfg` — Postfix transport map config
- `/etc/mailman3/mailman-hyperkitty.cfg` — HyperKitty plugin config

**Key `mailman.cfg` settings:**
```ini
[mta]
incoming: mailman.mta.postfix.LMTP
outgoing: mailman.mta.deliver.deliver
lmtp_host: 127.0.0.1
lmtp_port: 8024
smtp_host: localhost
smtp_port: 10587        # listserv port → outbound milter only
message_instance: yes   # global DKIM2 MI enable

[database]
url: sqlite:////var/lib/mailman3/mailman.db
```

**Services:**
- `mailman3.service` — core Mailman daemon (LMTP on :8024, REST on :8001)
- `mailman-web.service` — gunicorn serving Postorius + HyperKitty on :8080

**Web UI:** `https://mailman.dkim2.com` → nginx → gunicorn :8080

**REST API:** `http://localhost:8001` (user: `restadmin`, pass: `dkim2demo`)

**Logs:**
- `/var/log/mailman3/mailman.log` — core mailman
- `/var/log/mailman3/dkim2.log` — DKIM2 MI handler
- `/var/log/mailman3/mailman-web.log` — Django/gunicorn

**Database:** `/var/lib/mailman3/mailman.db` (SQLite)
**Web database:** `/var/lib/mailman3/web/mailman-web.db` (SQLite, Django)

**Lists:**
- `test@mailman.dkim2.com` — subject prefix + footer (full MI)
- `test-subject-only@mailman.dkim2.com` — subject prefix only
- `test-body-only@mailman.dkim2.com` — footer only
- `test-passthrough@mailman.dkim2.com` — no modification (passthrough)

**Update process:**

Sync changed handler files from the local brong/mailman checkout:
```bash
VENV=/opt/mailman/venv/lib/python3.13/site-packages/mailman
rsync -av src/mailman/handlers/message_instance.py \
          src/mailman/mta/message_instance.py \
          root@dkim2.com:$VENV/handlers/
```
Or from the repo directory on the local machine, run the deploy script
(see below).  After copying files:
```bash
ssh dkim2
# Run Alembic migration if model changed:
/opt/mailman/venv/bin/mailman --config /etc/mailman3/mailman.cfg \
    shell -r mailman.database.initialize:initialize
# or: /opt/mailman/venv/bin/alembic upgrade head
systemctl restart mailman3 mailman-web
```

**Per-list DKIM2 toggle (added 2026-03-23):**
The `dkim2_message_instance` boolean attribute on each list can be set
via the REST API to disable MI for a specific list:
```bash
curl -u restadmin:dkim2demo -X PATCH \
     http://localhost:8001/3.1/lists/test-passthrough.mailman.dkim2.com/config \
     -d '{"dkim2_message_instance": false}'
```

---

### 4. Sympa

**Role:** Mailing list manager at `sympa.dkim2.com`.

**Source:** Fork at `github.com/brong/sympa` (branch `dkim2`) with DKIM2
additions in `src/lib/Sympa/Message.pm`.

**Installation:** Installed from the Debian/Ubuntu `sympa` package, then
DKIM2-modified Perl files overlaid into `/usr/share/sympa/lib/`.
The key modified file is `/usr/share/sympa/lib/Sympa/Message.pm`.

Version: 6.2.76

**Config files:**
- `/etc/sympa/sympa/sympa.conf` — main Sympa config
- `/etc/sympa/auth.conf` — authentication config

**Key `sympa.conf` settings:**
```
domain sympa.dkim2.com
listmaster admin@dkim2.com
wwsympa_url https://sympa.dkim2.com/sympa
db_type SQLite
db_name /var/lib/sympa/sympa.sqlite
sendmail /usr/local/bin/sympa-sendmail
```

**`/usr/local/bin/sympa-sendmail`:** Custom sendmail wrapper that submits
outbound mail via SMTP to localhost:10587 (listserv port) so that only the
outbound milter processes it (not the inbound milter).

**Services:**
- `sympa.service` — main Sympa process
- `sympa-archived.service`, `sympa-bounced.service`, `sympa-bulk.service`,
  `sympa-task_manager.service` — Sympa sub-processes
- `wwsympa.service` — web interface FastCGI backend (socket:
  `/run/sympa/wwsympa.socket`)

**Web UI:** `https://sympa.dkim2.com/sympa` → nginx → FastCGI

**Database:** `/var/lib/sympa/sympa.sqlite` (SQLite)

**Perl dependency (Mail::DKIM2):** Installed system-wide from this repo:
```bash
ssh dkim2
cd /root/interop/brong
perl Makefile.PL && make && make install
```

**Update process:**
```bash
# From local machine
rsync -av src/lib/Sympa/Message.pm \
          root@dkim2.com:/usr/share/sympa/lib/Sympa/Message.pm
ssh dkim2 systemctl restart sympa sympa-bulk sympa-archived
```

---

### 5. Nginx

**Role:** TLS termination and reverse proxy.

**Config:** `/etc/nginx/sites-enabled/`
- `mailman.dkim2.com` → proxy to gunicorn :8080
- `sympa.dkim2.com` → FastCGI to wwsympa socket

**TLS certificates:** Let's Encrypt, stored at:
- `/etc/letsencrypt/live/mailman.dkim2.com/`
- `/etc/letsencrypt/live/sympa.dkim2.com/`
- `/etc/letsencrypt/live/mail.dkim2.com/` (for Postfix SMTP TLS)

---

## Updating Code on the Server

### DKIM2 milter (Perl, this repo)
```bash
ssh dkim2 'cd /root/interop && git pull && \
    systemctl restart dkim2-milter-inbound dkim2-milter-outbound'
```

### Mailman handlers (Python, brong/mailman repo)

From your local `~/src/mailman` working directory:
```bash
DEST=root@dkim2.com:/opt/mailman/venv/lib/python3.13/site-packages/mailman
rsync -av src/mailman/handlers/message_instance.py $DEST/handlers/
rsync -av src/mailman/mta/message_instance.py $DEST/mta/
ssh dkim2 systemctl restart mailman3 mailman-web
```

If the database model changed (new Alembic migration):
```bash
ssh dkim2 'MAILMAN_CONFIG_FILE=/etc/mailman3/mailman.cfg \
    /opt/mailman/venv/bin/alembic \
    -c /opt/mailman/venv/lib/python3.13/site-packages/mailman/config/alembic.cfg \
    upgrade head'
```

### Sympa Message.pm (Perl, brong/sympa repo)

From your local `~/src/sympa` working directory:
```bash
scp src/lib/Sympa/Message.pm \
    root@dkim2.com:/usr/share/sympa/lib/Sympa/Message.pm
ssh dkim2 systemctl restart sympa sympa-bulk sympa-archived sympa-bounced
```

---

## Quick Health Check
```bash
ssh dkim2 systemctl status dkim2-milter-inbound dkim2-milter-outbound \
    mailman3 mailman-web sympa postfix nginx
```

## Log Tailing
```bash
# DKIM2 milter
ssh dkim2 journalctl -fu dkim2-milter-inbound
ssh dkim2 journalctl -fu dkim2-milter-outbound

# Mailman
ssh dkim2 tail -f /var/log/mailman3/mailman.log /var/log/mailman3/dkim2.log

# Postfix
ssh dkim2 tail -f /var/log/mail.log

# Sympa
ssh dkim2 journalctl -fu sympa
```
