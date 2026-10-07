# DKIM2 Message-Instance support for GNU Mailman 3

Three patches (plus two small upstream fixes 3.3.10 needs on Python 3.13,
see below) that make Mailman record, in a `Message-Instance` header, what
it changed about each message it redistributes, so a DKIM2 verifier
downstream can undo the list's changes and check the signatures of earlier
hops. Mailman adds only `Message-Instance`; the `DKIM2-Signature` is added
by the MTA (see the [Postfix mailing-list host
guide](../docs/dkim2-postfix-list-host-guide.md)).

The series exists on three bases in <https://github.com/brong/mailman>:

- branch **`dkim2-3.3.10`**, on the v3.3.10 release (October 2024, the
  current release on PyPI and in Debian 13 and Ubuntu 25.04+):
  `patches-3.3.10/` here. Install this one unless you are on an LTS below.
- branch **`dkim2-3.3.8`**, on the 3.3.8 release (January 2023, what
  Debian 12 and Ubuntu 24.04 LTS package): `patches-3.3.8/` here.
- branch `dkim2`, on upstream master: the same change where upstream
  development happens (`patches-master/` here).

The previous approach, which preserved the body's Content-Transfer-Encoding
when appending a footer instead of MIME-wrapping, is kept on the branches
`dkim2-cte-preserve-3.3.10`, `dkim2-cte-preserve-3.3.8` and
`dkim2-cte-preserve` (October 2026) in case it is wanted again.

The DKIM2 code is identical on all three; they differ only where the
releases differ around it (the owner pipeline's handler list, the Alembic
revision the migration follows, and the upstream code around the few lines
added to `decorate.py`, `mime_delete.py` and `dmarc.py`). The design is described in
`DKIM2-MESSAGE-INSTANCE.md`, which the Message-Instance patch adds.

`patches-3.3.10/` carries five patches. The first two are upstream commits
that 3.3.10 needs to run on Python 3.13 at all (the default on Debian 13 and
Ubuntu 25.04+) and that have not been in a release yet: the `nntplib`
requirement becomes `standard-nntplib`, without which `pip install` cannot
resolve 3.3.10 on 3.13, and the template loader stops using a `pathlib`
path as a context manager, without which every template lookup (and so
every decoration) raises a TypeError on 3.13. On Python 3.12 and earlier
they change nothing and can be skipped. The DKIM2 patches are the last
three. `patches-3.3.8/` and `patches-master/` are these three patches alone: 3.3.8 is only
shipped with Python 3.11 and 3.12, where it needs no such fixes.

## The patches

0. *(upstream, `patches-3.3.10/` only)* **Fix requirement for standard-nntplib
   with Python >= 3.13** and **remove context manager usage for
   PosixPath**: the two Python 3.13 fixes described above.
1. **Keep the bytes a message arrived with.** Only when Message-Instance
   support is enabled (`[mta] message_instance: yes`, the option this patch
   adds, off by default), the LMTP runner stores the received octets as
   `msg.original_bytes`. Re-serializing a parsed multipart message is not
   byte-faithful (a part header loses a trailing space or is refolded, a
   final boundary gains a line ending), and a Message-Instance Recipe has
   to rebuild exactly what the sender signed. With the option off nothing
   is kept, so the queue pickles do not grow.
2. **Add DKIM2 Message-Instance headers at ingress and egress.** A
   `message-instance-ingress` handler at the front of the posting and owner
   pipelines records the message as received (adding `m=1` if it has no
   instance, leaving any existing instance alone; the baseline is
   `msg.original_bytes`, with no on-disk cache), and a
   `MessageInstanceMixin` on the `Deliver` and `BulkDelivery` classes adds
   the next `m=` with header and body Recipes after decoration,
   personalisation and ARC signing. It hashes the message as `smtplib`
   will send it (without `Bcc` and `Resent-Bcc`, which `smtplib` drops), so
   the Recipe records that change too. Each instance is accompanied by an
   `X-DKIM2-Info` debug header. Enabled by `[mta] message_instance: yes`;
   on a list that opts out, ingress drops the received octets.
   Includes the tests and `DKIM2-MESSAGE-INSTANCE.md`.

   On a list with Message-Instance enabled, decoration always MIME-wraps:
   the received `Content-*` fields and body octets are spliced in unchanged
   as the middle part of a new `multipart/mixed`, between `text/plain`
   header and footer parts, so the body Recipe is literal lines, one copy
   range, literal lines, whatever the body's encoding or structure. When
   Mailman rewrites the body itself (content filtering, or the DMARC
   mitigation's wrap), the body Recipe is `"b": null` instead: the earlier
   body cannot be rebuilt, and the Recipe says so. Lists without
   Message-Instance decorate exactly as upstream does.
3. **Add a per-list `dkim2_message_instance` flag.** A boolean list
   attribute (default on) exposed through the REST list configuration
   resource, with its Alembic migration, so individual lists can opt out.

## What they apply to

`patches-3.3.10/` applies to the `v3.3.10` tag, `patches-3.3.8/` to the
`3.3.8` tag, and `patches-master/` to upstream master at `687b9e4dc`
(September 2026). None applies to another base.

Both assume Mailman installed the upstream way, as a Python package in a
virtualenv. If you run a distribution's `mailman3` package instead, apply
the matching series to the package source and rebuild it, or overlay the changed
files into `/usr/lib/python3/dist-packages/mailman/`; this README does not
cover either.

Tested: the `dkim2-3.3.10` branch passes Mailman's own test suite for the
handlers, decoration, REST list configuration, templates and modules on
Python 3.13, and runs the lists on dkim2.com. The `dkim2-3.3.8` branch
passes the same handler, decoration, content filter, DMARC, REST and LMTP
tests on Python 3.12, and the `dkim2` branch on Python 3.13.

## Installing

Either install the branch matching your release into the Mailman
virtualenv:

```bash
/opt/mailman/venv/bin/pip install 'git+https://github.com/brong/mailman@dkim2-3.3.10'
# or, on Mailman 3.3.8:
/opt/mailman/venv/bin/pip install 'git+https://github.com/brong/mailman@dkim2-3.3.8'
```

or apply the matching series to a checkout of the release and install that:

```bash
git clone https://gitlab.com/mailman/mailman.git && cd mailman
git checkout v3.3.10        # or: git checkout 3.3.8
git -c user.name=ops -c user.email=ops@example.org am /path/to/interop/mailman/patches-3.3.10/*.patch
                            # or: .../mailman/patches-3.3.8/*.patch
/opt/mailman/venv/bin/pip install .
```

Either way you stay on your release plus these three changes, so your
Postorius and HyperKitty keep working. (If you run Mailman master, use
branch `dkim2` or `patches-master/` the same way.)

Then, with Mailman stopped, run any `mailman` command as the Mailman user;
every one applies pending database migrations (the per-list flag adds a
column):

```bash
sudo -u mailman /opt/mailman/venv/bin/mailman -C /etc/mailman3/mailman.cfg info
```

and in `mailman.cfg` (comments on their own lines: lazr.config keeps an
inline comment as part of the value):

```ini
[mta]
# Record the list's changes in Message-Instance headers.
message_instance: yes
# One recipient per SMTP transaction, so each signed copy's rt= names only
# its own recipient. See the guide, "Recipient privacy".
max_recipients: 1

[logging.dkim2]
# The handlers log to the mailman.dkim2 logger; without this section their
# lines go to mailman.log.
path: dkim2.log
```

Restart Mailman. The baseline for Recipe computation travels with each
queued message (`msg.original_bytes`, kept only when Message-Instance
support is enabled, not for a list that opts out, and not in the copies
queued for the archivers and the NNTP gateway); there is no cache
directory. Earlier
builds kept baselines in `$VAR_DIR/mi-cache/`, which is no longer used and
can be deleted.

When upgrading or downgrading: messages queued by this version pickle a
`mailman.handlers.decorate._ReceivedPart` (the wrapped middle part), so a
build without that class cannot unpickle them, and an earlier build that
held the part as a list of lines (before mailman commit 86bd7bee8) cannot
send them; this build still sends parts those earlier builds queued. Drain the queues (stop
accepting mail and let `out` and `retry` empty) before rolling back to an
earlier build.

To turn it off for one list (the body must be sent as JSON):

```bash
curl -u restadmin:PASSWORD -X PATCH -H 'Content-Type: application/json' \
     http://localhost:8001/3.1/lists/LIST.DOMAIN/config \
     -d '{"dkim2_message_instance": false}'
```

## Regenerating the series

```bash
util/export-list-patches.sh          # from the fork checkouts
util/export-list-patches.sh --check  # apply-check against the bases above
```
