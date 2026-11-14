# DKIM2 Message-Instance support for GNU Mailman 3

Four patches (plus two small upstream fixes 3.3.10 needs on Python 3.13,
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

Earlier series are kept for reference: the one that kept each post's
received octets and diffed against them is tagged
`dkim2-history-2026-11-13`, `dkim2-3.3.10-history-2026-11-13` and
`dkim2-3.3.8-history-2026-11-13` (replaced 13 November 2026), and the one
that preserved the body's Content-Transfer-Encoding instead of MIME-wrapping
is on the branches `dkim2-cte-preserve-3.3.10`, `dkim2-cte-preserve-3.3.8`
and `dkim2-cte-preserve` (October 2026).

The DKIM2 code is identical on all three; they differ only where the
releases differ around it (the owner pipeline's handler list, the Alembic
revision the migration follows, and the upstream code around the lines
added to `decorate.py`, `dmarc.py`, `lmtp.py` and `email/message.py`). The design is described in
`src/mailman/handlers/docs/message-instance.rst`, which the Message-Instance
patch adds.

`patches-3.3.10/` carries six patches. The first two are upstream commits
that 3.3.10 needs to run on Python 3.13 at all (the default on Debian 13 and
Ubuntu 25.04+) and that have not been in a release yet: the `nntplib`
requirement becomes `standard-nntplib`, without which `pip install` cannot
resolve 3.3.10 on 3.13, and the template loader stops using a `pathlib`
path as a context manager, without which every template lookup (and so
every decoration) raises a TypeError on 3.13. On Python 3.12 and earlier
they change nothing and can be skipped. The DKIM2 patches are the last
four. `patches-3.3.8/` and `patches-master/` are these four patches alone:
3.3.8 is only shipped with Python 3.11 and 3.12, where it needs no such
fixes.

## The patches

0. *(upstream, `patches-3.3.10/` only)* **Fix requirement for standard-nntplib
   with Python >= 3.13** and **remove context manager usage for
   PosixPath**: the two Python 3.13 fixes described above.
1. **Add a setting to decorate text/plain by wrapping it.** A new
   `[mailman] decorate_plain_text_in_place` option (default `yes`, upstream
   behaviour): with `no`, a single-part text/plain post gets its header and
   footer as parts of a `multipart/mixed` wrap, as every other type already
   does, instead of being decoded and re-encoded (a utf-8 body usually came
   out base64). Useful on its own; proposed upstream separately.
2. **Message: log the original values of header fields Mailman changes.**
   Once started, Mailman's `Message` records, the first time any code adds,
   sets, replaces or deletes a header field name, the values that name had.
   Python's compat32 `Message` edits its header list directly in six
   methods; overriding those six sees every change. The log is an
   attribute, pickled and copied with the message, never written into it.
3. **Add DKIM2 Message-Instance headers.** With `[mta] message_instance:
   yes` (off by default) the LMTP runner hashes each post as received and
   checks the Message-Instance it came with (keeping two digests and the
   outcome, not the octets) and starts the header log; a
   `message-instance-ingress` handler takes the snapshot (leaving a signed
   post's instances alone; an unsigned post leaves with a single `m=1`);
   on a DKIM2 list decoration always wraps, and records how; and a
   `MessageInstanceMixin` on `Deliver` and `BulkDelivery` adds the next
   `m=` after decoration, personalisation and ARC signing. Its header
   Recipe comes from the header log, its body Recipe from where decoration
   put the post (literals only for the `From ` lines smtplib mangles), each
   checked against the arrival digests: a body Mailman rewrote (content
   filtering, the DMARC wrap) gets `"b": null`. On a DKIM2 list From
   becomes the list's address whenever the list changes or originates a
   post; every copy is marked `X-DKIM2-Exploded` for the signing milter;
   each instance comes with an `X-DKIM2-Info` debug header. Includes the
   tests and `src/mailman/handlers/docs/message-instance.rst`.
4. **Add a per-list `dkim2_message_instance` flag.** A boolean list
   attribute (default on) exposed through the REST list configuration
   resource, with its Alembic migration, so individual lists can opt out.

## What they apply to

`patches-3.3.10/` applies to the `v3.3.10` tag, `patches-3.3.8/` to the
`3.3.8` tag, and `patches-master/` to upstream master at `b84676666`
(November 2026). None applies to another base.

Both assume Mailman installed the upstream way, as a Python package in a
virtualenv. If you run a distribution's `mailman3` package instead, apply
the matching series to the package source and rebuild it, or overlay the changed
files into `/usr/lib/python3/dist-packages/mailman/`; this README does not
cover either.

Tested: the `dkim2` branch passes Mailman's whole test suite (2,501 tests)
on Python 3.14, and the `dkim2-3.3.10` branch passes it on Python 3.13 and
runs the lists on dkim2.com. The `dkim2-3.3.8` branch carries the same
DKIM2 code and is not tested separately.

## Upgrading from a series installed before 14 November 2026

The series was tidied for upstream review on 14 November 2026. Two things
changed that an existing installation notices:

- **The Alembic migration was renamed**, from the placeholder revision
  `a1b2c3d4e5f6` to `1371b515fbeb`. A database migrated by an earlier series
  is stamped with the old id, which the new code does not have, and every
  `mailman` command then fails with `Can't locate revision identified by
  'a1b2c3d4e5f6'`. The column the migration adds is already there, so only
  the stamp needs changing. With Mailman stopped and the new branch
  installed, run this against Mailman's database (with `sqlite3`, `psql` or
  `mysql`, whichever it uses), then `mailman info` and start Mailman:

  ```sql
  UPDATE alembic_version SET version_num = '1371b515fbeb'
   WHERE version_num = 'a1b2c3d4e5f6';
  ```

  The new id is the same on all three branches.
- **The names Mailman keeps a post's DKIM2 state under changed** (the
  `dkim2_snapshot` and `dkim2_arrival_status` queue metadata, the
  `dkim2_arrival` attribute). A post that was already in a queue, or held
  for moderation, when the old code was stopped has the old names, and
  leaves without a Message-Instance when it is processed or released. Let
  the queues drain before stopping the old version; nothing is lost but the
  instance on those posts.

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

Either way you stay on your release plus these four changes, so your
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
```

Restart Mailman.

The Message-Instance handlers have a logger of their own, `mailman.dkim2`,
which writes to Mailman's `mailman.log` (not the journal). At the default
level it says nothing unless something is wrong: `Message-Instance m=N does
not describe the message as received` (a post that arrived already
damaged) and `Header log does not rebuild the headers as received` (a
header change Mailman could not account for; that copy leaves without an
instance). To see every post -- `Accepted existing Message-Instance m=1`,
`Added Message-Instance m=2` -- add to `mailman.cfg`:

```ini
[logging.dkim2]
level: debug
```

Nothing of a received post is kept beyond two
digests and the header log, so the queues do not grow; there is no cache
directory (earlier builds kept one in `$VAR_DIR/mi-cache/`, which can be
deleted).

When upgrading from the earlier series (which kept each post's received
octets as `msg.original_bytes`), or rolling back to it: messages queued by
one cannot be described by the other (the earlier series pickled a
`mailman.handlers.decorate._ReceivedPart`, and this one needs the header
log), so drain the queues first: stop accepting mail and let `out` and
`retry` empty.

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
