# DKIM2 Message-Instance support for GNU Mailman 3

Three patches that make Mailman record, in a `Message-Instance` header, what
it changed about each message it redistributes, so a DKIM2 verifier
downstream can undo the list's changes and check the signatures of earlier
hops. Mailman adds only `Message-Instance`; the `DKIM2-Signature` is added
by the MTA (see the [Postfix mailing-list host
guide](../docs/dkim2-postfix-list-host-guide.md)).

The same three commits are the `dkim2` branch of
<https://github.com/brong/mailman>, which is what these patches are exported
from. The design is described in that branch's `DKIM2-MESSAGE-INSTANCE.md`,
which patch 2 adds.

## The patches

1. **Preserve the original Content-Transfer-Encoding when decorating.**
   Adding a header or footer to a single-part text message used to let
   Python's email library pick a new encoding (a UTF-8 body arriving as 8bit
   came out as base64), which changed every line of the body. Now 7bit/8bit,
   quoted-printable and base64 bodies keep their encoding, so a
   Message-Instance Recipe for the common footer-append case is one copy
   range rather than the whole body. This applies whether or not
   Message-Instance is enabled.
2. **Add DKIM2 Message-Instance headers at ingress and egress.** A
   `message-instance-ingress` handler at the front of the posting and owner
   pipelines records the message as received (adding `m=1` if it has no
   instance, leaving any existing instance alone), and a
   `MessageInstanceMixin` on the `Deliver` and `BulkDelivery` classes adds
   the next `m=` with header and body Recipes after decoration,
   personalisation and ARC signing. Each instance is accompanied by an
   `X-DKIM2-Info` debug header. Enabled by `[mta] message_instance: yes`.
   Includes the tests and `DKIM2-MESSAGE-INSTANCE.md`.
3. **Add a per-list `dkim2_message_instance` flag.** A boolean list
   attribute (default on) exposed through the REST list configuration
   resource, with its Alembic migration, so individual lists can opt out.

## What they apply to

The series is based on upstream `master` at commit `687b9e4dc`
(`v3.3.10-466-g687b9e4dc`, September 2026) and applies cleanly there.

It does **not** apply to the `v3.3.10` release: patch 1 touches
`src/mailman/handlers/decorate.py`, which changed on master after 3.3.10.
Use master, or the fork branch below, until a release carries those
changes.

## Installing

Either install the fork branch into the Mailman virtualenv:

```bash
/opt/mailman/venv/bin/pip install 'git+https://github.com/brong/mailman@dkim2'
```

or apply the patches to your own checkout of Mailman master and install
that:

```bash
git clone https://gitlab.com/mailman/mailman.git && cd mailman
git checkout 687b9e4dc
git -c user.name=ops -c user.email=ops@example.org am /path/to/interop/mailman/patches/*.patch
/opt/mailman/venv/bin/pip install .
```

Either way the virtualenv moves from a 3.3.10 release to a master
snapshot; check that your Postorius and HyperKitty versions accept it.

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

Restart Mailman. Baselines for Recipe computation live briefly in
`$VAR_DIR/mi-cache/`.

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
