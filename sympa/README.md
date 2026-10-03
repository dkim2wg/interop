# DKIM2 Message-Instance support for Sympa 6.2.78

Three patches that make Sympa record, in a `Message-Instance` header, what
it changed about each message it redistributes, so a DKIM2 verifier
downstream can undo the list's changes and check the signatures of earlier
hops. Sympa adds only `Message-Instance`; the `DKIM2-Signature` is added by
the MTA (see the [Postfix mailing-list host
guide](../docs/dkim2-postfix-list-host-guide.md)).

The same three commits are the `dkim2` branch of
<https://github.com/brong/sympa>, which is what these patches are exported
from. The design and its resource impact are described in that branch's
`DKIM2-MESSAGE-INSTANCE.md`, which patch 2 adds.

## The patches

1. **Preserve the body encoding when decorating.** Four changes to
   `Sympa::Message` that keep the lines of the original body byte-identical
   through personalisation and footer decoration: no re-encoding when
   personalisation substituted nothing, the original charset preferred over
   a UTF-8 fallback, a MIME-part fallback instead of a dropped footer, and
   encoded-level footer appends for quoted-printable and base64 bodies. A
   Message-Instance Recipe for a footer is then one copy range rather than
   the whole body. This applies whether or not Message-Instance is enabled.
2. **Add DKIM2 Message-Instance header support.** At ingress
   (`ProcessIncoming`) the message is recorded as received, `m=1` added if
   it has no instance; the original is kept beside the message in the
   outgoing spool. At egress (`ProcessOutgoing`), after all transformations
   and before DKIM signing, the next `m=` with Recipes is added if anything
   changed. Internally generated messages, resends from the archive and
   direct sends get an originating `m=1`. Includes `t/Message_DKIM2.t` and
   `DKIM2-MESSAGE-INSTANCE.md`.
3. **Add the X-DKIM2-Info debug header.** One above every Message-Instance
   Sympa adds, naming the draft, implementation date, action and hashed
   header fields, so an interop problem can be diagnosed from the message.

## What they apply to

Sympa **6.2.78** only: the series is based on that tag and applies cleanly
there. Older packages are not supported.

## Dependencies

`Sympa::Message` loads `Mail::DKIM2::MessageInstance` and
`Mail::DKIM2::Common` from the Mail-DKIM2 Perl distribution in
[`../perl`](../perl); install it first (`cpanm .` in that directory). It is a
soft dependency: without it Sympa runs but adds no headers.

## Installing

Apply to a 6.2.78 source tree and build as usual:

```bash
git clone https://github.com/sympa-community/sympa.git && cd sympa
git checkout 6.2.78
git -c user.name=ops -c user.email=ops@example.org am /path/to/interop/sympa/patches/*.patch
autoreconf -i && ./configure ... && make && make install
```

Or overlay the patched files onto an installed 6.2.78 (an older install,
such as a distribution's 6.2.76 package, is not a supported base: its
`Message.pm` differs and the overlay then needs files from 6.2.78 that the
patches do not carry):

```
src/lib/Sympa/Message.pm
src/lib/Sympa/Spool/Outgoing.pm
src/lib/Sympa/Spindle/ProcessIncoming.pm
src/lib/Sympa/Spindle/ProcessOutgoing.pm
src/lib/Sympa/Spindle/ResendArchive.pm
src/lib/Sympa/Spindle/ToList.pm
src/lib/Sympa/Spindle/ToMailer.pm
```

Then in `sympa.conf`:

```
# Submit outbound mail to the MTA's signing listener (see the guide).
sendmail /usr/local/bin/sympa-sendmail
# One recipient per transaction, so each signed copy's rt= names only its
# own recipient. See the guide, "Recipient privacy".
nrcpt 1
```

`sympa-sendmail` is in [`../deploy/examples/`](../deploy/examples/). Restart
`sympa sympa-bulk sympa-archived sympa-bounced sympa-task_manager wwsympa`;
all of them load `Message.pm`.

## Regenerating the series

```bash
util/export-list-patches.sh          # from the fork checkouts
util/export-list-patches.sh --check  # apply-check against the base above
```
